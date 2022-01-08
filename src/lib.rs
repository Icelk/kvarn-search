use kvarn::prelude::*;
use search::index::Provider;
use tokio::sync::RwLock;

#[derive(serde::Serialize)]
struct HitResponse {
    start: usize,
    rating: f32,
    path: String,
    context: String,
    start_in_context: usize,

    associated_occurrences: Vec<usize>,
}

fn request(path: impl AsRef<str>) -> Request<application::Body> {
    Request::builder()
        .uri(path.as_ref())
        .method("GET")
        .header("user-agent", "kvarn-search-engine-indexer")
        .body(kvarn::application::Body::Bytes(Bytes::new().into()))
        // We know this is OK.
        .unwrap()
}

/// Quite slow, takes ~70ms (debug) to get
///
/// It's the HTML parsing which is the real problem.
fn text_from_response(response: &kvarn::CacheReply) -> Result<Cow<'_, str>, ()> {
    let body = &response.identity_body;

    let mime: Option<internals::Mime> = response
        .response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|header| header.to_str().ok())
        .and_then(|content_type| content_type.parse().ok());

    let text = match mime {
        Some(mime)
            if mime.type_() == internals::mime::TEXT && mime.subtype() == internals::mime::HTML =>
        {
            {
                let body = String::from_utf8_lossy(body);

                let html = scraper::Html::parse_document(&body);

                let selected_body = html
                    .select(&scraper::Selector::parse("main").unwrap())
                    .next()
                    .or_else(|| {
                        html.select(&scraper::Selector::parse("body").unwrap())
                            .next()
                    });

                if let Some(content) = selected_body {
                    // `TODO`: Convert to MD-like format to get better paragraphs,
                    // headings, and general formatting.
                    let text = content.text();

                    let mut document = String::with_capacity(body.len() / 2);

                    for text_node in text {
                        document.push_str(text_node.trim());
                        document.push_str("\n\n");
                    }

                    Cow::Owned(document)
                } else {
                    info!("Kvarn gave HTML response without body.");
                    return Err(());
                }
            }
        }
        Some(mime)
            if mime.type_() == internals::mime::TEXT && mime.subtype() != internals::mime::CSS =>
        {
            String::from_utf8_lossy(body)
        }
        _ => return Err(()),
    };
    Ok(text)
}

/// To not have to [`Arc`]s.
#[derive(Debug)]
struct SearchEngineHandleInner {
    index: RwLock<search::SimpleIndex>,
    doc_map: RwLock<search::DocumentMap>,
}

#[derive(Debug, Clone)]
pub struct SearchEngineHandle {
    inner: Arc<SearchEngineHandleInner>,
}
impl SearchEngineHandle {
    /// This spawns a new [task](tokio::spawn) for every request it makes.
    /// The requests are processed in parallell - this should return within the longest response
    /// duration-
    pub async fn index(&self, host: &Host) {
        let documents = find_documents(host);

        let mut handles = Vec::with_capacity(documents.len());

        for document in documents {
            let mut request = request(&document);

            // SAFETY: We use the pointer inside the future.
            // When we await all handles at the end of this fn, the pointer is no longer used.
            // Therefore, it doesn't escape this fn. host isn't used after it's lifetime.
            let host_ptr = unsafe { utils::SuperUnsafePointer::new(host) };
            let me = self.clone();
            let handle = tokio::spawn(async move {
                let host = unsafe { host_ptr.get() };
                let response = kvarn::handle_cache(
                    &mut request,
                    net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0).into(),
                    host,
                )
                .await;

                if !response.response.status().is_success() {
                    return;
                }

                let text = if let Ok(text) = text_from_response(&response) {
                    text
                } else {
                    return;
                };

                let id = {
                    let mut doc_map = me.inner.doc_map.write().await;

                    doc_map.reserve_id(document)
                };

                {
                    // `TODO`: Do this on a blocking thread. How to get lock?
                    let mut index = me.inner.index.write().await;
                    index.digest_document(id, &text);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.expect("indexing task panicked");
        }

        info!(
            "Indexing done. {} words.",
            self.inner.index.read().await.words().count()
        );
        debug!("Doc map: {:#?}", self.inner.doc_map.read().await);
    }
}

/// `path`: the path to use for the search API.
/// Use something which starts with `/./` if you don't want it to be public.
pub async fn mount_search(
    extensions: &mut Extensions,
    path: impl AsRef<str>,
) -> SearchEngineHandle {
    let index = search::SimpleIndex::new(0.85, search::proximity::Algorithm::Hamming, 2_500);
    let doc_map = search::DocumentMap::new();

    let handle = SearchEngineHandle {
        inner: Arc::new(SearchEngineHandleInner {
            index: RwLock::new(index),
            doc_map: RwLock::new(doc_map),
        }),
    };
    let ext_handle = handle.clone();

    extensions.add_prepare_single(
        path,
        prepare!(req, host, _path, _addr, move |ext_handle| {
            struct UnsafeSendSync<T>(T);
            unsafe impl<T> Send for UnsafeSendSync<T> {}
            unsafe impl<T> Sync for UnsafeSendSync<T> {}
            impl<T, F: Future<Output = T> + Unpin> Future for UnsafeSendSync<F> {
                type Output = T;
                fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                    Pin::new(&mut self.0).poll(cx)
                }
            }

            let now = time::Instant::now();

            let handle = ext_handle;

            let query = utils::parse::query(req.uri().query().unwrap_or(""));

            let query = if let Some(query) = query.get("q") {
                query
            } else {
                return default_error_response(
                    StatusCode::BAD_REQUEST,
                    host,
                    Some("specify the search query using URI query parameter `q`"),
                )
                .await;
            };

            let query: search::Query = match query.value().parse() {
                Ok(q) => q,
                Err(err) => {
                    let message = format!("query malformed: {}", err);
                    return default_error_response(StatusCode::BAD_REQUEST, host, Some(&message))
                        .await;
                }
            };

            warn!("Starting getting docs: {:?}", now.elapsed().as_micros());

            let documents: Vec<_> = {
                let lock = handle.inner.index.read().await;
                let documents = query.documents(&*lock).map(UnsafeSendSync);
                let documents = match documents {
                    Ok(docs) => docs,
                    Err(err) => match err {
                        search::query::IterError::StrayNot => {
                            return default_error_response(
                                StatusCode::BAD_REQUEST,
                                host,
                                Some("NOT without AND, this is an illegal operation"),
                            )
                            .await
                        }
                    },
                };

                let documents = documents.0;
                documents.collect()
            };

            warn!("Get docs with query: {:?}", now.elapsed().as_micros());

            let documents = {
                let lock = handle.inner.doc_map.read().await;
                let mut docs = Vec::with_capacity(documents.len());
                for id in documents {
                    // ~~UNWRAP: We have just gotten this from the index, which is "associated" with
                    // this doc map.~~
                    // It could have been removed in the process.
                    if let Some(name) = lock.get_name(id) {
                        docs.push((id, name.to_owned()));
                    }
                }
                docs
            };

            warn!("Get docs names: {:?}", now.elapsed().as_micros());

            let documents = {
                let doc_len = documents.len();

                let mut handles = Vec::with_capacity(doc_len);

                for (id, doc) in documents {
                    let host_ptr = unsafe { utils::SuperUnsafePointer::new(host) };
                    let handle = tokio::spawn(async move {
                        let host = unsafe { host_ptr.get() };
                        debug!("Requesting {}{}", host.name, doc);
                        let mut request = request(&doc);

                        let response = UnsafeSendSync(Box::pin(kvarn::handle_cache(
                            &mut request,
                            net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0).into(),
                            host,
                        )));
                        let response = response.await;

                        let text = if let Ok(text) = text_from_response(&response) {
                            text
                        } else {
                            return None;
                        };

                        Some((id, Arc::new(text.into_owned())))
                    });

                    handles.push(handle);
                }

                let mut docs = HashMap::with_capacity(doc_len);

                for handle in handles {
                    let value = handle.await.expect("Kvarn panicked");
                    if let Some((id, text)) = value {
                        docs.insert(id, text);
                    }
                }

                docs
            };

            warn!("Get doc contents: {:?}", now.elapsed().as_micros());

            let mut hits: Vec<_> = {
                let index = handle.inner.index.read().await;
                let doc_map = handle.inner.doc_map.read().await;
                let mut occurrences = search::SimpleIndexOccurenceProvider::new(&*index);
                for (id, body) in &documents {
                    occurrences.add_document(*id, Arc::clone(body));
                }

                // UNWRAP: We handled this above, and have asserted there are not stray NOTs in the
                // query.
                let occurrences = query.occurrences(&occurrences, 100).unwrap();

                let occurrences = occurrences.map(|occurrence| {
                    fn first_char_boundary(s: &str, start: usize, backwards: bool) -> usize {
                        let mut start = start;
                        loop {
                            if s.is_char_boundary(start) {
                                break;
                            }
                            if backwards {
                                start -= 1;
                            } else {
                                start += 1;
                            }
                        }
                        start
                    }
                    let id = occurrence.id();
                    let doc = &documents[&id];
                    let start =
                        first_char_boundary(doc, occurrence.start().saturating_sub(50), false);
                    let end = first_char_boundary(
                        doc,
                        std::cmp::min(occurrence.start() + 50, doc.len()),
                        true,
                    );

                    let context = doc[start..end].to_owned();

                    HitResponse {
                        start: occurrence.start(),
                        rating: occurrence.rating(),
                        path: doc_map.get_name(id).unwrap_or("").to_owned(),
                        context,
                        start_in_context: occurrence.start() - start,

                        associated_occurrences: occurrence
                            .associated_occurrences()
                            .map(|occ| occ.start())
                            .collect(),
                    }
                });

                occurrences.collect()
            };

            warn!("Get hits / occurrences: {:?}", now.elapsed().as_micros());

            hits.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap());

            hits.drain(std::cmp::min(hits.len(), 50)..);

            let mut body = WriteableBytes::with_capacity(256);

            // UNWRAP: The values should not panic when serializing.
            serde_json::to_writer(&mut body, &hits).unwrap();

            let response = Response::builder()
                .header("content-type", "application/json")
                .body(body.into_inner().freeze())
                .unwrap();

            warn!("Done: {:?}", now.elapsed().as_micros());

            FatResponse::no_cache(response)
        }),
    );

    handle
}

fn find_documents(host: &Host) -> Vec<String> {
    struct PrefixPath {
        path: PathBuf,
        absolute: bool,
    }
    impl PrefixPath {
        fn new(host: &Host) -> Self {
            Self {
                path: host.path.join(host.options.get_public_data_dir()),
                absolute: false,
            }
        }
        fn prefix(&self) -> &Path {
            &self.path
        }
        fn make_absolute(&mut self) {
            if self.path.is_absolute() || self.absolute {
                return;
            }
            if let Ok(mut current) = std::env::current_dir() {
                current.push(self.prefix());
                self.path = current;
            }
            self.absolute = true;
        }
    }

    let mut list: Vec<_> = host
        .extensions
        .get_prepare_single()
        .keys()
        .cloned()
        .collect();

    let host_absolute = host.path.is_absolute() || host.options.get_public_data_dir().is_absolute();
    let mut prefix_path = PrefixPath::new(host);

    for entry in walkdir::WalkDir::new(prefix_path.prefix())
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir())
    {
        let path = entry.path();

        if path.is_absolute() && !host_absolute {
            prefix_path.make_absolute();
        }

        let uri_path = if let Ok(uri_path) = path.strip_prefix(prefix_path.prefix()) {
            uri_path
        } else {
            warn!("Host path isn't prefix of indexed resource.");
            path
        };

        if let Some(uri_path) = uri_path.to_str() {
            let uri_path = format!("/{}", uri_path);
            list.push(uri_path);
        } else {
            warn!("Path {:?} is not UTF-8. Will not index.", uri_path);
        }
        // strip prefix.
        // if entry is absolute but not host path, make a struct which caches the absolute
        // prefix of the host path.
    }

    list
}

// Watch for changes and rebuild index/cache, only for the resources that changed.
// pub fn watch(host: &Host, handle: SearchEngineHandle) {}
