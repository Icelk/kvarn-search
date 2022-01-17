use elipdotter::index::Provider;
use kvarn::prelude::*;
use tokio::sync::RwLock;

pub use elipdotter;

#[derive(Debug)]
pub struct Options {
    /// Forces documents which have been deleted to be removed from the index immediately.
    ///
    /// This brings more consistent query times for a bit of performance if the FS is modified
    /// often.
    ///
    /// Default `true`
    pub force_remove: bool,
    /// The limit of word proximity to accept as "close enough".
    ///
    /// Between [0..1], where 1 is the exact word, and 0 is basically everything.
    ///
    /// Default: `0.85`
    pub proximity_threshold: f32,
    /// Which proximity algorithm to use.
    ///
    /// Default: [`search::proximity::Algorithm::Hamming`]
    pub proximity_algorithm: elipdotter::proximity::Algorithm,
    /// The limit of different words where it will only search for proximate words which start with
    /// the same [`char`].
    ///
    /// Default: `2_500`
    pub word_count_limit: usize,
    /// Max number of hits to respond with.
    ///
    /// Does not improve performance of the searching algorithm.
    ///
    /// Default: `50`
    pub response_hits_limit: usize,
    /// Distance of two occurrences where they are considered "next to each other".
    ///
    /// Default: `100`
    pub distance_threshold: usize,
    /// Interval of clearing of the internal cache.
    ///
    /// This greatly improves performance, and stays out of your way, as it clears itself.
    ///
    /// Default: `10 minutes`
    pub clear_interval: time::Duration,
    /// The max length of the input query.
    ///
    /// If the length is too large, often many documents are searched, hurting performance.
    ///
    /// Default: `100`
    pub query_max_length: usize,
    /// The highest number of [`elipdotter::Part::String`] a query can have.
    ///
    /// Allowing too many of these slows down the query.
    ///
    /// Default: `10`
    pub query_max_terms: usize,

    /// Additional documents to always index.
    /// Will only be once, at start-up, if they aren't on the FS.
    ///
    /// Only the [`Uri::path`] component will be used, so setting this to another domain won't work
    /// :)
    pub additional_paths: Vec<Uri>,
}
impl Options {
    pub fn new() -> Self {
        Self {
            force_remove: true,
            proximity_threshold: 0.85,
            proximity_algorithm: elipdotter::proximity::Algorithm::Hamming,
            word_count_limit: 2_500,
            response_hits_limit: 50,
            distance_threshold: 100,
            clear_interval: time::Duration::from_secs(10 * 60),
            query_max_length: 100,
            query_max_terms: 10,
            additional_paths: Vec::new(),
        }
    }
}
impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Serialize)]
struct HitResponse {
    start: usize,
    rating: f32,
    path: String,
    context: String,
    context_start_bytes: usize,
    context_start_chars: usize,

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
    index: RwLock<elipdotter::SimpleIndex>,
    doc_map: RwLock<elipdotter::DocumentMap>,
    options: Options,
    watching: threading::atomic::AtomicBool,
    document_cache: RwLock<HashMap<String, Arc<String>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WatchError {
    /// Can occur if the host name isn't part of the [`HostCollection`] because the host doesn't
    /// exist, or because it's inside another collection.
    HostNotFound,
    /// The [file system feature](host::Options::disable_fs) was disabled for this host.
    FsDisabled,
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
        let start = time::Instant::now();

        let documents = find_documents(host, &self.inner.options.additional_paths).await;

        let mut handles = Vec::with_capacity(documents.len());

        for document in documents {
            // SAFETY: We use the pointer inside the future.
            // When we await all handles at the end of this fn, the pointer is no longer used.
            // Therefore, it doesn't escape this fn. host isn't used after it's lifetime.
            let host_ptr = unsafe { utils::SuperUnsafePointer::new(host) };
            let me = self.clone();
            let handle = tokio::spawn(async move {
                let host = unsafe { host_ptr.get() };
                let response = me.get_response(host, &document).await;

                let text = if let Some(text) = response {
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
            "Indexing done. {} words. Took {}ms.",
            self.inner.index.read().await.words().count(),
            start.elapsed().as_millis(),
        );
        debug!("Doc map: {:#?}", self.inner.doc_map.read().await);
    }

    async fn get_response(&self, host: &Host, document: &str) -> Option<Arc<String>> {
        // {
        // let cache = self.inner.document_cache.read().await;
        // if let Some(text) = cache.get(document) {
        // return Some(Arc::clone(text));
        // }
        // }

        let mut request = request(&document);

        let response = kvarn::handle_cache(
            &mut request,
            net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0).into(),
            host,
        )
        .await;

        if !response.response.status().is_success() {
            info!("Response from Kvarn isn't a 200. Page '{}'", document);
            return None;
        }

        let text = if let Ok(text) = text_from_response(&response) {
            Arc::new(text.into_owned())
        } else {
            return None;
        };

        {
            let mut cache = self.inner.document_cache.write().await;
            cache.insert(document.to_owned(), Arc::clone(&text));
        }
        Some(text)
    }

    /// Watch for changes and rebuild index/cache, only for the resources that changed.
    pub fn watch(
        &self,
        host_name: &'static str,
        collection: Arc<HostCollection>,
    ) -> Result<(), WatchError> {
        use notify::{event::EventKind::*, event::*, RecursiveMode, Watcher};
        use tokio::sync::mpsc::channel;

        struct EventEffects {
            delete: Option<PathBuf>,
            index: Option<PathBuf>,
        }

        let host = collection
            .get_host(host_name)
            .ok_or(WatchError::HostNotFound)?;

        if host.options.disable_fs {
            return Err(WatchError::FsDisabled);
        }

        let (tx, mut rx) = channel(1024);

        let mut watcher = notify::RecommendedWatcher::new(move |res| match res {
            Err(err) => {
                error!("Failed to watch directory, but continuing: {:?}", err);
            }
            Ok(res) => futures::executor::block_on(async {
                tx.send(res).await.expect("failed to send notify message")
            }),
        })
        .expect("failed to start watching directory for changes");

        let path = host.path.join(host.options.get_public_data_dir());

        info!("Watching {}", path.display());

        self.inner.watching.store(true, threading::Ordering::SeqCst);

        let host_name = host.name;
        let handle = self.clone();

        std::thread::spawn(move || {
            watcher.watch(&path, RecursiveMode::Recursive).unwrap();
            std::thread::park();
        });

        tokio::spawn(async move {
            let host = collection
                .get_host(host_name)
                .expect("we just did this above");
            loop {
                let mut event = rx.recv().await.expect("Failed to receive FS watch message");
                let mut iter = std::mem::take(&mut event.paths).into_iter();
                let source = iter.next();
                let destination = iter.next();
                info!(
                    "File {} changed on the FS. {}{}Event is of type {:?}.",
                    source
                        .as_deref()
                        .unwrap_or_else(|| Path::new("<unknown>"))
                        .display(),
                    destination
                        .as_deref()
                        .unwrap_or_else(|| Path::new(""))
                        .display(),
                    if destination.is_some() {
                        " is the destination. "
                    } else {
                        ""
                    },
                    event.kind,
                );
                let effects: EventEffects = match event.kind {
                    Create(CreateKind::File) => EventEffects {
                        delete: None,
                        index: source,
                    },
                    Remove(RemoveKind::File) => EventEffects {
                        delete: source,
                        index: None,
                    },
                    Modify(ModifyKind::Data(_)) => EventEffects {
                        delete: None,
                        index: source,
                    },
                    Modify(ModifyKind::Name(RenameMode::To)) => EventEffects {
                        delete: None,
                        index: source,
                    },
                    Modify(ModifyKind::Name(RenameMode::From)) => EventEffects {
                        delete: source,
                        index: None,
                    },
                    Modify(ModifyKind::Name(RenameMode::Both)) => EventEffects {
                        delete: source,
                        index: destination,
                    },
                    _ => EventEffects {
                        delete: None,
                        index: None,
                    },
                };
                if let Some(delete) = effects.delete.as_ref().and_then(|path| path.to_str()) {
                    if handle.inner.options.force_remove {
                        let mut doc_map = handle.inner.doc_map.write().await;
                        let mut index = handle.inner.index.write().await;

                        let mut path = PrefixPath::new(host).await;
                        let document = if let Some(doc) = path
                            .process(
                                delete,
                                host.path.is_absolute()
                                    || host.options.get_public_data_dir().is_absolute(),
                            )
                            .await
                        {
                            doc
                        } else {
                            continue;
                        };

                        let id = doc_map.get_id(&document);
                        if let Some(id) = id {
                            doc_map.force_remove(id, &mut *index);
                        }
                    } else {
                        // On remove, rely on the missing feature of occurrences to clean it up.
                    }
                }

                if let Some(index) = effects.index.as_ref().and_then(|path| path.to_str()) {
                    {
                        let mut cache = handle.inner.document_cache.write().await;
                        cache.remove(index);
                    }

                    let mut path = PrefixPath::new(host).await;
                    let document = if let Some(doc) = path
                        .process(
                            index,
                            host.path.is_absolute()
                                || host.options.get_public_data_dir().is_absolute(),
                        )
                        .await
                    {
                        doc
                    } else {
                        continue;
                    };

                    let text = if let Some(text) = handle.get_response(host, &document).await {
                        text
                    } else {
                        continue;
                    };

                    let id = {
                        let mut doc_map = handle.inner.doc_map.write().await;

                        doc_map.reserve_id(&document)
                    };

                    {
                        // `TODO`: Do this on a blocking thread. How to get lock?
                        let mut index = handle.inner.index.write().await;
                        index.digest_document(id, &text);
                    }
                }
            }
        });
        Ok(())
    }
}

/// `path`: the path to use for the search API.
/// Use something which starts with `/./` if you don't want it to be public.
pub async fn mount_search(
    extensions: &mut Extensions,
    path: impl AsRef<str>,
    options: Options,
) -> SearchEngineHandle {
    let index = elipdotter::SimpleIndex::new(
        options.proximity_threshold,
        options.proximity_algorithm,
        options.word_count_limit,
    );
    let doc_map = elipdotter::DocumentMap::new();

    let handle = SearchEngineHandle {
        inner: Arc::new(SearchEngineHandleInner {
            index: RwLock::new(index),
            doc_map: RwLock::new(doc_map),
            options,
            watching: false.into(),
            document_cache: RwLock::new(HashMap::new()),
        }),
    };
    let ext_handle = handle.clone();

    extensions.add_prepare_single(
        path,
        prepare!(req, host, _path, _addr, move |ext_handle| {
            struct UnsafeSendSync<T>(T);
            // That's the whole point.
            #[allow(clippy::non_send_fields_in_send_ty)]
            unsafe impl<T> Send for UnsafeSendSync<T> {}
            unsafe impl<T> Sync for UnsafeSendSync<T> {}
            impl<T, F: Future<Output = T> + Unpin> Future for UnsafeSendSync<F> {
                type Output = T;
                fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
                    Pin::new(&mut self.0).poll(cx)
                }
            }
            impl<T> UnsafeSendSync<T> {
                fn inner(self) -> T {
                    self.0
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

            if query.value().len() > handle.inner.options.query_max_length {
                return default_error_response(
                    StatusCode::BAD_REQUEST,
                    host,
                    Some("query is too long"),
                )
                .await;
            }

            let query: elipdotter::Query = match query.value().parse() {
                Ok(q) => q,
                Err(err) => {
                    let message = format!("query malformed: {}", err);
                    return default_error_response(StatusCode::BAD_REQUEST, host, Some(&message))
                        .await;
                }
            };

            {
                let mut string_parts = 0;
                query.root().for_each_string(&mut |_s| string_parts += 1);
                if string_parts > handle.inner.options.query_max_terms {
                    return default_error_response(
                        StatusCode::BAD_REQUEST,
                        host,
                        Some("too many parts in the query"),
                    )
                    .await;
                }
            }

            debug!("Starting getting docs: {:?}", now.elapsed().as_micros());

            let (documents, proximate_map) = {
                let lock = handle.inner.index.read().await;
                let mut documents = query.documents(&*lock);
                let docs = {
                    let documents_iter = documents.iter().map(UnsafeSendSync);
                    let documents_iter = match documents_iter {
                        Ok(docs) => docs,
                        Err(err) => match err {
                            elipdotter::query::IterError::StrayNot => {
                                return default_error_response(
                                    StatusCode::BAD_REQUEST,
                                    host,
                                    Some("NOT without AND, this is an illegal operation"),
                                )
                                .await
                            }
                        },
                    };

                    documents_iter.inner().collect::<Vec<_>>()
                };
                let proximate_map = documents.take_proximate_map();
                (docs, proximate_map)
            };

            debug!("Get docs with query: {:?}", now.elapsed().as_micros());

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

            debug!("Get docs names: {:?}", now.elapsed().as_micros());

            let documents = {
                let doc_len = documents.len();

                let mut handles = Vec::with_capacity(doc_len);

                for (id, doc) in documents {
                    let host_ptr = unsafe { utils::SuperUnsafePointer::new(host) };
                    let se_handle = handle.clone();
                    let handle = tokio::spawn(async move {
                        let host = unsafe { host_ptr.get() };
                        debug!("Requesting {}{}", host.name, doc);

                        let text = se_handle.get_response(host, &doc).await?;

                        Some((id, text))
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

            debug!("Get doc contents: {:?}", now.elapsed().as_micros());

            let (mut hits, missing) = {
                let index = handle.inner.index.read().await;
                let doc_map = handle.inner.doc_map.read().await;
                let mut occurrences =
                    elipdotter::SimpleIndexOccurenceProvider::new(&*index, &proximate_map);
                for (id, body) in &documents {
                    occurrences.add_document(*id, Arc::clone(body));
                }

                // UNWRAP: We handled this above, and have asserted there are not stray NOTs in the
                // query.
                let occurrence_iter = query
                    .occurrences(&occurrences, ext_handle.inner.options.distance_threshold)
                    .unwrap();

                let occurrence_iter = occurrence_iter.map(|occurrence| {
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

                    let context_start_bytes = occurrence.start() - start;

                    HitResponse {
                        start: occurrence.start(),
                        rating: occurrence.rating(),
                        path: doc_map.get_name(id).unwrap_or("").to_owned(),
                        context_start_chars: {
                            context
                                .char_indices()
                                .position(|(pos, _char)| pos >= context_start_bytes)
                                .unwrap_or(context_start_bytes)
                        },
                        context,
                        context_start_bytes,

                        associated_occurrences: occurrence
                            .associated_occurrences()
                            .map(|occ| occ.start())
                            .collect(),
                    }
                });

                let hits = occurrence_iter.collect::<Vec<_>>();

                let missing = occurrences.missing();

                (hits, missing)
            };

            {
                if !missing.list().is_empty() {
                    info!("Removing {} elements from index.", missing.list().len());
                }
                let mut index = handle.inner.index.write().await;
                missing.apply(&mut *index);
            }

            debug!("Get hits / occurrences: {:?}", now.elapsed().as_micros());

            hits.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap());

            hits.drain(std::cmp::min(hits.len(), ext_handle.inner.options.response_hits_limit)..);

            let mut body = WriteableBytes::with_capacity(256);

            // UNWRAP: The values should not panic when serializing.
            serde_json::to_writer(&mut body, &hits).unwrap();

            let response = Response::builder()
                .header("content-type", "application/json")
                .body(body.into_inner().freeze())
                .unwrap();

            debug!("Done: {:?}", now.elapsed().as_micros());

            FatResponse::no_cache(response)
        }),
    );

    let clear_handle = handle.clone();

    tokio::spawn(async move {
        let handle = clear_handle;

        loop {
            tokio::time::sleep(handle.inner.options.clear_interval).await;

            {
                let mut cache = handle.inner.document_cache.write().await;
                cache.clear();
            }
        }
    });

    handle
}

struct PrefixPath {
    path: PathBuf,
    absolute: bool,
}
impl PrefixPath {
    async fn new(host: &Host) -> Self {
        let path = host.path.join(host.options.get_public_data_dir());
        Self {
            path: tokio::fs::canonicalize(&path).await.unwrap_or(path),
            absolute: false,
        }
    }
    fn prefix(&self) -> &Path {
        &self.path
    }
    fn strip_prefix<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        path.strip_prefix(self.prefix()).ok()
    }
    fn update(&mut self, path: impl AsRef<Path>, host_absolute: bool) {
        let path = path.as_ref();
        if !host_absolute && path.is_absolute() {
            self.make_absolute();
        }
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

    async fn process(&mut self, path: impl AsRef<Path>, host_absolute: bool) -> Option<String> {
        let path = path.as_ref();

        let path = if path.is_dir() {
            tokio::fs::canonicalize(path)
                .await
                .unwrap_or_else(|_| path.to_path_buf())
        } else if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) {
            let mut path = tokio::fs::canonicalize(parent)
                .await
                .unwrap_or_else(|_| path.to_path_buf());
            path.push(file_name);
            path
        } else {
            path.to_path_buf()
        };
        self.update(&path, host_absolute);

        let uri_path = if let Some(uri_path) = self.strip_prefix(&path) {
            uri_path
        } else {
            warn!(
                "Host path ({}) isn't prefix of indexed resource.",
                path.display()
            );
            &path
        };
        if let Some(uri_path) = uri_path.to_str() {
            Some(format!("/{}", uri_path))
        } else {
            warn!("Path {:?} is not UTF-8. Will not index.", uri_path);
            None
        }
    }
}
async fn find_documents(host: &Host, additional: &[Uri]) -> Vec<String> {
    let mut list: Vec<_> = host
        .extensions
        .get_prepare_single()
        .keys()
        .cloned()
        .collect();

    list.extend(additional.iter().map(|uri| uri.path().to_owned()));

    let host_absolute = host.path.is_absolute() || host.options.get_public_data_dir().is_absolute();
    let mut prefix_path = PrefixPath::new(host).await;

    for entry in walkdir::WalkDir::new(prefix_path.prefix())
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir())
    {
        let path = entry.path();

        if let Some(uri_path) = prefix_path.process(path, host_absolute).await {
            list.push(uri_path);
        }
    }

    list
}
