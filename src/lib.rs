use elipdotter::index::{OccurenceProvider, Provider};
use kvarn::prelude::*;
use tokio::sync::RwLock;

pub use elipdotter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexKind {
    /// Stores only which documents words appear in.
    /// Requires reading each of those documents when getting the occurrences.
    Simple,
    /// Stores all the occurrences of all the words.
    /// Much faster than [`IndexKind::Simple`] byt requires more memory.
    /// This is basically like loading the entire website into memory.
    Lossless,
}

#[derive(Debug)]
pub struct Options {
    /// The kind of index to use.
    pub kind: IndexKind,

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
    /// Default: [`elipdotter::proximity::Algorithm::Hamming`]
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
    pub clear_interval: Duration,
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
    /// Only used if you call [`SearchEngineHandle::index_all`].
    /// Will only be once, at start-up, if they aren't on the FS.
    ///
    /// Only the [`Uri::path`] component will be used, so setting this to another domain won't work
    /// :)
    pub additional_paths: Vec<Uri>,
    /// Always ignore queries which start with any of these [`Uri`]s.
    ///
    /// Only the [`Uri::path`] component will be used.
    pub ignore_paths: Vec<Uri>,
    /// Ignore these file extensions.
    /// This is useful for not indexing images and other media.
    ///
    /// Defaults: `jpg avif ico png mkv mp4 mp3 m4a wav woff woff2 css js`
    ///
    /// The strings MUST NOT include `.`
    pub ignore_extensions: Vec<String>,

    /// Index the WordPress-generated sitemap at `/sitemap.xml`?
    ///
    /// Default: `false`
    /// Requires features: `wordpress-sitemap`
    pub index_wordpress_sitemap: bool,
}
impl Options {
    pub fn new() -> Self {
        Self {
            kind: IndexKind::Simple,
            force_remove: true,
            proximity_threshold: 0.85,
            proximity_algorithm: elipdotter::proximity::Algorithm::Hamming,
            word_count_limit: 2_500,
            response_hits_limit: 50,
            distance_threshold: 100,
            clear_interval: Duration::from_secs(10 * 60),
            query_max_length: 100,
            query_max_terms: 10,
            additional_paths: Vec::new(),
            ignore_paths: Vec::new(),
            ignore_extensions: vec![
                "jpg".into(),
                "avif".into(),
                "ico".into(),
                "png".into(),
                "mkv".into(),
                "mp4".into(),
                "mp3".into(),
                "m4a".into(),
                "wav".into(),
                "woff".into(),
                "woff2".into(),
                "css".into(),
                "js".into(),
            ],
            index_wordpress_sitemap: false,
        }
    }
}
impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum Index {
    Simple(elipdotter::SimpleIndex),
    Lossless(elipdotter::LosslessIndex),
}
impl Index {
    fn word_count(&self) -> usize {
        match self {
            Index::Simple(i) => i.words().count(),
            Index::Lossless(i) => i.words().count(),
        }
    }
    fn size(&self) -> usize {
        match self {
            Index::Simple(i) => i.size(),
            Index::Lossless(i) => i.size(),
        }
    }
}

#[derive(serde::Serialize)]
struct ResponseOccurrence {
    start: usize,
    ctx_byte_idx: usize,
    ctx_char_idx: usize,
    ctx: String,
}
#[derive(serde::Serialize)]
struct HitResponse {
    path: String,
    rating: f32,

    occurrences: Vec<ResponseOccurrence>,
}

/// `accept` MUST be a valid [`HeaderValue`].
fn request(path: impl AsRef<str>, accept: impl AsRef<str>) -> Request<application::Body> {
    // https://url.spec.whatwg.org/#c0-control-percent-encode-set
    static CODE_SET: &percent_encoding::AsciiSet = &{
        {
            {
                { percent_encoding::CONTROLS }
                    .add(b' ')
                    .add(b'"')
                    .add(b'#')
                    .add(b'<')
                    .add(b'>')
            }
            .add(b'?')
            .add(b'`')
            .add(b'{')
            .add(b'}')
        }
        .add(b':')
        .add(b';')
        .add(b'=')
        .add(b'@')
        .add(b'[')
        .add(b'\\')
        .add(b']')
        .add(b'^')
        .add(b'|')
    }
    .add(b'$')
    .add(b'&');

    let path = path.as_ref();

    Request::builder()
        .uri(percent_encoding::utf8_percent_encode(path, CODE_SET).to_string())
        .method("GET")
        .header("user-agent", "kvarn-search-engine-indexer")
        .header("accept-encoding", "identity")
        .header("accept", accept.as_ref())
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
                    let ignored = |s| {
                        matches!(s, |"code"| "a"
                            | "span"
                            | "i"
                            | "b"
                            | "em"
                            | "strong"
                            | "u"
                            | "s"
                            | "q"
                            | "ul"
                            | "ol"
                            | "table"
                            | "center"
                            | "kbd"
                            | "cite"
                            | "abbr"
                            | "mark"
                            | "dfn"
                            | "small"
                            | "sup"
                            | "sub"
                            | "link"
                            | "script"
                            | "style"
                            | "img"
                            | "video")
                    };
                    let doubled = |s: &str| {
                        s.strip_prefix('h').and_then(|v| {
                            if v.len() != 1 {
                                return None;
                            }
                            let char = v.chars().next().unwrap();
                            if char == 'r' || ('1'..='6').contains(&char) {
                                Some(char)
                            } else {
                                None
                            }
                        })
                    };

                    let nodes = content.descendants();

                    let mut document = String::with_capacity(body.len() / 2);

                    let mut ignore = 0;
                    for node in nodes {
                        if ignore > 0 {
                            ignore -= 1;
                            continue;
                        }
                        if let scraper::Node::Element(e) = node.value() {
                            if let Some(char) = doubled(e.name()) {
                                let hashes: Result<u32, _> = char.to_string().parse();
                                if let Ok(hashes) = hashes {
                                    for _ in 0..hashes {
                                        document.push('#')
                                    }
                                    document.push(' ')
                                }
                            }
                            if e.name() == "table" && e.attr("id") == Some("toc") {
                                ignore = node.descendants().count();
                            }
                        }
                        if let scraper::Node::Text(e) = node.value() {
                            let first = node.prev_sibling().is_none();
                            let last = node.next_sibling().is_none();
                            let trimmed = if e.chars().all(|c| c.is_whitespace()) {
                                continue;
                            } else if first && last {
                                e.trim()
                            } else if first {
                                e.trim_start()
                            } else if last {
                                e.trim_end()
                            } else {
                                e
                            };
                            document.push_str(trimmed);
                            // add newline?
                            if last {
                                let parent = node.parent();
                                let parent_tag = parent
                                    .and_then(|p| p.value().as_element())
                                    .map_or("", |parent| parent.name());
                                let ignore = ignored(parent_tag);
                                if ignore {
                                    // if parent is last in grandparent, just use grandparent's
                                    // newline capabilities.
                                    if let Some(parent) = parent {
                                        if parent.next_sibling().is_none() {
                                            let grandparent = parent.parent();
                                            if let Some(grandparent) = grandparent {
                                                if let Some(tag) = grandparent
                                                    .value()
                                                    .as_element()
                                                    .map(|p| p.name())
                                                {
                                                    if !ignored(tag) {
                                                        if doubled(tag).is_some() {
                                                            document.push_str("\n\n")
                                                        } else {
                                                            document.push('\n')
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    // else (if ignored), do nothing
                                } else if doubled(parent_tag).is_some() {
                                    document.push_str("\n\n");
                                } else {
                                    document.push('\n');
                                }
                            }
                        }
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
    index: RwLock<Index>,
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
    /// duration.
    pub async fn index(&self, host: &Host, documents: impl Iterator<Item = String>) {
        #[derive(Debug)]
        enum UriOrString {
            String(String),
            #[cfg(feature = "wordpress-sitemap")]
            Uri(Uri),
        }
        impl UriOrString {
            fn s(&self) -> &str {
                match self {
                    #[cfg(feature = "wordpress-sitemap")]
                    Self::Uri(uri) => uri.path(),
                    Self::String(s) => s,
                }
            }
            fn into_string(self) -> String {
                match self {
                    #[cfg(feature = "wordpress-sitemap")]
                    Self::Uri(uri) => uri.path().to_owned(),
                    Self::String(s) => s,
                }
            }
        }
        #[cfg(feature = "wordpress-sitemap")]
        #[derive(Debug)]
        enum EitherIter<I1, I2> {
            One(I1),
            Two(I1, I2),
        }
        #[cfg(feature = "wordpress-sitemap")]
        impl<T, I1: Iterator<Item = T>, I2: Iterator<Item = T>> Iterator for EitherIter<I1, I2> {
            type Item = T;
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    Self::One(i) => i.next(),
                    Self::Two(i1, i2) => {
                        if let Some(next) = i1.next() {
                            Some(next)
                        } else {
                            i2.next()
                        }
                    }
                }
            }
        }

        let start = Instant::now();

        #[cfg(feature = "wordpress-sitemap")]
        let bytes = if self.inner.options.index_wordpress_sitemap {
            let mut request = request("/sitemap.xml", "text/xml");

            let response = kvarn::handle_cache(
                &mut request,
                net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0).into(),
                host,
            )
            .await;

            if !response.response.status().is_success() {
                error!("Failed to get WordPress site map for a host where it was enabled");
                return;
            }

            let bytes = response.identity_body;

            Some(bytes)
        } else {
            None
        };
        #[cfg(feature = "wordpress-sitemap")]
        let sitemap = if let Some(bytes) = &bytes {
            let text = if let Ok(s) = str::from_utf8(bytes) {
                s
            } else {
                error!("WordPress supplied a site map with invalid UTF-8");
                return;
            };

            let sitemap = match sitemap_iter::Document::parse(text) {
                Ok(doc) => doc,
                Err(err) => {
                    error!("WordPress supplied an incorrectly formatted sitemap: {err:?}");
                    return;
                }
            };
            Some(sitemap)
        } else {
            None
        };
        #[cfg(feature = "wordpress-sitemap")]
        let urls = if let Some(sitemap) = &sitemap {
            match sitemap.iterate() {
                Ok(iter) => Some(iter.filter_map(|entry| {
                    if let Ok(uri) = entry.location.parse() {
                        Some(uri)
                    } else {
                        error!(
                            "WordPress sitemap contains invalid uri: {:?}",
                            entry.location
                        );
                        None
                    }
                })),
                Err(err) => {
                    error!("WordPress supplied an incorrectly formatted sitemap: {err:?}");
                    None
                }
            }
        } else {
            None
        };

        let size_hint = documents.size_hint();
        let mut handles = Vec::with_capacity(size_hint.1.unwrap_or(size_hint.0));

        let documents = documents.map(UriOrString::String);

        #[cfg(feature = "wordpress-sitemap")]
        let documents = if let Some(urls) = urls {
            EitherIter::Two(documents, urls.map(UriOrString::Uri))
        } else {
            EitherIter::One(documents)
        };

        for document in documents.filter(|doc| {
            !doc.s().starts_with("/./")
                && !self
                    .inner
                    .options
                    .ignore_paths
                    .iter()
                    .any(|ignored| doc.s().starts_with(ignored.path()))
        }) {
            // SAFETY: We use the pointer inside the future.
            // When we await all handles at the end of this fn, the pointer is no longer used.
            // Therefore, it doesn't escape this fn. host isn't used after it's lifetime.
            // could be negated with tokio scoped tasks, but that's not available: https://github.com/tokio-rs/tokio/issues/3162
            let host_ptr = unsafe { utils::SuperUnsafePointer::new(host) };
            let me = self.clone();
            let handle = tokio::spawn(async move {
                let host = unsafe { host_ptr.get() };

                debug!("Getting response from {:?}", document.s());

                let response = me.get_response(host, document.s(), true).await;

                response.map(|text| (document, text))
            });
            handles.push(handle);
        }

        let mut responses = Vec::new();
        for handle in handles {
            if let Some(response) = handle.await.expect("indexing task panicked") {
                responses.push(response);
            }
        }
        let me = self.clone();
        let host_name = host.name.clone();
        // move the processing to the background, so we return early!
        tokio::spawn(async move {
            for (document, text) in responses {
                debug!("Indexing {:?}", document.s());

                let id = {
                    let mut doc_map = me.inner.doc_map.write().await;

                    doc_map.reserve_id(document.into_string())
                };

                {
                    let me = me.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut index =
                            tokio::runtime::Handle::current().block_on(me.inner.index.write());
                        match &mut *index {
                            Index::Simple(i) => i.digest_document(id, &text),
                            Index::Lossless(i) => i.digest_document(id, &text),
                        }
                    })
                    .await
                    .unwrap(); // `TODO`: Investigate if `.await` is a good idea here.
                }
            }
            info!(
                "Indexing done for {}. {} words. Took {}ms. Size in memory is {}KB",
                host_name,
                me.inner.index.read().await.word_count(),
                start.elapsed().as_millis(),
                me.inner.index.read().await.size() / 1024,
            );
            debug!("Doc map: {:#?}", me.inner.doc_map.read().await);
            trace!("Index: {:#?}", me.inner.index.read().await);
        });
    }
    /// Indexes all the pages in `host`.
    ///
    /// Read [this section of an article](https://icelk.dev/articles/search-engine.html#kvarn-integration) about how it fetches this.
    pub async fn index_all(&self, host: &Host) {
        let documents = find_documents(
            host,
            &self.inner.options.additional_paths,
            &self.inner.options.ignore_extensions,
        )
        .await;
        self.index(host, documents.into_iter()).await;
    }

    async fn get_response(&self, host: &Host, document: &str, cache: bool) -> Option<Arc<String>> {
        if cache {
            let cache = self.inner.document_cache.read().await;
            if let Some(text) = cache.get(document) {
                return Some(Arc::clone(text));
            }
        }

        let mut request = request(document, "text/html");

        let response = kvarn::handle_cache(
            &mut request,
            net::SocketAddrV4::new(net::Ipv4Addr::LOCALHOST, 0).into(),
            host,
        )
        .await;

        if !response.response.status().is_success() {
            debug!("Response from Kvarn isn't a 200. Page '{}'", document);
            return None;
        }
        if !response
            .response
            .headers()
            .get("content-type")
            .and_then(|ct| ct.to_str().ok())
            .map_or(false, |ct| ct.contains("text/html"))
        {
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
    ///
    /// This must be called within a Tokio runtime.
    ///
    /// The returned [`notify::RecommendedWatcher`] should not be dropped.
    /// When it is dropped, the functionality of this function stops.
    pub async fn watch(
        &self,
        host_name: impl Into<String>,
        collection: Arc<HostCollection>,
    ) -> Result<notify::RecommendedWatcher, WatchError> {
        use notify::{event::EventKind::*, event::*, RecursiveMode, Watcher};
        use tokio::sync::mpsc::channel;

        struct EventEffects {
            delete: Option<PathBuf>,
            index: Option<PathBuf>,
        }

        let host_name = host_name.into();

        let host = collection
            .get_host(&host_name)
            .ok_or(WatchError::HostNotFound)?;

        if host.options.disable_fs {
            return Err(WatchError::FsDisabled);
        }

        let (tx, mut rx) = channel(1024);

        let rt = tokio::runtime::Handle::current();
        let mut watcher = notify::RecommendedWatcher::new(
            move |res| match res {
                Err(err) => {
                    error!("Failed to watch directory, but continuing: {:?}", err);
                }
                Ok(res) => rt
                    .block_on(async { tx.send(res).await.expect("failed to send notify message") }),
            },
            notify::Config::default(),
        )
        .expect("failed to start watching directory for changes");

        let path = host.path.join(host.options.get_public_data_dir());

        info!("Watching {}", path.display());

        self.inner.watching.store(true, threading::Ordering::SeqCst);

        let host_name = host.name.clone();
        let handle = self.clone();

        watcher.watch(&path, RecursiveMode::Recursive).unwrap();

        tokio::spawn(async move {
            let host = collection
                .get_host(&host_name)
                .expect("we just did this above");
            loop {
                let _handle = tokio::runtime::Handle::current();
                let mut event = if let Some(m) = rx.recv().await {
                    m
                } else {
                    info!("Watcher dropped - stop watching for file changes.");
                    break;
                };
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
                            match &mut *index {
                                Index::Simple(i) => doc_map.force_remove(id, i),
                                Index::Lossless(i) => doc_map.force_remove(id, i),
                            }
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

                    let text = if let Some(text) = handle.get_response(host, &document, false).await
                    {
                        text
                    } else {
                        continue;
                    };

                    let id = {
                        let mut doc_map = handle.inner.doc_map.write().await;

                        doc_map.reserve_id(&document)
                    };

                    let handle = handle.clone();
                    tokio::task::spawn_blocking(move || {
                        let mut index =
                            tokio::runtime::Handle::current().block_on(handle.inner.index.write());
                        match &mut *index {
                            Index::Simple(i) => i.digest_document(id, &text),
                            Index::Lossless(i) => i.digest_document(id, &text),
                        }
                    });
                }
            }
        });
        Ok(watcher)
    }
}

/// `path`: the path to use for the search API.
/// Use something which starts with `/./` if you don't want it to be public.
pub async fn mount_search(
    extensions: &mut Extensions,
    path: impl AsRef<str>,
    mut options: Options,
) -> SearchEngineHandle {
    let path = path.as_ref();
    if let Ok(uri) = path.parse() {
        options.ignore_paths.push(uri);
    } else {
        warn!(
            "Mounting path supplied is not an URI: {path:?}. Should be something like '/search'."
        );
    }
    let index = match options.kind {
        IndexKind::Simple => Index::Simple(elipdotter::SimpleIndex::new(
            options.proximity_threshold,
            options.proximity_algorithm,
            options.word_count_limit,
        )),
        IndexKind::Lossless => Index::Lossless(elipdotter::LosslessIndex::new(
            options.proximity_threshold,
            options.proximity_algorithm,
            options.word_count_limit,
        )),
    };
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
        prepare!(
            req,
            host,
            _path,
            _addr,
            move |ext_handle: SearchEngineHandle| {
                let now = Instant::now();

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
                        return default_error_response(
                            StatusCode::BAD_REQUEST,
                            host,
                            Some(&message),
                        )
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
                    let (documents, proximate_map) = match &*lock {
                        Index::Simple(i) => {
                            let mut d = query.documents(i);
                            let i = d.iter().map(|i| i.collect::<Vec<_>>());
                            (i, d.take_proximate_map())
                        }
                        Index::Lossless(i) => {
                            let mut d = query.documents(i);
                            let i = d.iter().map(|i| i.collect::<Vec<_>>());
                            (i, d.take_proximate_map())
                        }
                    };
                    let docs = match documents {
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

                            let text = se_handle.get_response(host, &doc, true).await?;

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

                    fn collect_hits<'a>(
                        provider: &'a impl OccurenceProvider<'a>,
                        query: &'a elipdotter::Query,
                        distance_threshold: usize,
                        documents: &HashMap<elipdotter::index::Id, Arc<String>>,
                        doc_map: &elipdotter::DocumentMap,
                    ) -> Vec<HitResponse> {
                        // UNWRAP: We handled this above, and have asserted there are not stray NOTs in the
                        // query.
                        let occurrence_iter =
                            query.occurrences(provider, distance_threshold).unwrap();
                        occurrence_iter
                            .map(|hit| {
                                fn first_char_boundary(
                                    s: &str,
                                    start: usize,
                                    backwards: bool,
                                ) -> usize {
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

                                let occurrences = hit.occurrences().filter_map(|occ| {
                                    let Some(doc) = &documents.get(&hit.id()) else {
                                        let loaded = documents.iter()
                                                .map(|(k,v)| {
                                                    let mut s = v.chars().take(50).collect();
                                                    s+= "…";
                                                    (*k, s)
                                                })
                                                .collect::<HashMap<_,String>>();
                                        error!(
                                            "Document {:?} wasn't loaded for the query. \
                                            Documents loaded: {loaded:?}",
                                            hit.id(),
                                        );
                                        return None;
                                    };
                                    let ctx_start = first_char_boundary(
                                        doc,
                                        occ.start().saturating_sub(50),
                                        false,
                                    );
                                    let ctx_end = first_char_boundary(
                                        doc,
                                        std::cmp::min(occ.start() + 50, doc.len()),
                                        true,
                                    );

                                    let ctx = doc[ctx_start..ctx_end].to_owned();

                                    let ctx_byte_idx = occ.start() - ctx_start;

                                    Some(ResponseOccurrence {
                                        start: occ.start(),
                                        ctx_byte_idx,
                                        ctx_char_idx: {
                                            ctx.char_indices()
                                                .position(|(pos, _char)| pos >= ctx_byte_idx)
                                                .unwrap_or(ctx_byte_idx)
                                        },
                                        ctx,
                                    })
                                });

                                HitResponse {
                                    path: doc_map.get_name(hit.id()).unwrap_or("").to_owned(),
                                    rating: hit.rating(),

                                    occurrences: occurrences.collect(),
                                }
                            })
                            .filter(|hit| !hit.occurrences.is_empty())
                            .collect()
                    }

                    match &*index {
                        Index::Simple(index) => {
                            let mut occurrences =
                                elipdotter::SimpleOccurrencesProvider::new(index, &proximate_map);
                            for (id, body) in &documents {
                                occurrences.add_document(*id, Arc::clone(body));
                            }

                            (
                                collect_hits(
                                    &occurrences,
                                    &query,
                                    ext_handle.inner.options.distance_threshold,
                                    &documents,
                                    &doc_map,
                                ),
                                Some(occurrences.missing()),
                            )
                        }
                        Index::Lossless(index) => {
                            let provider =
                                elipdotter::LosslessOccurrencesProvider::new(index, &proximate_map);
                            (
                                collect_hits(
                                    &provider,
                                    &query,
                                    ext_handle.inner.options.distance_threshold,
                                    &documents,
                                    &doc_map,
                                ),
                                None,
                            )
                        }
                    }
                };

                if let Some(missing) = missing {
                    if !missing.list().is_empty() {
                        info!("Removing {} elements from index.", missing.list().len());
                    }
                    let mut index = handle.inner.index.write().await;
                    if let Index::Simple(index) = &mut *index {
                        missing.apply(index);
                    }
                }

                debug!("Get hits / occurrences: {:?}", now.elapsed().as_micros());

                hits.sort_unstable_by(|a, b| {
                    let cmp = b
                        .rating
                        .partial_cmp(&a.rating)
                        .unwrap_or(cmp::Ordering::Equal);
                    // if rating is equal, prefer occurrences which start earlier in the document.
                    if cmp.is_eq() {
                        a.occurrences[0].start.cmp(&b.occurrences[0].start)
                    } else {
                        cmp
                    }
                });

                hits.drain(
                    std::cmp::min(hits.len(), ext_handle.inner.options.response_hits_limit)..,
                );

                let mut body = WriteableBytes::with_capacity(256);

                // UNWRAP: The values should not panic when serializing.
                serde_json::to_writer(&mut body, &hits).unwrap();

                let response = Response::builder()
                    .header("content-type", "application/json")
                    .body(body.into_inner().freeze())
                    .unwrap();

                debug!("Done: {:?}", now.elapsed().as_micros());

                FatResponse::no_cache(response)
            }
        ),
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
            info!(
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
async fn find_documents(
    host: &Host,
    additional: &[Uri],
    ignored_extensions: &[String],
) -> Vec<String> {
    let mut list: Vec<_> = host
        .extensions
        .get_prepare_single()
        .keys()
        .cloned()
        .collect();

    list.extend(additional.iter().map(|uri| uri.path().to_owned()));

    let host_absolute = host.path.is_absolute() || host.options.get_public_data_dir().is_absolute();
    let mut prefix_path = PrefixPath::new(host).await;

    let file_filter = |path: &Path| {
        for ignored in ignored_extensions {
            if path
                .extension()
                .map_or(false, |ext| ext == ignored.as_str())
            {
                return false;
            }
        }
        true
    };

    for entry in walkdir::WalkDir::new(prefix_path.prefix())
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir() && file_filter(e.path()))
    {
        let path = entry.path();

        if let Some(uri_path) = prefix_path.process(path, host_absolute).await {
            list.push(uri_path);
        }
    }

    list
}
