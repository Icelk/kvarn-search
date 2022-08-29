[![crates.io version](https://img.shields.io/crates/v/kvarn-search)](https://crates.io/crates/kvarn-search)
![lines of code](https://img.shields.io/tokei/lines/github/Icelk/kvarn-search)
![license](https://img.shields.io/github/license/Icelk/kvarn-search)

# [Kvarn search](https://kvarn.org/search.)

Uses [elipdotter](https://github.com/Icelk/elipdotter)
to provide search capabilities for a Kvarn host.

Uses the file system and [`prepare_single`](https://doc.kvarn.org/kvarn/extensions/struct.Extensions.html#method.get_prepare_single)
extensions to get all documents to index.

To get more info, check out the section about this extension in [my article about elipdotter](https://icelk.dev/articles/search-engine.#kvarn-integration).

> This means this implementation currently does not crawl the local site.

This extension provides an endpoint which returns the result in JSON format. The scheme is described on [icelk.dev](https://icelk.dev/api/#search).

For an example of a frontend, check out [this portion of the overview at kvarn.org](https://kvarn.org/search.#frontend).

# Cargo features

Enable the `wordpress-sitemap` feature to automatically index a WordPress site.
You also have to set the option `index_wordpress_sitemap` option in `Options` to enable it.

# Versions

-   0.1.x - `kvarn v0.4`
-   0.2.x - `kvarn v0.4`
-   0.3.x - `kvarn v0.4`
-   0.4.x - `kvarn v0.5.x`

# Changelog

## v0.4.0

-   Add hashes `#` to headings in preview (like headings are written in MarkDown)
-   Ignore Kvarn Chute generated table of content when indexing
-   Update to `kvarn v0.5.0`
-   Updated `notify` dependency

## v0.3.2

-   Fixed issue when files has non-alphanumerical characters in them.

## v0.3.1

-   Removed unwanted debugging.

## v0.3.0

-   Updated [elipdotter](https://crates.io/crates/elipdotter)
    -   See [it's changelog](https://github.com/Icelk/elipdotter#v030) for the comprehensive improvements to search results and performance.
-   Added option [`kind`](https://doc.icelk.dev/kvarn-search/kvarn_search/struct.Options.html#structfield.kind)
    to choose the type of index. Using `Simple` takes less memory. Using `Lossless` is 10x faster but uses more memory (2-4x).

## v0.2.0

-   Updated [elipdotter](https://crates.io/crates/elipdotter)
    -   See [it's changelog](https://github.com/Icelk/elipdotter#v020) for the comprehensive improvements to search results and memory performance.
-   Added option [`ignore_paths`](https://doc.icelk.dev/kvarn-search/kvarn_search/struct.Options.html#structfield.ignore_paths)
    to filter out documents from being indexed.

# Development

Since this is used by some projects which require the git version of Kvarn, this requires [Kvarn](https://github.com/Icelk/kvarn) to be cloned at `../kvarn` during development.

# License

`kvarn-search` is licensed under the [GNU LGPLv3](COPYING).
All contributions must also be.
