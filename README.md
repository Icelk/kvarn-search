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

# License

`kvarn-search` is licensed under the [GNU LGPLv3](COPYING).
All contributions must also be.
