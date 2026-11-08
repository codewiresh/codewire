---
title: Documentation for agents
description: Every page as Markdown, an index in llms.txt and the whole documentation in llms-full.txt, for agents and other tools that read text.
updated: 2026-11-08
weight: 9
---

The documentation is published as Markdown as well as HTML, so an agent can
read it without parsing a web page.

| URL | Contents |
| --- | --- |
| [/docs/llms-full.txt](/docs/llms-full.txt) | Every page, in sidebar order, in one Markdown file |
| [/docs/llms.txt](/docs/llms.txt) | An index: every page's title, Markdown URL and one-line description, grouped by section |
| A page's URL plus `.md` | That page as Markdown, for example [/docs/access/ports.md](/docs/access/ports.md); this overview is [/docs/index.md](/docs/index.md) |

`/llms.txt` and `/llms-full.txt` at the root of `codewire.sh` serve the same
two files. Markdown is sent as `text/markdown` and the two text files as
`text/plain`, both UTF-8.

Each Markdown page starts with its title, its one-line description and a
`Source:` line with the HTML page's URL. Links to other pages point at their
Markdown copies. Every HTML page also names its copy in a
`<link rel="alternate" type="text/markdown">` element.

## Give an agent the docs

Most agents can fetch a URL. Tell yours to read the whole documentation first:

```text
Read https://codewire.sh/docs/llms-full.txt before using cw.
```

For a smaller context, point it at
[/docs/llms.txt](/docs/llms.txt) and let it fetch only the pages it needs.

## The CLI describes itself

An agent driving `cw` can also ask the CLI:

```sh
cw help --all              # every command
cw help create             # one command, with every flag
cw ls --output json        # machine output that never prompts
```

See [Conventions](@/reference/cli/conventions.md) for JSON output and how secret
values are read.
