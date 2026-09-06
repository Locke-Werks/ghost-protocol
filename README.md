<div align="center">

<img src="assets/ghost-protocol.png" width="96" alt="Ghost Protocol">

# Ghost Protocol

**A relay for pages that refuse to talk to you.**

[![license](https://img.shields.io/badge/license-GPLv3-d6262a?style=flat-square)](LICENSE)
[![platform](https://img.shields.io/badge/platform-Debian%2013-d6262a?style=flat-square)](#requirements)
[![protocol](https://img.shields.io/badge/MCP-Streamable%20HTTP-d6262a?style=flat-square)](#connecting)

</div>

---

An MCP server that browses on an agent's behalf.

You ask Claude to read a page. The site checks the user agent, sees `ClaudeBot`,
and serves a 403. Or it checks the source address, recognises a model
provider's range, and does the same. Or the page is a single-page app and there
is nothing in the HTML to read anyway.

Ghost Protocol loads that page in a real Google Chrome on a server that belongs
to neither of you, presenting an ordinary Windows 11 Chrome identity, and hands
back two things: the page as readable text, and a screenshot of what it looked
like. Both are labelled as untrusted the whole way.

## What it does

Seven tools, split between the browser path and a plain HTTP one.

- **`ghost_fetch`** — load a URL, read it, throw the browser away. One call,
  one page.
- **`ghost_open`** / **`ghost_act`** / **`ghost_close`** — the same thing, but
  the browser stays open so an agent can click through a docs set across
  several turns. Cookies and storage live inside the session and die with it.
- **`ghost_sessions`** — what you have open, where each one is parked, and
  every host it has touched.
- **`ghost_document`** — read a PDF, Word document, spreadsheet or deck.
- **`ghost_curl`** — one GET or HEAD with Chrome-on-Windows headers and no
  browser at all. Right for JSON APIs, `robots.txt`, `llms.txt`, and for
  telling apart a block served at the HTTP layer from one drawn by a script.

Text comes back as markdown by default, extracted with Readability and
converted with Turndown. Plain text and cleaned HTML are also available.

Screenshots come back as WebP tiles roughly 1280x1600, top to bottom. A single
full-page image of a long documentation page is the obvious implementation and
it produces something useless: a 1280x8000 capture gets downscaled to fit a
vision model's input budget and every line of body text turns to grey smear.
Height is the enemy, so the capture is sliced and the number of tiles is
capped.

## Documents

Half the links worth following are not pages. A URL that turns out to be a PDF
loads into Chrome's PDF viewer, whose DOM is a single `<embed>` element, so
reading it the usual way returns an empty page and a picture of a toolbar. A
`.docx` link does not even navigate: Chrome answers it with a download, which
this relay refuses, so the fetch aborts and nothing lands at all.

So documents are read as documents.

| | |
| --- | --- |
| PDF | page by page, with metadata and the outline |
| `.docx` | headings, lists, tables, hyperlinks with their real targets, footnotes, endnotes and review comments |
| `.xlsx` | one markdown table per sheet, hidden sheets included and labelled |
| `.pptx` | slide by slide in presentation order, speaker notes included |
| `.odt` `.ods` `.odp` | the OpenDocument equivalents of the three above |

`ghost_document` does this directly and takes a page range, so a 400-page PDF
is read in pieces rather than refused. `ghost_fetch`, `ghost_open` and
`ghost_curl` route to the same reader on their own when a URL turns out to be
one of these, and a click inside a session that produces a download reports the
URL rather than looking like a click that missed. Pass `include_file` to get the
raw bytes back as well, or instead, when the format is one this cannot read.

Two things are worth knowing about the output. A spreadsheet's dates are stored
as floating-point day counts, so a reader that skips the style table reports an
invoice dated `45231`; this one parses enough of `xl/styles.xml` to render them
as dates. And a PDF has no text in it, only instructions for placing glyphs, so
what comes back is a reconstruction — pdf.js's, the same one Firefox ships —
and column order in a complicated layout is inference rather than fact. A
scanned PDF has nothing to reconstruct from and says so; there is no OCR here.

Not read: pre-2007 Office files (`.doc`, `.xls`, `.ppt`), which are OLE
compound documents rather than zipped XML, and RTF. Both are identified by name
rather than mangled into gibberish.

## The part that matters

**Everything this server returns is untrusted data, and it says so four times.**

Some sites now write text aimed at whatever agent might read them. There is no
filter that reliably separates "documentation about prompt injection" from "a
prompt aimed at you", and one that tried would mangle exactly the technical
writing this tool exists to fetch. So the approach is containment rather than
cleaning:

1. **Invisible characters come out.** Zero-width joiners, bidi overrides, tag
   characters, C0 and C1 controls. They exist to make text read differently to
   a machine than to a human, which is the entire trick, and nothing in a
   documentation page needs them.

2. **Text the page hid from its readers is pulled out and reported
   separately.** White-on-white, `display:none`, one-pixel type, elements
   parked at `-9999px`, HTML comments. These are found by checking computed
   styles in the live DOM, which is the only place the question can actually be
   answered, and they are listed above the content rather than silently
   dropped: that a page carried invisible instructions is itself the finding.

   Documents get the same treatment through the same path, because they are
   where this attack has actually been found: a paragraph of instructions in
   white type, or in PDF rendering mode 3 which paints no glyphs at all, aimed
   at whatever model is asked to summarise the file. A Word run marked
   `w:vanish`, a spreadsheet cell in white on white, and a PDF paragraph drawn
   invisibly all come out of the content and into the same report. Ordinary
   structure — a collapsed menu, a filtered row, a hidden worksheet — is
   counted and dropped rather than shouted about, because a warning that fires
   on every third file is one nobody reads.

3. **The payload sits inside a boundary carrying a nonce.** The nonce is minted
   in the server process after the page has already been read, so the page
   never sees it and cannot write its own closing boundary to end the quotation
   early and resume speaking as the server.

4. **Instruction-shaped text is flagged above the content**, where it is read
   before the payload rather than after. The rules are deliberately narrow:
   phrasings that address a model directly, not "the page mentions an API key".
   A warning that fires on every third documentation page trains the reader to
   ignore it.

The content itself is passed through unaltered. A page explaining an injection
attack has to survive being fetched.

The split between what runs in the page and what runs in the server is a
boundary, not a convenience. In-page code gets the DOM work, because it needs
computed styles. Everything a hostile page would want to suppress — the
character strip, the scan, the cap, the envelope — runs afterwards, in Node, on
the returned string. A page can choose what text it hands over. It cannot reach
the code that decides how that text is labelled.

## Where the browser runs

Rendering hostile pages is the job, so the process doing it is the process that
owns nothing.

Chrome runs in its own systemd unit under `ghostbrowser`: no database
credential, no signing key, no read access to the service's secrets. The MCP
service talks to it over a loopback websocket. If a page ever achieves code
execution there, it lands on an account with nothing to take.

**Chrome's own sandbox stays on.** `--no-sandbox` is the reflex when Chrome
will not start under a hardened unit, and it removes the one boundary between a
compromised renderer and everything else. The browser unit instead relaxes
`RestrictNamespaces` and widens `SystemCallFilter` so Chrome can build the user,
PID, network and mount namespaces its sandbox is made of. Those deviations, and
the two others (V8's JIT needs `MemoryDenyWriteExecute=no`; `PrivateUsers` must
stay off so Chrome can nest its own user namespace), are spelled out in
`deploy/ghost-protocol-browser.service`.

Each session gets its own `BrowserContext`, destroyed when the session ends.
Downloads are refused, service workers are blocked, permissions are denied, and
dialogs are dismissed. Refusing downloads means nothing a page offers is ever
written to this disk; the URL is kept and reported, so a file can still be
fetched and read on purpose.

Document parsing is the one piece of format handling that runs in the MCP
process rather than in the browser account, and it runs in a worker thread with
a heap ceiling and a wall-clock timeout. A thread is not the boundary a separate
account is and is not claimed to be. It closes the failure that is actually
likely from a crafted file, which is not code execution but a parse that never
finishes or never stops allocating: a worker can be killed from outside while it
is spinning, and a synchronous parse on the main thread cannot. Above that,
every archive is opened with a budget — entry count, per-entry size, and total
expansion — because a 40 KB `.docx` that inflates to 5 GB is a thing anyone can
build. The XML underneath is read by a scanner that does not process a DTD at
all, so external entities and entity expansion are not attack surface rather
than being defended against.

## Where the requests go

A public endpoint that fetches any URL you name is an SSRF machine unless
something stops it. Whatever else the host can reach, it can reach: databases
and admin APIs bound to loopback, an overlay network interface onto a private
network, a cloud metadata service.

Every outbound connection — the browser's and `ghost_curl`'s alike — goes
through a forward proxy in the MCP process. Chrome resolves nothing itself: it
sends `CONNECT host:port` and the proxy does the lookup, checks **every** address
the name answers with against the reserved and private ranges, and then dials
the address it checked. Pinning the connection to the verified address is what
closes DNS rebinding, and checking all the answers rather than the first is what
closes a name that returns one public address and one private one.

Refused: loopback, RFC 1918, CGNAT, link-local (`169.254.169.254` included),
multicast, reserved, IPv6 unique-local and link-local, and IPv4-mapped IPv6
literals unwrapped first, because `::ffff:127.0.0.1` walking past a v4-only
denylist is the classic way in. Ports are limited to 80, 443, 8080 and 8443.
Each redirect hop is resolved and checked in its own right, since a public host
answering `302` to a private address is the whole point of a redirect attack.

The host's own public address belongs in `deny_addresses`; without it the relay
can be pointed back at the reverse proxy in front of it and used to loop through
whatever else that proxy serves. The built-in ranges cannot close that one,
because the address is a perfectly ordinary public address.

## What it does not hide

Being straight about the limits is more useful than a list of features.

- **`ghost_curl` sends Node's TLS handshake, not Chrome's.** No header will
  make a ClientHello agree with the User-Agent above it. Anything doing JA3 or
  JA4 fingerprinting sees Node. Use `ghost_fetch` for those.
- **`ghost_document` does too.** Fetching a file through a session carries that
  session's cookies and Chrome's headers, which is what a document behind a
  login needs, but the request itself is made by Playwright's own HTTP client
  and the handshake is Node's. The exception is a document Chrome already
  navigated to, where the bytes it received are read back and nothing is
  fetched a second time.
- **A PDF's text is a reconstruction.** Reading order in a multi-column layout,
  table structure, and anything carried only in an image are all inference or
  absent. A scanned page has no text at all and is reported as such rather than
  as an empty document.
- **Font metrics still say Linux.** The identity is consistent across the
  user agent, client hints, `navigator.platform`, WebGL strings, screen
  dimensions and `navigator.webdriver`, and that covers ordinary bot heuristics.
  It is not built to beat a dedicated anti-automation vendor, and a comment
  claiming otherwise would just mislead whoever reads it next.
- **Chrome contacts `www.google.com` once per navigation.** It survives
  `--disable-background-networking`, `--disable-component-update`, disabling
  Safe Browsing and every prefetch flag. It carries nothing, but it is visible
  in the egress log and it is honest to say so.
- **Sessions can type.** `fill` and `press` exist because a docs site without
  its search box is half a docs site, which is also where the read-only
  guarantee stops being structural and starts being a convention.

## Intended Use

Ghost Protocol fetches web pages on behalf of one person, one page at a time, in
response to something that person actually asked for. That is the whole design
intent. It exists because a growing number of sites now serve a blank page or a
403 to anything that looks automated, including an assistant reading a single
article at your request.

Use it the way you would use a browser. Read a page. Follow a link. Check a doc.
If the volume or shape of your traffic would not be plausible coming from a
human at a keyboard, you are outside the intended use.

## Not For

- Bulk extraction, crawling, or mirroring
- Building datasets or training corpora
- Circumventing authentication, paywalls, licensing, or access controls
- Evading a block that exists to protect a system rather than to express a
  preference about automation

The relay presents as an ordinary browser and does not identify itself as a bot.
It does not consult or honor robots.txt. That is stated plainly here because you
should know it going in. robots.txt is addressed to crawlers, and this is not a
crawler, but reasonable people put that line in different places. If a site has
said in plain language that it does not want AI-mediated access to its content,
whether to honor that is your decision and your responsibility. The tool will
not make it for you.

## For Site Operators

If you would rather this tool not reach your content, ordinary controls work.
Authentication, session requirements, rate limiting, and behavioral WAF
challenges all stop it. Ghost Protocol makes no attempt to defeat any of them
and is not designed to. It will fail against a real control, by design, and that
is the intended outcome.

If you believe traffic from this project is causing you a problem, contact
archon@lockewerks.com and I will address it.

## Responsibility

Operators are responsible for their own use, including compliance with site
terms and applicable law. Nothing in this document is legal advice.

## Requirements

- Debian 13 or similar, Node 24 (vendored into the tree rather than taken from
  the system, which is usually older), PostgreSQL 16+.
- `google-chrome-stable` from Google's apt repository. The bundled Chromium
  works but announces itself as Chromium and lacks proprietary codecs.
- Unprivileged user namespaces enabled, which is what Chrome's sandbox is built
  from. `provision.sh` refuses to continue without them rather than letting
  anyone reach for `--no-sandbox`.
- The database holds auth plumbing and a request trail: who fetched what, when,
  and how many findings came back. No page content is ever written to it.
- The MCP unit's `MemoryMax` is 1500M, which is `documents.parse_memory_mb`
  times `documents.parse_concurrency` plus headroom for the main thread and the
  file being read. Raising either of those without raising the unit's limit
  gets the whole service killed rather than one parse abandoned.

## Install

Copy `deploy/deploy.env.example` to `deploy/deploy.env` and fill in your host,
key, hostname and public address. That file is gitignored, which is where those
belong.

```sh
scp deploy/{provision.sh,ghost-protocol.service,ghost-protocol-browser.service,ghost-protocol-site.caddy} root@<host>:/tmp/
scp -r deploy/fail2ban root@<host>:/tmp/
ssh root@<host> 'GHOST_VHOST=ghost.example.com bash /tmp/provision.sh'
```

It creates both accounts, the tree, the database, the secrets, the units, the
vhost and the fail2ban jails, then prints a summary of what it made. Then:

```sh
./deploy/deploy.sh
ghost-cli oauth keygen /etc/ghost-protocol/oauth_signing_key.pem
ghost-cli passwd <principal>
systemctl enable --now ghost-protocol-browser ghost-protocol
```

`config/ghost-protocol.toml.example` documents every setting. Secrets are
environment variables and never config keys.

## Connecting

Add `https://<your-host>/mcp` as a remote MCP connector. The embedded OAuth 2.1
server handles the rest: RFC 8414 and 9728 discovery, RFC
7591 dynamic client registration, PKCE authorization code with S256 required,
and rotating refresh tokens with reuse detection. Sign in at the built-in page
with the principal and password set by `ghost-cli passwd`.

Access tokens are short because there is no revocation store; longevity lives in
the refresh token, which is a database row and can be killed. A refresh token
presented after rotation kills its whole family, and an authorization code
presented twice kills every family that pairing minted. Both are the case where
one of two presenters stole it and there is no way to tell which.

Bad passwords answer 401, which the fail2ban jail counts. Token-endpoint grant
failures answer 400 and never 401, so a connector backend retrying a dead token
cannot accumulate toward a ban and lock out the real user.

## Operating

```sh
ghost-cli log 50           # the last 50 relayed requests, with finding counts
ghost-cli oauth clients    # who has registered
ghost-cli oauth revoke <id>
ghost-cli prune 30         # drop expired grants and old request log
journalctl -u ghost-protocol -f
journalctl -u ghost-protocol-browser -f
```

`/healthz` reports whether the browser is connected and how many sessions are
open. Caddy proxies it; nothing else on the host is exposed.
