#!/usr/bin/env python3
"""Build the mimihubd site from this repository.

    build.py --out <dir> [--sha <sha>] [--built-at <ISO 8601>]
             [--running-sha <sha> --deployed-at <ISO 8601>] [--previous-status <url or path>]
             [--directory <url or path>] [--report] [--repo <checkout>]

Every page but the home page is a file of this repository rendered to HTML (see PAGES), so the site says what the
repository says at the revision it was built from, and each page names that revision. The home page is site/home.md.

The status page shows what Haven's hub runs: the revision its last deploy reported (--running-sha, --deployed-at) and
the hub's public directory, read when the site is built (--directory). A build without a reported revision keeps the
one the published site last showed (--previous-status), so a scheduled rebuild never forgets a deployment; when that
cannot be read for any reason but its absence, the build stops and the published site stays as it was. With --report,
scripts/render_status_page.py renders the full deployment report for the running revision under status/report/.

Needs Python 3.11+ and the markdown package (site/requirements.txt). Writes only under --out.
"""

from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import markdown

REPO = Path(__file__).resolve().parent.parent
SITE = Path(__file__).resolve().parent
REPO_URL = "https://github.com/havenmessenger/interop"
HUB = "mimi.havenmessenger.com"
DIRECTORY_URL = f"https://{HUB}/.well-known/mimi-protocol-directory"
SHA = re.compile(r"[0-9a-f]{7,40}")
FETCH_TIMEOUT = 15
FETCH_LIMIT = 1 << 20


@dataclass(frozen=True)
class Page:
    source: str
    out: str
    nav: str
    description: str


# The pages, in navigation order. `source` is relative to the repository root.
PAGES = (
    Page("site/home.md", "index.html", "Home", "mimihubd, an open-source MIMI hub, and Haven's running instance of it."),
    Page(
        "docs/INTEROP.md",
        "interop.html",
        "Test against our hub",
        "What a provider needs to connect to Haven's hub, and how to ask to be added.",
    ),
    Page("mimihubd/README.md", "running.html", "Run a hub", "Building, configuring and running mimihubd."),
    Page(
        "docs/mimi/CONFORMANCE.md",
        "conformance.html",
        "Conformance",
        "What mimihubd and mimi-core implement, section by section.",
    ),
    Page(
        "DIVERGENCES.md",
        "divergences.html",
        "Divergences",
        "Where mimihubd takes a reading the drafts leave open, and what it does not build yet.",
    ),
    Page(
        "SECURITY-INVARIANTS.md",
        "security.html",
        "Security",
        "The security properties mimihubd holds, and where each is enforced.",
    ),
    Page("docs/problems.md", "problems.html", "Problem types", "The RFC 9457 problem types mimihubd answers with."),
    Page("docs/ARCHITECTURE.md", "architecture.html", "Architecture", "How the repository is laid out."),
    Page("CHANGELOG.md", "changelog.html", "Changelog", "What changed, newest first."),
)
STATUS_OUT = "status.html"
STATUS_NAV = "Live status"
PAGE_OF = {page.source: page.out for page in PAGES}
# A link to one of the site's own pages by its name, as site/home.md writes them, stays as written.
SITE_PAGES = {page.out for page in PAGES} | {STATUS_OUT}


class BuildError(Exception):
    pass


# --- Markdown to HTML --------------------------------------------------------------------------------------------


def github_slug(value: str, separator: str = "-") -> str:
    """A heading's anchor as GitHub writes it, so a link to a section reads the same on GitHub and on the site:
    lowercased, every character but a letter, digit, space, hyphen or underscore dropped, each space a hyphen."""
    value = value.strip().lower()
    value = "".join(c for c in value if c.isalnum() or c in " -_")
    return value.replace(" ", separator)


def _markdown() -> markdown.Markdown:
    return markdown.Markdown(
        extensions=["tables", "fenced_code", "toc", "sane_lists"],
        extension_configs={
            "toc": {
                "permalink": "#",
                "permalink_title": "Link to this section",
                "toc_depth": "2-3",
                "slugify": github_slug,
            },
        },
    )


def rewrite_href(href: str, source: str) -> str:
    """A link as the site serves it: a repository file the site renders goes to its page, any other repository path to
    GitHub at main, and anything absolute or in-page stays as written."""
    if not href or href.startswith(("#", "mailto:")) or re.match(r"[a-z][a-z0-9+.-]*:", href, re.I):
        return href
    path, _, fragment = href.partition("#")
    if path in SITE_PAGES:
        return href
    if path.startswith("/"):
        target = path.lstrip("/")
    else:
        target = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
    if target.startswith("../") or target == "..":
        return href
    anchor = f"#{fragment}" if fragment else ""
    if target in PAGE_OF:
        return PAGE_OF[target] + anchor
    return f"{REPO_URL}/blob/main/{target}{anchor}"


def render(text: str, source: str) -> tuple[str, str]:
    """`text` (Markdown from `source`) as HTML, and its table of contents."""
    md = _markdown()
    body = md.convert(text)
    body = re.sub(
        r'href="([^"]*)"',
        lambda m: f'href="{html.escape(rewrite_href(html.unescape(m.group(1)), source), quote=True)}"',
        body,
    )
    body = body.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")
    toc = md.toc if "<li>" in md.toc else ""
    return body, toc


def page_title(body: str, fallback: str) -> str:
    match = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.S)
    if not match:
        return fallback
    return html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).strip() or fallback


def sections(body: str, title: str, out: str) -> list[dict[str, str]]:
    """The search index's entries for one page: one per h2 and h3, with the text under it."""
    entries = []
    parts = re.split(r'(<h[23] id="[^"]+">.*?</h[23]>)', body, flags=re.S)
    heading, anchor = title, ""
    for part in parts:
        match = re.match(r'<h[23] id="([^"]+)">(.*?)</h[23]>', part, re.S)
        if match:
            anchor = match.group(1)
            heading = html.unescape(re.sub(r"<[^>]+>", "", match.group(2))).replace("#", "").strip()
            continue
        text = " ".join(html.unescape(re.sub(r"<[^>]+>", " ", part)).split())
        if text:
            entries.append(
                {"t": title, "h": heading, "u": out + (f"#{anchor}" if anchor else ""), "x": text[:600]}
            )
    return entries


# --- The page around the content ---------------------------------------------------------------------------------


def nav(current: str) -> str:
    links = [(page.out, page.nav) for page in PAGES] + [(STATUS_OUT, STATUS_NAV)]
    items = []
    for out, label in links:
        here = ' aria-current="page"' if out == current else ""
        items.append(f'<li><a href="{out}"{here}>{html.escape(label)}</a></li>')
    return "\n".join(items)


def wrap(*, title: str, description: str, out: str, body: str, toc: str, source_url: str, stamp: str) -> str:
    aside = (
        f'<aside class="page-toc" aria-labelledby="toc-title"><p id="toc-title">On this page</p>{toc}</aside>'
        if toc
        else ""
    )
    layout = "page with-toc" if toc else "page"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · mimihubd</title>
<meta name="description" content="{html.escape(description, quote=True)}">
<link rel="stylesheet" href="assets/style.css">
<link rel="icon" href="assets/icon.svg" type="image/svg+xml">
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
<header class="site">
<div class="bar">
<a class="brand" href="index.html">mimihubd</a>
<div class="search" role="search">
<label for="q" class="vh">Search the documentation</label>
<input id="q" type="search" placeholder="Search" autocomplete="off" spellcheck="false" aria-controls="results">
<ol id="results" hidden></ol>
</div>
</div>
<nav aria-label="Site"><ul>
{nav(out)}
</ul></nav>
</header>
<div class="{layout}">
{aside}
<main id="content">
{body}
</main>
</div>
<footer class="site">
<p>mimihubd is open source under the Apache License 2.0, built by <a href="https://havenmessenger.com">Haven</a>.
Source: <a href="{REPO_URL}">github.com/havenmessenger/interop</a>.</p>
<p class="stamp">{stamp} <a href="{source_url}">This page's source</a>.</p>
</footer>
<script src="assets/search.js" defer></script>
</body>
</html>
"""


def stamp_line(sha: str | None, built_at: str) -> str:
    if sha:
        return (
            f'Built from <a href="{REPO_URL}/commit/{sha}"><code>{sha[:12]}</code></a> on '
            f"{html.escape(built_at)}."
        )
    return f"Built from a working copy on {html.escape(built_at)}."


# --- The status page ---------------------------------------------------------------------------------------------


def _read(location: str) -> bytes:
    """`location` (an https URL or a local path) as bytes, at most FETCH_LIMIT of them."""
    if location.startswith("https://"):
        request = urllib.request.Request(location, headers={"User-Agent": "mimihubd-site-build"})
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:  # noqa: S310 (https only)
            data = response.read(FETCH_LIMIT + 1)
    elif "://" in location:
        raise BuildError(f"{location}: only https URLs and local paths are read")
    else:
        data = Path(location).read_bytes()
    if len(data) > FETCH_LIMIT:
        raise BuildError(f"{location}: more than {FETCH_LIMIT} bytes")
    return data


def previous_status(location: str | None) -> dict | None:
    """What the published site reported last. None when there is none yet (a first build, or a 404); any other failure
    stops the build, so a deployment is never forgotten because the site could not be read."""
    if not location:
        return None
    try:
        data = _read(location)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise BuildError(f"the published status could not be read ({location}): HTTP {error.code}") from error
    except FileNotFoundError:
        return None
    except (OSError, urllib.error.URLError) as error:
        raise BuildError(f"the published status could not be read ({location}): {error}") from error
    try:
        status = json.loads(data)
    except ValueError as error:
        raise BuildError(f"the published status is not JSON ({location})") from error
    if not isinstance(status, dict):
        raise BuildError(f"the published status is not an object ({location})")
    return status


def checked_time(value: str, what: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise BuildError(f"{what} is not an ISO 8601 time: {value!r}") from error
    if parsed.tzinfo is None:
        raise BuildError(f"{what} names no time zone: {value!r}")
    return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def running_state(
    running_sha: str | None, deployed_at: str | None, previous: dict | None
) -> tuple[dict | None, str | None]:
    """The revision the hub runs and the one it ran before, from a deploy's report or else from the published site."""
    prior = (previous or {}).get("running")
    prior_sha = prior.get("sha") if isinstance(prior, dict) else None
    if running_sha:
        if not SHA.fullmatch(running_sha):
            raise BuildError(f"the running revision is not a commit id: {running_sha!r}")
        if not deployed_at:
            raise BuildError("a running revision needs the time it was deployed")
        before = prior_sha if prior_sha and prior_sha != running_sha else (previous or {}).get("previous_running")
        return {"sha": running_sha, "since": checked_time(deployed_at, "the deploy time")}, before
    if deployed_at:
        raise BuildError("a deploy time needs the revision it deployed")
    if isinstance(prior, dict) and isinstance(prior_sha, str) and SHA.fullmatch(prior_sha):
        return {"sha": prior_sha, "since": prior.get("since")}, (previous or {}).get("previous_running")
    return None, None


def directory(location: str | None, now: str) -> dict:
    if not location:
        return {"read": False, "why": "not read in this build"}
    try:
        data = json.loads(_read(location))
    except (OSError, ValueError, urllib.error.URLError, BuildError) as error:
        return {"read": False, "why": f"unreachable at {now}: {error}"}
    if not isinstance(data, dict):
        return {"read": False, "why": f"not a directory object at {now}"}
    return {"read": True, "at": now, "document": data}


def commits_apart(running: str, main: str | None) -> int | None:
    if not main:
        return None
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), "rev-list", "--count", f"{running}..{main}"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return int(out.stdout.strip())


def glance(status: dict) -> str:
    """The home page's summary of Haven's hub, from the same facts as the status page."""
    rows = [
        ("Hub", f'<a href="https://{HUB}/">{HUB}</a>'),
        ("Directory", f'<a href="{DIRECTORY_URL}"><code>/.well-known/mimi-protocol-directory</code></a>'),
    ]
    found = status.get("directory", {})
    drafts = found.get("document", {}).get("protocol_drafts") if found.get("read") else None
    if isinstance(drafts, dict):
        rows.append(
            ("Drafts", ", ".join(f"{html.escape(str(k))}-{html.escape(str(v))}" for k, v in sorted(drafts.items())))
        )
    running = status.get("running")
    if running:
        sha = running["sha"]
        rows.append(
            (
                "Running",
                f'<a href="{REPO_URL}/commit/{sha}"><code>{sha[:12]}</code></a> '
                f'(<a href="{STATUS_OUT}">live status</a>)',
            )
        )
    rows.append(("Source", f'<a href="{REPO_URL}">github.com/havenmessenger/interop</a>, Apache-2.0'))
    items = "".join(f"<div><dt>{name}</dt><dd>{value}</dd></div>" for name, value in rows)
    return f'<dl class="glance" aria-label="Haven&#x27;s hub at a glance">{items}</dl>'


def status_body(status: dict, report: bool) -> str:
    parts = ["<h1>Live status</h1>"]
    running = status.get("running")
    main = status.get("main")
    parts.append(f'<p>Haven runs mimihubd at <a href="https://{HUB}/">{HUB}</a>.</p>')
    parts.append('<h2 id="revision">The revision it runs</h2>')
    if running:
        sha = running["sha"]
        line = (
            f'Running <a href="{REPO_URL}/commit/{sha}"><code>{sha[:12]}</code></a>'
            f", deployed {html.escape(str(running.get('since') or 'at a time not reported'))}."
        )
        apart = status.get("commits_behind_main")
        if main and apart is not None:
            line += (
                f' This repository\'s main is <a href="{REPO_URL}/commit/{main}"><code>{main[:12]}</code></a>, '
                + ("the same revision." if apart == 0 else f"{apart} commit{'s' if apart != 1 else ''} ahead.")
            )
        parts.append(f"<p>{line}</p>")
        if report:
            parts.append(
                '<p><a href="status/report/index.html">The deployment report</a>: what changed since the previous '
                "deployment, the sections implemented, the divergences, the problem types and the test vectors, "
                "all at the running revision.</p>"
            )
    else:
        parts.append("<p>No deployment of Haven's hub has been reported to this site yet.</p>")
    parts.append('<h2 id="directory">Its directory</h2>')
    found = status.get("directory", {})
    if found.get("read"):
        doc = found["document"]
        url = DIRECTORY_URL
        parts.append(f'<p>Read from <a href="{url}">{url}</a> at {html.escape(found["at"])}.</p>')
        drafts = doc.get("protocol_drafts")
        if isinstance(drafts, dict):
            rows = "".join(
                f"<tr><td>draft-ietf-mimi-{html.escape(str(k))}</td><td>-{html.escape(str(v))}</td></tr>"
                for k, v in sorted(drafts.items())
            )
            parts.append(
                '<div class="table-wrap"><table><thead><tr><th>Draft</th><th>Version</th></tr></thead>'
                f"<tbody>{rows}</tbody></table></div>"
            )
        suites = doc.get("mls_ciphersuites")
        if isinstance(suites, list):
            listed = ", ".join(f"<code>0x{int(s):04x}</code>" for s in suites if isinstance(s, int))
            parts.append(f"<p>MLS ciphersuites accepted: {listed}.</p>")
        unsupported = doc.get("unsupported")
        if isinstance(unsupported, dict) and unsupported:
            items = "".join(
                f"<li><code>{html.escape(str(k))}</code>: {html.escape(str(v))}</li>" for k, v in sorted(unsupported.items())
            )
            parts.append(f"<p>What it says it does not support:</p><ul>{items}</ul>")
    else:
        parts.append(f"<p>Not read: {html.escape(found.get('why', 'no reason given'))}.</p>")
    parts.append(
        '<p>The same facts, for a program: <a href="status.json"><code>status.json</code></a>.</p>'
    )
    return "\n".join(parts)


def render_report(running: dict, before: str | None, out: Path) -> bool:
    """The deployment report for the running revision, from scripts/render_status_page.py run on a checkout of it."""
    with tempfile.TemporaryDirectory() as tmp:
        checkout = Path(tmp) / "running"
        try:
            subprocess.run(
                ["git", "-C", str(REPO), "worktree", "add", "--detach", str(checkout), running["sha"]],
                capture_output=True,
                check=True,
            )
            command = [
                sys.executable,
                str(REPO / "scripts" / "render_status_page.py"),
                "--repo",
                str(checkout),
                "--revision",
                running["sha"],
                "--deployed-at",
                str(running.get("since") or ""),
                "--domain",
                HUB,
                "--out",
                str(out),
            ]
            if before:
                command += ["--previous", before]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"build: the deployment report was not rendered: {result.stderr.strip()}", file=sys.stderr)
                return False
            return True
        except (OSError, subprocess.CalledProcessError) as error:
            print(f"build: the deployment report was not rendered: {error}", file=sys.stderr)
            return False
        finally:
            subprocess.run(
                ["git", "-C", str(REPO), "worktree", "remove", "--force", str(checkout)], capture_output=True
            )


# --- The build ---------------------------------------------------------------------------------------------------


def build(args: argparse.Namespace) -> None:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise BuildError(f"{out} is not empty")
    out.mkdir(parents=True, exist_ok=True)
    built_at = checked_time(args.built_at, "the build time") if args.built_at else dt.datetime.now(
        dt.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if args.sha and not SHA.fullmatch(args.sha):
        raise BuildError(f"the build revision is not a commit id: {args.sha!r}")
    stamp = stamp_line(args.sha, built_at)
    ref = args.sha or "main"

    previous = previous_status(args.previous_status)
    running, before = running_state(args.running_sha, args.deployed_at, previous)
    status = {
        "built_from": args.sha,
        "built_at": built_at,
        "main": args.sha,
        "running": running,
        "previous_running": before,
        "commits_behind_main": commits_apart(running["sha"], args.sha) if running else None,
        "directory": directory(args.directory, built_at),
    }

    root = Path(args.repo) if args.repo else REPO
    index = []
    for page in PAGES:
        source = root / page.source
        if not source.is_file():
            raise BuildError(f"{page.source} is missing")
        body, toc = render(source.read_text(encoding="utf-8"), page.source)
        title = page_title(body, page.nav)
        if page.out == "index.html":
            # The home page is short: no table of contents, and Haven's hub at a glance after its first paragraph.
            toc = ""
            body = body.replace("</p>", "</p>\n" + glance(status), 1)
        (out / page.out).write_text(
            wrap(
                title=title,
                description=page.description,
                out=page.out,
                body=body,
                toc=toc,
                source_url=f"{REPO_URL}/blob/{ref}/{page.source}",
                stamp=stamp,
            ),
            encoding="utf-8",
        )
        index.extend(sections(body, title, page.out))

    report = bool(args.report and running and render_report(running, before, out / "status" / "report"))
    (out / "status.json").write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    body = status_body(status, report)
    (out / STATUS_OUT).write_text(
        wrap(
            title="Live status",
            description="The revision Haven's hub runs, and its directory.",
            out=STATUS_OUT,
            body=body,
            toc="",
            source_url=f"{REPO_URL}/blob/{ref}/site/build.py",
            stamp=stamp,
        ),
        encoding="utf-8",
    )
    index.extend(sections(body, "Live status", STATUS_OUT))

    shutil.copytree(SITE / "assets", out / "assets")
    (out / "assets" / "search.json").write_text(json.dumps(index, separators=(",", ":")), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True)
    parser.add_argument("--sha")
    parser.add_argument("--built-at")
    parser.add_argument("--running-sha")
    parser.add_argument("--deployed-at")
    parser.add_argument("--previous-status")
    parser.add_argument("--directory")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--repo", help="the repository to render, if not the one this script is in (for tests)")
    args = parser.parse_args()
    for name in ("sha", "running_sha", "deployed_at", "previous_status", "directory", "built_at", "repo"):
        if getattr(args, name) == "":
            setattr(args, name, None)
    try:
        build(args)
    except BuildError as error:
        print(f"build: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
