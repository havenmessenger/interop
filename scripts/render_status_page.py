#!/usr/bin/env python3
"""Render a deployment's status page: which revision of this repository a hub runs, what changed since the previous
one, the drafts and sections it implements, its divergences, the problem types it answers with, the deployment's own
settings, and the test vectors to check against, for download.

    render_status_page.py --revision <sha> --deployed-at <ISO 8601> --out <dir>
                          [--previous <sha>] [--repo <checkout>] [--domain <provider domain>]
                          [--setting "<label>=<file>" ...]
    render_status_page.py --self-test

Everything on the page comes from the checkout at --revision: docs/mimi/CONFORMANCE.md, CHANGELOG.md, DIVERGENCES.md,
docs/problems.md, docs/reasons.toml and tests/vectors/. The checkout must be at --revision with no local changes, so the page describes
the code that was built. --setting adds a file of the deployment's own choices (a policy file, a room profile),
shown as it is; pass nothing secret.

Writes <dir>/index.html (static: no script, no external asset), <dir>/status.json (the same facts for a program) and
<dir>/vectors/. Uses the standard library only and makes no network request.
"""

import argparse
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO_URL = "https://github.com/havenmessenger/interop"
PROBLEM_BASE = f"{REPO_URL}/blob/main/docs/problems.md"
MAX_COMMITS = 200


class RenderError(Exception):
    pass


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RenderError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


# --- a Markdown subset: the one these documents use ------------------------------------------------------------


def slug(text: str) -> str:
    """The anchor GitHub gives a heading."""
    text = re.sub(r"[`*]", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


class Links:
    """Resolves a link in a document at `path` (relative to the repository) to an absolute URL at `revision`."""

    def __init__(self, revision: str, path: str):
        self.revision = revision
        self.base = Path(path).parent

    def __call__(self, target: str) -> str | None:
        if target.startswith("#"):
            return None  # an anchor within the source document, which is not this page
        if re.match(r"^https://", target):
            return target
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            return None  # any other scheme is dropped, its text kept
        file, _, anchor = target.partition("#")
        resolved = (self.base / file).as_posix()
        parts = []
        for part in resolved.split("/"):
            if part == "..":
                if parts:
                    parts.pop()
            elif part not in ("", "."):
                parts.append(part)
        url = f"{REPO_URL}/blob/{self.revision}/{'/'.join(parts)}"
        return url + (f"#{anchor}" if anchor else "")


def inline(text: str, links: Links) -> str:
    out, pos = [], 0
    for m in re.finditer(r"`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)", text):
        out.append(emphasis(html.escape(text[pos : m.start()], quote=False)))
        if m.group(1) is not None:
            out.append(f"<code>{html.escape(m.group(1), quote=False)}</code>")
        else:
            label = inline(m.group(2), links)
            url = links(m.group(3))
            out.append(f'<a href="{html.escape(url)}">{label}</a>' if url else label)
        pos = m.end()
    out.append(emphasis(html.escape(text[pos:], quote=False)))
    return "".join(out)


def emphasis(escaped: str) -> str:
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    return re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", escaped)


def cells(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", line)]


def render_markdown(text: str, links: Links, shift: int = 0) -> str:
    """Headings, paragraphs, tables, nested lists and fenced code: the subset the repository's documents use."""
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            out.append(
                f"<pre><code>{html.escape(chr(10).join(lines[i + 1 : j]), quote=False)}</code></pre>"
            )
            i = j + 1
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            level = min(len(m.group(1)) + shift, 6)
            out.append(
                f'<h{level} id="{slug(m.group(2))}">{inline(m.group(2), links)}</h{level}>'
            )
            i += 1
            continue
        if (
            line.lstrip().startswith("|")
            and i + 1 < len(lines)
            and re.match(r"^\s*\|?[\s:|-]+\|?\s*$", lines[i + 1])
        ):
            head = cells(line)
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                rows.append(cells(lines[j]))
                j += 1
            out.append('<div class="table"><table><thead><tr>')
            out.extend(f"<th>{inline(c, links)}</th>" for c in head)
            out.append("</tr></thead><tbody>")
            for row in rows:
                out.append(
                    "<tr>"
                    + "".join(f"<td>{inline(c, links)}</td>" for c in row)
                    + "</tr>"
                )
            out.append("</tbody></table></div>")
            i = j
            continue
        if re.match(r"^\s*([-*]|\d+\.)\s+", line):
            j = i
            block = []
            while j < len(lines) and (
                re.match(r"^\s*([-*]|\d+\.)\s+", lines[j])
                or (lines[j].startswith("  ") and lines[j].strip())
            ):
                block.append(lines[j])
                j += 1
            out.append(render_list(block, links))
            i = j
            continue
        j = i
        para = []
        while (
            j < len(lines)
            and lines[j].strip()
            and not re.match(r"^(#{1,6}\s|```|\s*\||\s*([-*]|\d+\.)\s+)", lines[j])
        ):
            para.append(lines[j].strip())
            j += 1
        out.append(f"<p>{inline(' '.join(para), links)}</p>")
        i = j
    return "\n".join(out)


def render_list(block: list[str], links: Links) -> str:
    """A list whose items may continue on indented lines and hold indented sub-lists."""
    items: list[tuple[int, str, bool]] = []  # (indent, text, ordered)
    for line in block:
        m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", line)
        if m:
            items.append((len(m.group(1)), m.group(3), m.group(2)[0].isdigit()))
        elif items:
            indent, text, ordered = items[-1]
            items[-1] = (indent, f"{text} {line.strip()}", ordered)
    out: list[str] = []
    stack: list[tuple[int, str]] = []
    for indent, text, ordered in items:
        tag = "ol" if ordered else "ul"
        while stack and indent < stack[-1][0]:
            out.append(f"</li></{stack.pop()[1]}>")
        if not stack or indent > stack[-1][0]:
            out.append(f"<{tag}>")
            stack.append((indent, tag))
        else:
            out.append("</li>")
        out.append(f"<li>{inline(text, links)}")
    while stack:
        out.append(f"</li></{stack.pop()[1]}>")
    return "".join(out)


# --- the facts ------------------------------------------------------------------------------------------------


def sections(text: str, level: int) -> list[tuple[str, str]]:
    """(heading, body) for each heading of exactly `level` in `text`."""
    marker = "#" * level + " "
    found, current, body = [], None, []
    for line in text.splitlines():
        if line.startswith(marker):
            if current is not None:
                found.append((current, "\n".join(body)))
            current, body = line[len(marker) :].strip(), []
        elif re.match(r"^#{1,%d} " % level, line):
            if current is not None:
                found.append((current, "\n".join(body)))
            current, body = None, []
        elif current is not None:
            body.append(line)
    if current is not None:
        found.append((current, "\n".join(body)))
    return found


def first_paragraph(body: str) -> str:
    """A section's lead: its first paragraph after any opening table, and the list it introduces when it ends in a
    colon, so a lead never stops mid-sentence."""
    lines = body.strip().splitlines()
    i = 0
    while i < len(lines) and (
        not lines[i].strip() or lines[i].lstrip().startswith("|")
    ):
        i += 1
    para = []
    while i < len(lines) and lines[i].strip() and not lines[i].startswith(("```", "#")):
        para.append(lines[i])
        i += 1
    if para and para[-1].rstrip().endswith(":"):
        while i < len(lines) and not lines[i].strip():
            i += 1
        while i < len(lines) and (
            re.match(r"^\s*([-*]|\d+\.)\s+", lines[i]) or lines[i].startswith("  ")
        ):
            para.append(lines[i])
            i += 1
    return "\n".join(para)


def table_fields(body: str) -> dict[str, str]:
    """The `| field | value |` rows of a section's opening table."""
    fields = {}
    for line in body.strip().splitlines():
        if not line.lstrip().startswith("|"):
            if fields:
                break
            continue
        row = cells(line)
        if len(row) >= 2 and not re.fullmatch(r"[\s:-]*", row[0]):
            fields[row[0].strip("`")] = row[1].strip("`")
    return fields


def changelog_entries(text: str) -> list[str]:
    """Every top-level entry of the changelog, its continuation lines joined."""
    entries, current = [], None
    for line in text.splitlines():
        if line.startswith("- "):
            if current is not None:
                entries.append(current)
            current = line[2:].strip()
        elif current is not None and line.startswith("  ") and line.strip():
            current += " " + line.strip()
        else:
            if current is not None:
                entries.append(current)
            current = None
    if current is not None:
        entries.append(current)
    return entries


def drafts(conformance: str) -> list[dict]:
    for heading, body in sections(conformance, 2):
        if heading == "Drafts":
            rows = [
                cells(line)
                for line in body.splitlines()
                if line.lstrip().startswith("|")
            ]
            return [
                {"draft": r[0].strip("`"), "revision": r[1]}
                for r in rows[2:]
                if len(r) >= 2
            ]
    raise RenderError("docs/mimi/CONFORMANCE.md has no Drafts table")


def conformance_ids(conformance: str) -> list[str]:
    ids = []
    for line in conformance.splitlines():
        if line.lstrip().startswith("|"):
            first = cells(line)[0]
            if re.fullmatch(r"[A-Z]{1,4}\d+[a-z]?", first):
                ids.append(first)
    return ids


def opened_files(repo: Path) -> dict[Path, set[str]]:
    """Each file a Rust source of the repository compiles in with include_str! or include_bytes!, resolved against that
    source as the compiler does, mapped to the sources that open it."""
    opened: dict[Path, set[str]] = {}
    for src in repo.rglob("*.rs"):
        rel = src.relative_to(repo)
        if rel.parts[0] in ("target", ".git"):
            continue
        for m in re.finditer(
            r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)',
            src.read_text(encoding="utf-8"),
        ):
            target = (src.parent / m.group(1)).resolve()
            opened.setdefault(target, set()).add(rel.as_posix())
    return opened


def vectors(repo: Path) -> list[dict]:
    root = repo / "tests" / "vectors"
    opened = opened_files(repo)
    found = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        found.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "opened_by": sorted(opened.get(path.resolve(), ())),
            }
        )
    return found


def gather(repo: Path, revision: str, previous: str | None) -> dict:
    read = lambda p: (repo / p).read_text(encoding="utf-8")  # noqa: E731
    conformance = read("docs/mimi/CONFORMANCE.md")
    changelog = read("CHANGELOG.md")
    divergences = read("DIVERGENCES.md")
    problems = read("docs/problems.md")
    facts = {
        "conformance": conformance,
        "drafts": drafts(conformance),
        "conformance_ids": conformance_ids(conformance),
        "divergences": [
            {
                "id": m.group(1),
                "title": m.group(2),
                "summary": first_paragraph(body),
                "anchor": slug(heading),
            }
            for heading, body in sections(divergences, 2)
            if (m := re.match(r"(DIV-\d+)\s*-\s*(.*)", heading))
        ],
        "problem_types": [
            {
                "type": heading,
                "uri": f"{PROBLEM_BASE}#{slug(heading)}",
                "title": table_fields(body).get("title", ""),
                "status": table_fields(body).get("status", ""),
                "summary": first_paragraph(body),
            }
            for heading, body in sections(problems, 2)
        ],
        "vectors": vectors(repo),
        "reasons": tomllib.loads(read("docs/reasons.toml")).get("reason", []),
        "new_entries": [],
        "commits": [],
        "commit_count": 0,
    }
    if previous:
        try:
            git(repo, "merge-base", "--is-ancestor", previous, revision)
        except RenderError:
            raise RenderError(
                f"the previous revision {previous} is not an ancestor of {revision}"
            ) from None
        try:
            before = set(
                changelog_entries(git(repo, "show", f"{previous}:CHANGELOG.md"))
            )
        except RenderError:
            before = set()
        facts["new_entries"] = [
            e for e in changelog_entries(changelog) if e not in before
        ]
        log = git(
            repo,
            "log",
            f"--max-count={MAX_COMMITS}",
            "--format=%H%x09%s",
            f"{previous}..{revision}",
        )
        facts["commits"] = [
            line.split("\t", 1) for line in log.splitlines() if "\t" in line
        ]
        facts["commit_count"] = int(
            git(repo, "rev-list", "--count", f"{previous}..{revision}").strip()
        )
    else:
        unreleased = next(
            (
                body
                for heading, body in sections(changelog, 2)
                if heading == "Unreleased"
            ),
            "",
        )
        facts["new_entries"] = changelog_entries(unreleased)
    return facts


# --- the page -------------------------------------------------------------------------------------------------

STYLE = """
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#5d5b55;--line:#dcd8cf;--code:#efece5;--link:#1f5f8b}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--fg:#ecebe6;--muted:#a9a69d;--line:#3a3934;--code:#24231f;
--link:#8cc3ea}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,sans-serif}
main{max-width:72rem;margin:0 auto;padding:1.5rem 1rem 4rem}a{color:var(--link)}h1{font-size:1.7rem;margin:.2rem 0}
h2{margin-top:2.6rem;padding-top:.6rem;border-top:1px solid var(--line)}h3{margin-top:1.8rem}
.muted{color:var(--muted)}code,pre{font:.88em ui-monospace,monospace;background:var(--code);border-radius:4px}
code{padding:.05em .3em}pre{padding:.8rem;overflow-x:auto}.table{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.93rem}
th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top}th{background:var(--code)}
nav ul{display:flex;flex-wrap:wrap;gap:.3rem 1rem;padding:0;list-style:none}dt{font-weight:600;margin-top:.8rem}
dd{margin:.2rem 0 0 0}
"""


def page(facts: dict, args) -> str:
    rev, short = args.revision, args.revision[:12]
    title = f"{args.domain} status" if args.domain else "Hub status"
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head><body><main>",
        f"<h1>{html.escape(title)}</h1>",
        '<p class="muted">Generated when this hub was deployed, from the '
        f'<a href="{REPO_URL}/tree/{rev}">interop repository at {short}</a>.</p>',
        "<nav><ul>"
        + "".join(
            f'<li><a href="#{a}">{t}</a></li>'
            for a, t in (
                ("revision", "Revision"),
                ("changes", "What changed"),
                ("conformance", "Conformance"),
                ("divergences", "Divergences"),
                ("problems", "Problem types"),
                ("reasons", "Reasons"),
                ("settings", "Settings"),
                ("vectors", "Test vectors"),
            )
        )
        + "</ul></nav>",
        '<h2 id="revision">Revision</h2><dl>',
        f'<dt>Running</dt><dd><a href="{REPO_URL}/commit/{rev}"><code>{rev}</code></a></dd>',
        f"<dt>Deployed</dt><dd>{html.escape(args.deployed_at)}</dd>",
    ]
    if args.previous:
        parts.append(
            f'<dt>Previous</dt><dd><a href="{REPO_URL}/commit/{args.previous}"><code>{args.previous}</code></a> '
            f'(<a href="{REPO_URL}/compare/{args.previous}...{rev}">compare</a>)</dd>'
        )
    if args.domain:
        url = f"https://{args.domain}/.well-known/mimi-protocol-directory"
        parts.append(
            f'<dt>Directory</dt><dd><a href="{html.escape(url)}">{html.escape(url)}</a></dd>'
        )
    parts.append("</dl>")

    changelog_links = Links(rev, "CHANGELOG.md")
    parts.append('<h2 id="changes">What changed</h2>')
    if args.previous:
        parts.append("<p>Changelog entries added since the previous deployment:</p>")
    else:
        parts.append(
            "<p>No previous deployment is recorded here; the changelog's unreleased entries:</p>"
        )
    if facts["new_entries"]:
        parts.append(
            "<ul>"
            + "".join(
                f"<li>{inline(e, changelog_links)}</li>" for e in facts["new_entries"]
            )
            + "</ul>"
        )
    else:
        parts.append('<p class="muted">None.</p>')
    if facts["commits"]:
        shown, total = len(facts["commits"]), facts["commit_count"]
        count = f"{shown}" if shown == total else f"the latest {shown} of {total}"
        parts.append(f"<h3>Commits ({count})</h3><ul>")
        parts.extend(
            f'<li><a href="{REPO_URL}/commit/{sha}"><code>{sha[:12]}</code></a> {html.escape(subject)}</li>'
            for sha, subject in facts["commits"]
        )
        parts.append("</ul>")

    parts.append('<h2 id="conformance">Conformance</h2>')
    body = re.sub(
        r"\A#[^\n]*\n", "", facts["conformance"]
    )  # its own title; this page has one
    parts.append(render_markdown(body, Links(rev, "docs/mimi/CONFORMANCE.md"), shift=1))

    div_url = f"{REPO_URL}/blob/{rev}/DIVERGENCES.md"
    div_links = Links(rev, "DIVERGENCES.md")
    parts.append(
        '<h2 id="divergences">Divergences</h2><p>Where this code departs from the drafts, and why. The full text: '
        f'<a href="{div_url}">DIVERGENCES.md</a>.</p><dl>'
    )
    for d in facts["divergences"]:
        parts.append(
            f'<dt id="{d["id"].lower()}"><a href="{div_url}#{d["anchor"]}">{d["id"]}</a> '
            f"{inline(d['title'], div_links)}</dt><dd>{render_markdown(d['summary'], div_links)}</dd>"
        )
    parts.append("</dl>")

    prob_links = Links(rev, "docs/problems.md")
    parts.append(
        '<h2 id="problems">Problem types</h2><p>Every refusal this hub answers with an HTTP error status carries an '
        "RFC 9457 problem body whose <code>type</code> is one of these.</p><dl>"
    )
    for p in facts["problem_types"]:
        parts.append(
            f'<dt id="{slug(p["type"])}"><a href="{html.escape(p["uri"])}"><code>{html.escape(p["type"])}'
            f"</code></a> {html.escape(p['status'])}: {html.escape(p['title'])}</dt>"
            f"<dd>{render_markdown(p['summary'], prob_links)}</dd>"
        )
    parts.append("</dl>")

    parts.append(
        '<h2 id="reasons">Reasons</h2><p>Why each refusal is given, and the sentence of the specification it rests '
        "on. Where the behaviour is this code's own, the row says so and names the divergence that explains it.</p>"
        '<div class="table"><table><thead><tr><th>Reason</th><th>Seen as</th><th>Rests on</th><th>Why</th>'
        "</tr></thead><tbody>"
    )
    for r in facts["reasons"]:
        source = html.escape(r["spec"]) + (
            f" §{html.escape(r['section'])}" if r.get("section") else ""
        )
        if r.get("quote"):
            source += f"<br><q>{html.escape(r['quote'])}</q>"
        if r.get("divergence"):
            d = r["divergence"]
            source += f'<br><a href="#{d.lower()}">{html.escape(d)}</a>'
        parts.append(
            f'<tr id="reason-{slug(r["id"])}"><td><code>{html.escape(r["id"])}</code></td>'
            f"<td>{html.escape(r['surfaces_as'])}</td><td>{source}</td><td>{html.escape(r['reason'])}</td></tr>"
        )
    parts.append("</tbody></table></div>")

    parts.append('<h2 id="settings">Settings</h2>')
    if args.setting:
        parts.append(
            "<p>This deployment's own choices, where the drafts leave one, as the hub reads them.</p>"
        )
        for label, content in args.setting:
            parts.append(
                f"<h3>{html.escape(label)}</h3><pre><code>{html.escape(content, quote=False)}</code></pre>"
            )
    else:
        parts.append('<p class="muted">None given.</p>')

    parts.append(
        '<h2 id="vectors">Test vectors</h2><p>The test vectors in this revision, for download. Beside each, the '
        "sources that compile it in (<code>include_str!</code> or <code>include_bytes!</code>); a dash means none "
        "does.</p>"
        '<div class="table"><table><thead><tr><th>File</th><th>Bytes</th><th>SHA-256</th><th>Opened by</th>'
        "</tr></thead><tbody>"
    )
    for v in facts["vectors"]:
        tests = ", ".join(
            f'<a href="{REPO_URL}/blob/{rev}/{html.escape(t)}"><code>{html.escape(t)}</code></a>'
            for t in v["opened_by"]
        )
        parts.append(
            f'<tr><td><a href="vectors/{html.escape(v["path"])}"><code>{html.escape(v["path"])}</code></a></td>'
            f"<td>{v['bytes']}</td><td><code>{v['sha256']}</code></td><td>{tests or '-'}</td></tr>"
        )
    parts.append("</tbody></table></div>")
    parts.append(
        '<p class="muted">The same facts as JSON: <a href="status.json">status.json</a>.</p></main></body></html>\n'
    )
    return "\n".join(parts)


def status_json(facts: dict, args) -> dict:
    return {
        "revision": args.revision,
        "previous": args.previous,
        "deployed_at": args.deployed_at,
        "domain": args.domain,
        "drafts": facts["drafts"],
        "divergences": [d["id"] for d in facts["divergences"]],
        "problem_types": [p["uri"] for p in facts["problem_types"]],
        "reasons": [r["id"] for r in facts["reasons"]],
        "vectors": [
            {k: v[k] for k in ("path", "bytes", "sha256")} for v in facts["vectors"]
        ],
    }


def render(repo: Path, args, check_checkout: bool = True) -> dict:
    if check_checkout:
        head = git(repo, "rev-parse", "HEAD").strip()
        if head != args.revision:
            raise RenderError(f"the checkout is at {head}, not {args.revision}")
        if git(repo, "status", "--porcelain", "--untracked-files=no").strip():
            raise RenderError(
                "the checkout has local changes; the page must describe what was built"
            )
    facts = gather(repo, args.revision, args.previous)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(page(facts, args), encoding="utf-8")
    (out / "status.json").write_text(
        json.dumps(status_json(facts, args), indent=2) + "\n", encoding="utf-8"
    )
    if (out / "vectors").exists():
        shutil.rmtree(out / "vectors")
    shutil.copytree(repo / "tests" / "vectors", out / "vectors")
    return facts


# --- the audit: what a rendered page must hold -----------------------------------------------------------------

REASON_FIELDS = (
    "id",
    "surfaces_as",
    "spec",
    "section",
    "quote",
    "divergence",
    "reason",
)


def check_reasons(facts: dict) -> list[str]:
    """The reason table: complete rows, one per problem type at least, sources named, divergences that exist."""
    errs = []
    reasons = facts["reasons"]
    ids = [r.get("id") for r in reasons]
    if len(ids) != len(set(ids)):
        errs.append("docs/reasons.toml has a repeated id")
    for r in reasons:
        missing = [f for f in REASON_FIELDS if not isinstance(r.get(f), str)]
        if missing:
            errs.append(f"reason {r.get('id')}: missing {', '.join(missing)}")
            continue
        if r["spec"] != "local" and not (
            r["quote"] and (r["section"] or "pull request" in r["spec"])
        ):
            errs.append(
                f"reason {r['id']}: rests on {r['spec']} but quotes no section of it"
            )
        if r["spec"] == "local" and (r["quote"] or r["section"]):
            errs.append(f"reason {r['id']}: a local reason quotes a specification")
    divergences = {d["id"] for d in facts["divergences"]}
    for r in reasons:
        if r.get("divergence") and r["divergence"] not in divergences:
            errs.append(
                f"reason {r.get('id')}: names {r['divergence']}, which DIVERGENCES.md does not have"
            )
    for p in facts["problem_types"]:
        if p["type"] not in ids:
            errs.append(f"problem type {p['type']} has no row in docs/reasons.toml")
    return errs


def audit(out: Path, facts: dict) -> list[str]:
    errs = check_reasons(facts)
    text = (out / "index.html").read_text(encoding="utf-8")
    for r in facts["reasons"]:
        if f'id="reason-{slug(r.get("id", ""))}"' not in text:
            errs.append(f"reason {r.get('id')} is missing")
    for row in facts["conformance_ids"]:
        if f"<td>{row}</td>" not in text:
            errs.append(f"conformance row {row} is missing")
    for d in facts["drafts"]:
        if html.escape(d["draft"]) not in text:
            errs.append(f"draft {d['draft']} is missing")
    for d in facts["divergences"]:
        if f'<dt id="{d["id"].lower()}">' not in text:
            errs.append(f"{d['id']} is missing")
    for p in facts["problem_types"]:
        if f'<dt id="{slug(p["type"])}">' not in text:
            errs.append(f"problem type {p['type']} is missing")
        if not (p["summary"].strip() and p["title"] and p["status"]):
            errs.append(
                f"problem type {p['type']} renders without its title, status or description"
            )
    for d in facts["divergences"]:
        if not d["summary"].strip() or d["summary"].rstrip().endswith(":"):
            errs.append(f"{d['id']}'s lead is empty or stops at a colon")
    for v in facts["vectors"]:
        copy = out / "vectors" / v["path"]
        if f'href="vectors/{v["path"]}"' not in text:
            errs.append(f"vector {v['path']} is not listed")
        if (
            not copy.is_file()
            or hashlib.sha256(copy.read_bytes()).hexdigest() != v["sha256"]
        ):
            errs.append(f"vector {v['path']} is not served as listed")
    if re.search(r"\|\s*-{3,}", text) or re.search(r"\]\([^)]*\)", text):
        errs.append("Markdown syntax was left unrendered")
    if re.search(r"<script|<iframe|<object|<embed|<link\b|<img\b", text, re.I):
        errs.append("the page loads or runs something")
    if re.search(r"\son[a-z]+\s*=", text, re.I):
        errs.append("the page has an inline event handler")
    for href in re.findall(r'href="([^"]*)"', text):
        if not (
            href.startswith(("https://", "#", "vectors/")) or href == "status.json"
        ):
            errs.append(f"a link that is not https, an anchor or a served file: {href}")
    return errs


def self_test() -> int:
    repo = Path(__file__).resolve().parent.parent
    head = git(repo, "rev-parse", "HEAD").strip()
    parent = (
        git(repo, "rev-parse", "HEAD~1").strip()
        if git(repo, "rev-list", "--count", "HEAD").strip() != "1"
        else None
    )
    with tempfile.TemporaryDirectory() as tmp:
        args = argparse.Namespace(
            revision=head,
            previous=parent,
            deployed_at="2026-01-01T00:00:00Z",
            domain="hub.example",
            setting=[("Policy", "mls_ciphersuites = [0x0001]\n")],
            out=tmp,
        )
        facts = render(repo, args, check_checkout=False)
        out = Path(tmp)
        errs = audit(out, facts)
        assert not errs, errs
        assert (
            facts["conformance_ids"]
            and facts["divergences"]
            and facts["problem_types"]
            and facts["vectors"]
        )
        if parent:
            subject = git(repo, "log", "-1", "--format=%s", head).strip()
            assert html.escape(subject) in (out / "index.html").read_text(), (
                "the last commit is not listed"
            )
        status = json.loads((out / "status.json").read_text())
        assert status["revision"] == head and len(status["vectors"]) == len(
            facts["vectors"]
        )
        # "Opened by" names only sources that compile the file in.
        opened = {v["path"]: v["opened_by"] for v in facts["vectors"]}
        assert any(opened.values()), (
            "no vector is credited to any source: the include scan found nothing"
        )
        for path, sources in opened.items():
            for source in sources:
                text = (repo / source).read_text(encoding="utf-8")
                assert Path(path).name in text, (
                    f"{source} is credited with {path} but never names it"
                )
        for v in facts["vectors"]:
            assert f'href="#{slug(v["path"])}"' not in (out / "index.html").read_text()
        for p in facts["problem_types"]:
            assert p["uri"].endswith("#" + slug(p["type"]))

        # The audit catches a page that is wrong. Each plant changes the rendered page and must be reported.
        page_path = out / "index.html"
        good = page_path.read_text()
        row = facts["conformance_ids"][0]
        plants = {
            "a conformance row dropped": good.replace(
                f"<td>{row}</td>", "<td></td>", 1
            ),
            "a divergence dropped": good.replace(
                f'<dt id="{facts["divergences"][0]["id"].lower()}">', "<dt>", 1
            ),
            "a problem type dropped": good.replace(
                f'<dt id="{slug(facts["problem_types"][0]["type"])}">', "<dt>", 1
            ),
            "a vector unlisted": good.replace(
                f'href="vectors/{facts["vectors"][0]["path"]}"', 'href="#"', 1
            ),
            "a script added": good.replace("</main>", "<script>x()</script></main>"),
            "an event handler added": good.replace("<main>", '<main onclick="x()">'),
            "a raw table left": good.replace("</main>", "| a | b |\n|---|---|</main>"),
            "an http link": good.replace(
                "</main>", '<a href="http://example.com">x</a></main>'
            ),
        }
        for name, planted in plants.items():
            page_path.write_text(planted)
            assert audit(out, facts), f"the audit missed: {name}"
        page_path.write_text(good)
        (out / "vectors" / facts["vectors"][0]["path"]).write_bytes(b"changed")
        assert audit(out, facts), (
            "the audit missed: a served vector that differs from the listed one"
        )

    # A cut commit list says how many there were.
    if int(git(repo, "rev-list", "--count", "HEAD").strip()) >= 3:
        global MAX_COMMITS
        saved, MAX_COMMITS = MAX_COMMITS, 1
        try:
            with tempfile.TemporaryDirectory() as tmp:
                args = argparse.Namespace(
                    revision=head,
                    previous=git(repo, "rev-parse", "HEAD~2").strip(),
                    deployed_at="x",
                    domain=None,
                    setting=[],
                    out=tmp,
                )
                render(repo, args, check_checkout=False)
                assert "the latest 1 of 2" in (Path(tmp) / "index.html").read_text(), (
                    "a cut commit list is not marked"
                )
        finally:
            MAX_COMMITS = saved

    # The table check catches a table that is wrong.
    base = gather(repo, head, None)
    first_problem = base["problem_types"][0]["type"]
    table_plants = {
        "a problem type without a row": [
            r for r in base["reasons"] if r["id"] != first_problem
        ],
        "a row naming a divergence that does not exist": base["reasons"]
        + [dict(base["reasons"][0], id="x", divergence="DIV-999")],
        "a row resting on a draft without a quote": base["reasons"]
        + [dict(base["reasons"][0], id="y", spec="RFC 9420", section="7.3", quote="")],
        "a row missing a field": base["reasons"] + [{"id": "z"}],
        "a repeated id": base["reasons"] + [base["reasons"][0]],
    }
    assert not check_reasons(base), check_reasons(base)
    for name, rows in table_plants.items():
        assert check_reasons(dict(base, reasons=rows)), (
            f"the table check missed: {name}"
        )

    # The checkout check: a page is never rendered from a revision other than the one named.
    with tempfile.TemporaryDirectory() as tmp:
        wrong = argparse.Namespace(
            revision="0" * 40,
            previous=None,
            deployed_at="x",
            domain=None,
            setting=[],
            out=tmp,
        )
        try:
            render(repo, wrong)
        except RenderError:
            pass
        else:
            raise AssertionError("rendered from a checkout at another revision")
    print(
        f"render_status_page self-test: ok ({len(plants) + 1 + len(table_plants)} planted errors caught)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--revision")
    parser.add_argument("--previous")
    parser.add_argument("--deployed-at")
    parser.add_argument("--domain")
    parser.add_argument(
        "--setting", action="append", default=[], help='"<label>=<file>"'
    )
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not (args.revision and args.deployed_at and args.out):
        parser.error("--revision, --deployed-at and --out are required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or (
        args.previous and not re.fullmatch(r"[0-9a-f]{40}", args.previous)
    ):
        parser.error("revisions are full 40-character commit ids")
    settings = []
    for item in args.setting:
        label, sep, file = item.partition("=")
        if not sep or not label.strip():
            parser.error(f'--setting takes "<label>=<file>": {item}')
        settings.append((label.strip(), Path(file).read_text(encoding="utf-8")))
    args.setting = settings
    try:
        facts = render(Path(args.repo), args)
    except RenderError as e:
        print(f"render_status_page: {e}", file=sys.stderr)
        return 1
    errs = audit(Path(args.out), facts)
    if errs:
        print(
            "render_status_page: the rendered page is incomplete:\n  "
            + "\n  ".join(errs),
            file=sys.stderr,
        )
        return 1
    print(f"render_status_page: {args.out}/index.html for {args.revision[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
