"""Tests of the site build (site/build.py): every page renders, every link on the site lands on a page and an anchor
that exist, a change to a source file reaches its page, and the status page keeps the reported deployment."""

import argparse
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SITE))

import build  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DIRECTORY = str(FIXTURES / "directory.json")


def args(out: Path, **kw) -> argparse.Namespace:
    values = {
        "out": str(out),
        "sha": "0123456789abcdef0123456789abcdef01234567",
        "built_at": "2026-01-02T03:04:05Z",
        "running_sha": None,
        "deployed_at": None,
        "previous_status": None,
        "directory": DIRECTORY,
        "report": False,
        "repo": None,
    }
    values.update(kw)
    return argparse.Namespace(**values)


class BuiltSite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "site"
        build.build(args(cls.out))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_page_is_written(self):
        for page in build.PAGES:
            self.assertTrue((self.out / page.out).is_file(), page.out)
        for name in ("status.html", "status.json", "assets/style.css", "assets/search.js", "assets/search.json"):
            self.assertTrue((self.out / name).is_file(), name)

    def test_every_link_on_the_site_lands(self):
        ids = {}
        for page in self.out.glob("*.html"):
            ids[page.name] = set(re.findall(r'\bid="([^"]+)"', page.read_text(encoding="utf-8")))
        missing = []
        for page in self.out.glob("*.html"):
            for href in re.findall(r'href="([^"]+)"', page.read_text(encoding="utf-8")):
                if re.match(r"[a-z]+:", href) or href.startswith("assets/"):
                    continue
                target, _, anchor = href.partition("#")
                target = target or page.name
                if target not in ids:
                    if not (self.out / target).is_file():
                        missing.append(f"{page.name}: {href}")
                elif anchor and anchor not in ids[target]:
                    missing.append(f"{page.name}: {href} (no such anchor)")
        self.assertEqual(missing, [], "links to nothing")

    def test_a_link_into_the_repository_goes_to_github(self):
        running = (self.out / "running.html").read_text(encoding="utf-8")
        self.assertIn(f'{build.REPO_URL}/blob/main/mimihubd/debian/', running)
        self.assertIn('href="divergences.html', running)

    def test_no_page_loads_anything_from_another_site(self):
        for page in self.out.glob("*.html"):
            text = page.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r'<(?:script|link)[^>]+(?:src|href)="https?:', text), page.name)

    def test_each_page_names_the_revision_it_was_built_from(self):
        for page in self.out.glob("*.html"):
            self.assertIn("0123456789ab", page.read_text(encoding="utf-8"), page.name)

    def test_the_search_index_covers_every_page(self):
        index = json.loads((self.out / "assets" / "search.json").read_text(encoding="utf-8"))
        pages = {entry["u"].split("#")[0] for entry in index}
        self.assertEqual(pages, {page.out for page in build.PAGES} | {"status.html"})

    def test_the_status_page_shows_the_directory_and_no_deployment_yet(self):
        status = json.loads((self.out / "status.json").read_text(encoding="utf-8"))
        self.assertIsNone(status["running"])
        self.assertTrue(status["directory"]["read"])
        page = (self.out / "status.html").read_text(encoding="utf-8")
        self.assertIn("No deployment of Haven's hub has been reported", page)
        self.assertIn("draft-ietf-mimi-protocol", page)
        self.assertIn("0x0001", page)


class ASourceChange(unittest.TestCase):
    def test_a_planted_line_reaches_its_page_and_the_search_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            for page in build.PAGES:
                target = repo / page.source
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(build.REPO / page.source, target)
            divergences = repo / "DIVERGENCES.md"
            divergences.write_text(
                divergences.read_text(encoding="utf-8").replace(
                    "## DIV-3 - Assets and OHTTP transport\n",
                    "## DIV-3 - Assets and OHTTP transport\n\nPLANTED-SITE-LINE: this sentence was planted.\n",
                    1,
                ),
                encoding="utf-8",
            )
            self.assertIn("PLANTED-SITE-LINE", divergences.read_text(encoding="utf-8"), "the plant did not apply")
            out = Path(tmp) / "site"
            build.build(args(out, repo=str(repo)))
            self.assertIn("PLANTED-SITE-LINE", (out / "divergences.html").read_text(encoding="utf-8"))
            self.assertIn("PLANTED-SITE-LINE", (out / "assets" / "search.json").read_text(encoding="utf-8"))


class TheRunningRevision(unittest.TestCase):
    A = "a" * 40
    B = "b" * 40

    def test_a_deploy_report_sets_it(self):
        running, before = build.running_state(self.A, "2026-01-02T03:04:05+01:00", None)
        self.assertEqual(running, {"sha": self.A, "since": "2026-01-02T02:04:05Z"})
        self.assertIsNone(before)

    def test_a_build_without_one_keeps_what_was_published(self):
        published = {"running": {"sha": self.A, "since": "2026-01-02T02:04:05Z"}, "previous_running": self.B}
        self.assertEqual(build.running_state(None, None, published), (published["running"], self.B))

    def test_a_new_deploy_moves_the_old_revision_to_previous(self):
        published = {"running": {"sha": self.A, "since": "2026-01-02T02:04:05Z"}}
        running, before = build.running_state(self.B, "2026-01-03T00:00:00Z", published)
        self.assertEqual(running["sha"], self.B)
        self.assertEqual(before, self.A)

    def test_a_report_of_the_same_revision_keeps_the_previous_one(self):
        published = {"running": {"sha": self.A, "since": "x"}, "previous_running": self.B}
        self.assertEqual(build.running_state(self.A, "2026-01-03T00:00:00Z", published)[1], self.B)

    def test_what_is_not_a_commit_or_a_time_is_refused(self):
        for sha, at in (("not-a-sha", "2026-01-02T00:00:00Z"), (self.A, "yesterday"), (self.A, "2026-01-02T00:00:00"),
                        (self.A, None), (None, "2026-01-02T00:00:00Z"), ("$(id)", "2026-01-02T00:00:00Z")):
            with self.assertRaises(build.BuildError, msg=f"{sha!r} {at!r}"):
                build.running_state(sha, at, None)

    def test_the_published_status_carried_into_a_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            published = Path(tmp) / "status.json"
            published.write_text(json.dumps({"running": {"sha": self.A, "since": "2026-01-02T02:04:05Z"}}))
            out = Path(tmp) / "site"
            build.build(args(out, previous_status=str(published)))
            status = json.loads((out / "status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["running"]["sha"], self.A)
            self.assertIn("aaaaaaaaaaaa", (out / "status.html").read_text(encoding="utf-8"))

    def test_a_published_status_that_is_not_json_stops_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            published = Path(tmp) / "status.json"
            published.write_text("<html>not json</html>")
            with self.assertRaises(build.BuildError):
                build.previous_status(str(published))

    def test_no_published_status_yet_is_a_first_build(self):
        self.assertIsNone(build.previous_status("/nonexistent/status.json"))
        self.assertIsNone(build.previous_status(None))

    def test_only_https_and_files_are_read(self):
        with self.assertRaises(build.BuildError):
            build.previous_status("http://example.com/status.json")


class TheDirectory(unittest.TestCase):
    def test_an_unreachable_directory_is_said_so_and_the_build_goes_on(self):
        found = build.directory("/nonexistent/directory.json", "2026-01-02T03:04:05Z")
        self.assertFalse(found["read"])
        self.assertIn("unreachable at 2026-01-02T03:04:05Z", found["why"])


class Links(unittest.TestCase):
    def test_rewrite(self):
        cases = {
            ("../DIVERGENCES.md#div-1", "docs/INTEROP.md"): "divergences.html#div-1",
            ("problems.md", "docs/INTEROP.md"): "problems.html",
            ("../DIVERGENCES.md", "mimihubd/README.md"): "divergences.html",
            ("debian/mimihubd.toml.example", "mimihubd/README.md"):
                f"{build.REPO_URL}/blob/main/mimihubd/debian/mimihubd.toml.example",
            ("status.html", "site/home.md"): "status.html",
            ("#local", "DIVERGENCES.md"): "#local",
            ("https://example.com/x.md", "DIVERGENCES.md"): "https://example.com/x.md",
            ("../../outside.md", "docs/INTEROP.md"): "../../outside.md",
        }
        for (href, source), expected in cases.items():
            self.assertEqual(build.rewrite_href(href, source), expected, href)

    def test_anchors_are_githubs(self):
        self.assertEqual(
            build.github_slug("DIV-16 - a certificate names the provider domains it carries"),
            "div-16---a-certificate-names-the-provider-domains-it-carries",
        )
        self.assertEqual(
            build.github_slug("DIV-23 - with MIMI_LAST_RESORT_REUSE=true, a last-resort KeyPackage"),
            "div-23---with-mimi_last_resort_reusetrue-a-last-resort-keypackage",
        )


if __name__ == "__main__":
    unittest.main()
