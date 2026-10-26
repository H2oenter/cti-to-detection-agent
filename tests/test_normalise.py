import pytest

from cti_agent.util.normalise import SourceIndex, fold, item_hash, match_key, refang


@pytest.mark.parametrize(
    ("defanged", "expected"),
    [
        ("hxxp://bad[.]example[.]net/x", "http://bad.example.net/x"),
        ("hXXps[:]//portal(.)example{.}org", "https://portal.example.org"),
        ("hxxps[://]host[dot]io", "https://host.io"),
        ("admin[@]corp[.]io", "admin@corp.io"),
        ("admin[at]corp[.]io", "admin@corp.io"),
        ("198.51.101[.]7", "198.51.101.7"),
        ("fxp://files[.]example[.]com", "ftp://files.example.com"),
        ("plain text stays", "plain text stays"),
    ],
)
def test_refang(defanged, expected):
    assert refang(defanged) == expected


def test_fold_handles_pdf_typography():
    assert fold("ﬁle “quoted” ‘single’ en–dash soft­hyphen​") == (
        "file \"quoted\" 'single' en-dash softhyphen"
    )


def test_match_key_collapses_whitespace_and_refangs():
    assert match_key("  C2 at\n hxxp://a[.]b   ") == "C2 at http://a.b"


@pytest.fixture
def index():
    return SourceIndex(
        [
            "The actor used ﬁle shares to follow-\nup, then ran Power-\nShell “scripts”.",
            "Page two mentions 198.51.101[.]7 as C2.",
        ]
    )


@pytest.mark.parametrize(
    ("quote", "page"),
    [
        ("used file shares to follow-up", 1),
        ('ran PowerShell "scripts"', 1),
        ("ran Power- Shell", 1),
        ("198.51.101.7 as C2", 2),
        ("198.51.101[.]7 as C2", 2),
    ],
)
def test_quote_found_with_page(index, quote, page):
    match = index.find(quote)
    assert match.found
    assert match.page == page


def test_quote_spanning_pages_is_found_without_page(index):
    match = index.find('"scripts". Page two mentions')
    assert match.found
    assert match.page is None


@pytest.mark.parametrize("quote", ["used file shares to follow up later", "invented sentence", ""])
def test_quote_not_found(index, quote):
    assert not index.find(quote).found


def test_single_page_doc_reports_no_page():
    assert SourceIndex(["one page only"]).find("page only").page is None


def test_item_hash_is_stable_across_key_order():
    assert item_hash({"a": 1, "b": [1, 2]}) == item_hash({"b": [1, 2], "a": 1})
    assert item_hash({"a": 1}) != item_hash({"a": 2})
    assert item_hash({"a": 1}).startswith("sha256:")
