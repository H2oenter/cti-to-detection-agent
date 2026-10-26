import pytest

from cti_agent.inputs import InputError, load_source


def make_pdf(pages: list[str]) -> bytes:
    """A minimal valid PDF with one line of text per page (no PDF library needed)."""
    page_ids = [4 + 2 * i for i in range(len(pages))]
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    for pid, text in zip(page_ids, pages, strict=True):
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {pid + 1} 0 R >>".encode()
        )
        stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
        objects.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{off:010d} 00000 n \n".encode() for off in offsets)
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n".encode()
    out += f"startxref\n{xref}\n%%EOF\n".encode()
    return out


def test_pdf_keeps_pages(tmp_path):
    path = tmp_path / "report.pdf"
    path.write_bytes(make_pdf(["First page about T1621", "Second page with 198.51.101.7"]))
    doc = load_source(path)
    assert doc.media_type == "pdf"
    assert len(doc.pages) == 2
    assert "T1621" in doc.pages[0] and "198.51.101.7" in doc.pages[1]
    assert len(doc.sha256) == 64


def test_html_drops_scripts_but_keeps_text(tmp_path):
    path = tmp_path / "report.html"
    path.write_text(
        "<html><head><title>Advisory</title><script>var x='hidden';</script></head>"
        "<body><h1>Fixture Spider</h1><style>p{}</style><p>C2 at 198.51.101[.]7</p></body></html>",
        encoding="utf-8",
    )
    doc = load_source(path)
    assert doc.media_type == "html"
    assert "Fixture Spider" in doc.text and "198.51.101[.]7" in doc.text
    assert "hidden" not in doc.text and "p{}" not in doc.text


def test_text_file(tmp_path):
    path = tmp_path / "report.txt"
    path.write_text("plain advisory text", encoding="utf-8")
    assert load_source(path).pages == ["plain advisory text"]


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("report.docx", b"x", "unsupported"),
        ("empty.txt", b"   \n  ", "no extractable text"),
        ("broken.pdf", b"not a pdf", "could not read"),
    ],
)
def test_bad_inputs(tmp_path, name, content, message):
    path = tmp_path / name
    path.write_bytes(content)
    with pytest.raises(InputError, match=message):
        load_source(path)


def test_missing_file(tmp_path):
    with pytest.raises(InputError, match="not a file"):
        load_source(tmp_path / "nope.pdf")
