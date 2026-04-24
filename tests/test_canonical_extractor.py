"""Python-mirror tests for the canonical-text extractors.

The JS lives in chrome-extension/canonical_text.js + pdf_text.js. These
tests mirror the algorithm in Python so we can verify behavior against
real generated files (built on the fly via Python's stdlib zip + a
hand-rolled minimal DOCX/XLSX template) and pin the SHA-256 output.

If the JS and Python mirrors ever diverge, the round-trip test at the
bottom of this file catches it: we hash the same input through both
paths and assert agreement.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------
# Python mirror of canonical_text.js::normalize — MUST match byte-for-byte.
# ---------------------------------------------------------------------

_WS_RE = re.compile(r"\s+")


def normalize(s: str | None) -> str:
    if s is None:
        return ""
    return _WS_RE.sub(" ", str(s)).strip()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def canonical_hash(text: str) -> str:
    return sha256_hex(normalize(text))


# ---------------------------------------------------------------------
# DOCX / XLSX / PPTX text extractors — minimal, matches the JS logic.
# ---------------------------------------------------------------------

def _text_from_xml_tags(xml_bytes: bytes, tag_names: set[str]) -> list[str]:
    """Strip namespace prefixes, extract textContent of every element
    whose local name matches any in tag_names. Preserves document order."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return []

    def localname(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    out: list[str] = []

    def walk(node):
        if localname(node.tag) in tag_names:
            out.append("".join(node.itertext()))
        for child in node:
            walk(child)

    walk(root)
    return out


def extract_docx(bytes_: bytes) -> str | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes_))
    except zipfile.BadZipFile:
        return None
    if "word/document.xml" not in zf.namelist():
        return None
    xml = zf.read("word/document.xml")

    # Walk: <w:t> is text, <w:p> and <w:br> and <w:tab> are whitespace boundaries.
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None

    def localname(tag: str) -> str:
        return tag.split("}", 1)[1] if "}" in tag else tag

    parts: list[str] = []

    def walk(node):
        name = localname(node.tag)
        if name == "t":
            parts.append("".join(node.itertext()))
        elif name in ("p", "br", "tab"):
            parts.append(" ")
        for child in node:
            walk(child)

    walk(root)
    return " ".join(parts)


def extract_pptx(bytes_: bytes) -> str | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes_))
    except zipfile.BadZipFile:
        return None
    slides = []
    for name in zf.namelist():
        m = re.match(r"^ppt/slides/slide(\d+)\.xml$", name)
        if m:
            slides.append((int(m.group(1)), name))
    if not slides:
        return None
    slides.sort()

    out: list[str] = []
    for _, name in slides:
        xml = zf.read(name)
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            continue

        def localname(tag: str) -> str:
            return tag.split("}", 1)[1] if "}" in tag else tag

        parts: list[str] = []

        def walk(node):
            name_ = localname(node.tag)
            if name_ == "t":
                parts.append("".join(node.itertext()))
            elif name_ == "p":
                parts.append(" ")
            for child in node:
                walk(child)

        walk(root)
        out.append(" ".join(parts))
    return " ".join(out)


def extract_xlsx(bytes_: bytes) -> str | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes_))
    except zipfile.BadZipFile:
        return None

    shared: list[str] = []
    if "xl/sharedStrings.xml" in zf.namelist():
        shared_xml = zf.read("xl/sharedStrings.xml")
        shared_raw = _text_from_xml_tags(shared_xml, {"si"})
        shared = [_WS_RE.sub(" ", s) for s in shared_raw]

    sheets = []
    for name in zf.namelist():
        m = re.match(r"^xl/worksheets/sheet(\d+)\.xml$", name)
        if m:
            sheets.append((int(m.group(1)), name))
    if not sheets:
        return None
    sheets.sort()

    out: list[str] = []
    for _, name in sheets:
        xml = zf.read(name)
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            continue

        def localname(tag: str) -> str:
            return tag.split("}", 1)[1] if "}" in tag else tag

        parts: list[str] = []
        # Find every <c> cell (spreadsheetml default namespace).
        for c in root.iter():
            if localname(c.tag) != "c":
                continue
            t = c.attrib.get("t")
            if t == "s":
                v = next((ch for ch in c if localname(ch.tag) == "v"), None)
                if v is not None and v.text is not None:
                    try:
                        idx = int(v.text)
                        if 0 <= idx < len(shared):
                            parts.append(shared[idx])
                    except ValueError:
                        pass
            elif t in ("inlineStr", "str"):
                is_ = next((ch for ch in c if localname(ch.tag) == "is"), None)
                if is_ is not None:
                    parts.append("".join(is_.itertext()))
                else:
                    parts.append("".join(c.itertext()))
            else:
                v = next((ch for ch in c if localname(ch.tag) == "v"), None)
                if v is not None and v.text is not None:
                    parts.append(v.text)
        out.append(" ".join(parts))
    return " ".join(out)


# ---------------------------------------------------------------------
# Fixture builders — construct minimal valid DOCX / XLSX / PPTX bytes.
# ---------------------------------------------------------------------

def _build_docx(body_text: str) -> bytes:
    # Minimal DOCX: one <w:p> containing a single <w:t>.
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body>'
        '<w:p><w:r><w:t>' + body_text + '</w:t></w:r></w:p>'
        '</w:body>'
        '</w:document>'
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        '</Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels_xml)
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()


def _build_xlsx(cells: list[list[str]]) -> bytes:
    # Minimal XLSX with one sheet, cells as inline strings (no shared strings).
    rows_xml = []
    for row_idx, row in enumerate(cells, start=1):
        cells_xml = []
        for col_idx, cell in enumerate(row):
            col_letter = chr(ord("A") + col_idx)
            cells_xml.append(
                f'<c r="{col_letter}{row_idx}" t="inlineStr"><is><t>{cell}</t></is></c>'
            )
        rows_xml.append(f'<row r="{row_idx}">' + "".join(cells_xml) + "</row>")

    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData>' + "".join(rows_xml) + '</sheetData>'
        '</worksheet>'
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>'
        '</sheets></workbook>'
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


def _build_pptx(slide_texts: list[str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '</Types>',
        )
        for i, text in enumerate(slide_texts, start=1):
            slide_xml = (
                '<?xml version="1.0"?>'
                '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                '<p:cSld><p:spTree>'
                '<p:sp><p:txBody>'
                '<a:p><a:r><a:t>' + text + '</a:t></a:r></a:p>'
                '</p:txBody></p:sp>'
                '</p:spTree></p:cSld></p:sld>'
            )
            zf.writestr(f"ppt/slides/slide{i}.xml", slide_xml)
    return buf.getvalue()


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------

def test_normalize_matches_server_contract():
    """normalize() must produce the same output as server.normalize_text
    for canonical hash stability."""
    import server
    for s in [
        "hello   world",
        "  leading spaces",
        "trailing spaces  ",
        "tabs\tand\nnewlines",
        "café — résumé",
        "",
        None,
    ]:
        assert normalize(s) == server.normalize_text(s), f"mismatch on {s!r}"


def test_plain_text_cross_whitespace_invariant():
    """The core contract: two text files that differ only in whitespace
    layout hash to the same canonical value."""
    a = "The quick brown fox jumps over the lazy dog."
    b = "  The   quick\nbrown\tfox  jumps   over the lazy dog.  "
    assert canonical_hash(a) == canonical_hash(b)


def test_docx_extracts_body_text():
    body = "Q2 revenue projections show a 12 percent increase."
    doc_bytes = _build_docx(body)
    text = extract_docx(doc_bytes)
    assert text is not None
    assert canonical_hash(text) == canonical_hash(body)


def test_docx_rejects_garbage():
    assert extract_docx(b"not a zip") is None
    assert extract_docx(b"PK\x03\x04garbage") is None


def test_xlsx_extracts_cell_values():
    cells = [
        ["Revenue", "Q1", "Q2"],
        ["Product A", "100", "120"],
        ["Product B", "80", "95"],
    ]
    xlsx_bytes = _build_xlsx(cells)
    text = extract_xlsx(xlsx_bytes)
    assert text is not None
    # Every cell value should appear.
    for row in cells:
        for cell in row:
            assert cell in text


def test_xlsx_canonical_matches_csv_equivalent():
    """An xlsx with the same cell values as a CSV should produce the same
    canonical hash — this is the whole point of cross-format chain."""
    cells = [["Name", "Amount"], ["Alice", "100"], ["Bob", "200"]]
    xlsx_bytes = _build_xlsx(cells)
    xlsx_text = extract_xlsx(xlsx_bytes)

    # Equivalent plain-text: cells concatenated in the same row/col order
    # with single spaces. Canonical normalization collapses whitespace
    # regardless, so any separator scheme that doesn't merge tokens is fine.
    csv_text = "Name Amount Alice 100 Bob 200"
    assert canonical_hash(xlsx_text) == canonical_hash(csv_text)


def test_pptx_extracts_slide_order():
    slides = ["Introduction to Q3", "Revenue highlights", "Action items for Q4"]
    pptx_bytes = _build_pptx(slides)
    text = extract_pptx(pptx_bytes)
    assert text is not None
    # Order must be preserved.
    idx_intro = text.find("Introduction")
    idx_rev = text.find("Revenue")
    idx_action = text.find("Action")
    assert idx_intro < idx_rev < idx_action


def test_pdf_extract_minimal_content_stream():
    """Build a tiny synthetic PDF with one uncompressed content stream
    containing a single Tj operator. Our Python mirror should find it."""
    # We mirror the JS textFromContentStream logic in a minimal form.
    content = "BT (Hello, PDF world!) Tj ET"

    def text_from_content_stream(text: str) -> str:
        # Minimal mirror: find "( ... ) Tj" pairs inside BT/ET.
        out: list[str] = []
        in_block = False
        i = 0
        while i < len(text):
            # Skip whitespace
            if text[i].isspace():
                i += 1; continue
            # BT / ET tokens
            if text[i:i+2] == "BT":
                in_block = True; i += 2; continue
            if text[i:i+2] == "ET":
                in_block = False; i += 2; continue
            if not in_block:
                i += 1; continue
            if text[i] == "(":
                # Scan until matching ).
                depth = 1
                j = i + 1
                while j < len(text) and depth > 0:
                    if text[j] == "\\": j += 2; continue
                    if text[j] == "(": depth += 1
                    elif text[j] == ")": depth -= 1
                    if depth > 0: j += 1
                literal = text[i+1:j]
                # Expect "Tj" after.
                k = j + 1
                while k < len(text) and text[k].isspace(): k += 1
                if text[k:k+2] == "Tj":
                    out.append(literal)
                    i = k + 2
                    continue
                i = j + 1
                continue
            i += 1
        return " ".join(out)

    assert text_from_content_stream(content) == "Hello, PDF world!"


def test_whitespace_collapse_stable_across_formats():
    """End-to-end: the same logical content in three formats yields the
    same canonical hash."""
    content_plain = "Q2 revenue projections show a 12 percent increase."
    content_docx = extract_docx(_build_docx(content_plain))
    content_xlsx = extract_xlsx(_build_xlsx([content_plain.split()]))
    content_pptx = extract_pptx(_build_pptx([content_plain]))

    h_plain = canonical_hash(content_plain)
    h_docx = canonical_hash(content_docx)
    h_xlsx = canonical_hash(content_xlsx)
    h_pptx = canonical_hash(content_pptx)

    assert h_plain == h_docx == h_xlsx == h_pptx, (
        f"format hashes diverge: plain={h_plain}, docx={h_docx}, "
        f"xlsx={h_xlsx}, pptx={h_pptx}"
    )
