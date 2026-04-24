// AIAuth canonical-text extractor — computes content_hash_canonical for
// file attestations so cross-format chain integrity (xlsx → csv → pdf)
// works without a desktop agent install.
//
// The canonical hash is SHA-256 of the extracted-and-normalized TEXT
// content of a file, independent of file format. Two files that contain
// the same words but in different formats (a Word doc and its PDF
// export, an Excel and its CSV) hash to the same canonical value.
//
// Supported formats in this file (all browser-native — no library deps):
//   - Plain text: .txt, .md, .csv, .tsv, .json, .xml, .html, .log, .yaml, .toml
//   - DOCX (Word): .docx — ZIP of word/document.xml
//   - XLSX (Excel): .xlsx — ZIP of xl/worksheets/*.xml + xl/sharedStrings.xml
//   - PPTX (PowerPoint): .pptx — ZIP of ppt/slides/slide*.xml
//
// PDF is handled in a sibling file, pdf_text.js, because its parsing
// machinery is large enough to warrant separation. All extractors
// normalize text identically (whitespace-collapse → trim → UTF-8 → SHA-256)
// so the resulting hash is stable regardless of which extractor ran.
//
// Graceful degradation contract: any extractor that hits an edge case
// or unsupported variant returns null. The caller (background.js
// enrichWithCanonicalText) emits the receipt WITHOUT content_hash_canonical
// in that case — no hash is always safer than a wrong hash.

/* global self */

const TEXT_MIME_PATTERNS = [
  /^text\//i,
  /^application\/json/i,
  /^application\/xml/i,
  /^application\/x-yaml/i,
  /^application\/toml/i,
];

const TEXT_EXTENSIONS = new Set([
  "txt", "md", "markdown", "csv", "tsv", "psv",
  "json", "jsonl", "ndjson",
  "xml", "html", "htm", "xhtml",
  "log", "yaml", "yml", "toml", "ini", "cfg", "conf",
  "py", "js", "mjs", "ts", "jsx", "tsx", "go", "rs", "java", "c", "cc", "cpp",
  "h", "hpp", "sh", "bash", "zsh", "rb", "php", "sql",
]);

function fileExtension(filename) {
  if (!filename) return "";
  const idx = filename.lastIndexOf(".");
  if (idx < 0 || idx === filename.length - 1) return "";
  return filename.slice(idx + 1).toLowerCase();
}

function looksLikePlainText(file, bytes) {
  if (!file) return false;
  const mime = (file.type || "").toLowerCase();
  if (TEXT_MIME_PATTERNS.some(rx => rx.test(mime))) return true;
  if (TEXT_EXTENSIONS.has(fileExtension(file.name))) return true;
  // Heuristic fallback for files with no extension + no MIME: if the
  // first kilobyte is mostly printable ASCII or valid UTF-8, treat as
  // text. Skip unless we have bytes already handy.
  if (bytes && bytes.length) {
    const sample = bytes.subarray(0, Math.min(1024, bytes.length));
    let printable = 0;
    for (let i = 0; i < sample.length; i++) {
      const b = sample[i];
      if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) printable++;
    }
    return printable / sample.length > 0.9;
  }
  return false;
}

// Canonical normalization — MUST stay identical to server.normalize_text
// (server.py:3263) and background.js:normalizeText. Breaking this
// invariant silently invalidates every cross-format receipt.
function normalize(s) {
  if (s == null) return "";
  return String(s).replace(/\s+/g, " ").trim();
}

async function sha256Hex(s) {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------
// ZIP reader — minimal, read-only, for Office Open XML files.
// Browser's DecompressionStream handles FlateDecode; we parse the ZIP
// central directory by hand. No external library required.
// ---------------------------------------------------------------------

function readU16LE(u8, p) { return u8[p] + (u8[p + 1] << 8); }
function readU32LE(u8, p) {
  return (u8[p] * 1 + u8[p + 1] * 0x100 + u8[p + 2] * 0x10000 + u8[p + 3] * 0x1000000) >>> 0;
}

/** Find the End-of-Central-Directory record at the tail of a ZIP.
 *  Returns its offset, or -1 if not found. */
function findEOCD(u8) {
  const sig = [0x50, 0x4B, 0x05, 0x06];
  const search = Math.max(0, u8.length - 65557);  // EOCD + max comment
  for (let p = u8.length - 22; p >= search; p--) {
    if (u8[p] === sig[0] && u8[p + 1] === sig[1]
     && u8[p + 2] === sig[2] && u8[p + 3] === sig[3]) {
      return p;
    }
  }
  return -1;
}

/** Parse a ZIP and return a map: entryName → {compressionMethod, offset,
 *  compressedSize, uncompressedSize}. Offset points at the local file
 *  header; we'll parse that when we read the entry. */
function parseZipCentralDir(u8) {
  const eocd = findEOCD(u8);
  if (eocd < 0) return null;
  const cdEntries = readU16LE(u8, eocd + 10);
  const cdOffset = readU32LE(u8, eocd + 16);

  const entries = new Map();
  let p = cdOffset;
  for (let i = 0; i < cdEntries && p + 46 <= u8.length; i++) {
    // Central directory signature 0x02014b50
    if (u8[p] !== 0x50 || u8[p + 1] !== 0x4B || u8[p + 2] !== 0x01 || u8[p + 3] !== 0x02) break;
    const method = readU16LE(u8, p + 10);
    const compSize = readU32LE(u8, p + 20);
    const uncompSize = readU32LE(u8, p + 24);
    const nameLen = readU16LE(u8, p + 28);
    const extraLen = readU16LE(u8, p + 30);
    const commentLen = readU16LE(u8, p + 32);
    const localHeaderOff = readU32LE(u8, p + 42);
    const name = new TextDecoder("utf-8", { fatal: false })
      .decode(u8.subarray(p + 46, p + 46 + nameLen));
    entries.set(name, {
      method, compSize, uncompSize, localHeaderOff,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

async function readZipEntry(u8, entry) {
  // Local file header: 30 bytes fixed + filename + extra, then payload.
  const h = entry.localHeaderOff;
  if (h + 30 > u8.length) return null;
  if (u8[h] !== 0x50 || u8[h + 1] !== 0x4B || u8[h + 2] !== 0x03 || u8[h + 3] !== 0x04) return null;
  const nameLen = readU16LE(u8, h + 26);
  const extraLen = readU16LE(u8, h + 28);
  const dataStart = h + 30 + nameLen + extraLen;
  const compBytes = u8.subarray(dataStart, dataStart + entry.compSize);

  if (entry.method === 0) {
    // Stored / uncompressed.
    return new TextDecoder("utf-8", { fatal: false }).decode(compBytes);
  }
  if (entry.method === 8) {
    // Deflate — use DecompressionStream ("deflate-raw" for raw DEFLATE
    // without zlib header, which is how ZIP stores it).
    try {
      const stream = new Blob([compBytes]).stream().pipeThrough(
        new DecompressionStream("deflate-raw")
      );
      const resp = new Response(stream);
      const out = await resp.arrayBuffer();
      return new TextDecoder("utf-8", { fatal: false }).decode(out);
    } catch (e) {
      return null;
    }
  }
  return null;  // Unsupported compression method.
}

// ---------------------------------------------------------------------
// XML helpers — browsers have DOMParser natively.
// ---------------------------------------------------------------------

function parseXML(xmlString) {
  try {
    const doc = new DOMParser().parseFromString(xmlString, "application/xml");
    if (doc.getElementsByTagName("parsererror").length) return null;
    return doc;
  } catch (e) {
    return null;
  }
}

/** Return concatenated text-content of every element whose local name
 *  (ignoring namespace prefix) matches any in `tagNames`. Preserves
 *  document order — that's critical for text reconstruction. */
function extractTagTexts(doc, tagNames) {
  const tagSet = new Set(tagNames);
  const out = [];
  const walk = (node) => {
    if (node.nodeType === 1) {
      const local = node.localName || node.nodeName.split(":").pop();
      if (tagSet.has(local)) {
        out.push(node.textContent || "");
      }
    }
    for (let child = node.firstChild; child; child = child.nextSibling) {
      walk(child);
    }
  };
  walk(doc.documentElement);
  return out;
}

// ---------------------------------------------------------------------
// Format-specific extractors. Each returns a single canonical string
// (pre-normalization), or null if it can't decode.
// ---------------------------------------------------------------------

async function extractDocx(bytes) {
  const entries = parseZipCentralDir(bytes);
  if (!entries || !entries.has("word/document.xml")) return null;
  const xml = await readZipEntry(bytes, entries.get("word/document.xml"));
  if (!xml) return null;
  const doc = parseXML(xml);
  if (!doc) return null;
  // <w:t> carries every run of visible text. <w:tab> and <w:br> mark
  // whitespace boundaries — we insert a space so words don't glue.
  const parts = [];
  const walk = (node) => {
    if (node.nodeType === 1) {
      const local = node.localName || node.nodeName.split(":").pop();
      if (local === "t") {
        parts.push(node.textContent || "");
      } else if (local === "tab" || local === "br" || local === "p") {
        parts.push(" ");
      }
    }
    for (let child = node.firstChild; child; child = child.nextSibling) {
      walk(child);
    }
  };
  walk(doc.documentElement);
  return parts.join(" ");
}

async function extractPptx(bytes) {
  const entries = parseZipCentralDir(bytes);
  if (!entries) return null;
  // Enumerate slides in numeric order so reconstruction is stable.
  const slidePaths = [];
  for (const name of entries.keys()) {
    const m = name.match(/^ppt\/slides\/slide(\d+)\.xml$/);
    if (m) slidePaths.push({ name, n: parseInt(m[1], 10) });
  }
  if (!slidePaths.length) return null;
  slidePaths.sort((a, b) => a.n - b.n);

  const out = [];
  for (const s of slidePaths) {
    const xml = await readZipEntry(bytes, entries.get(s.name));
    if (!xml) continue;
    const doc = parseXML(xml);
    if (!doc) continue;
    // <a:t> carries text inside <a:r> runs. <a:p> boundaries.
    const parts = [];
    const walk = (node) => {
      if (node.nodeType === 1) {
        const local = node.localName || node.nodeName.split(":").pop();
        if (local === "t") parts.push(node.textContent || "");
        else if (local === "p") parts.push(" ");
      }
      for (let child = node.firstChild; child; child = child.nextSibling) {
        walk(child);
      }
    };
    walk(doc.documentElement);
    out.push(parts.join(" "));
  }
  return out.join(" ");
}

async function extractXlsx(bytes) {
  const entries = parseZipCentralDir(bytes);
  if (!entries) return null;

  // sharedStrings.xml is optional (not present if the workbook has no
  // repeated strings). When present it holds every unique string,
  // referenced by index from cells via <c t="s"><v>INDEX</v></c>.
  let shared = [];
  if (entries.has("xl/sharedStrings.xml")) {
    const xml = await readZipEntry(bytes, entries.get("xl/sharedStrings.xml"));
    if (xml) {
      const doc = parseXML(xml);
      if (doc) {
        const siNodes = doc.getElementsByTagNameNS("*", "si");
        for (let i = 0; i < siNodes.length; i++) {
          // <si> can contain <t>text</t> OR <r><t>runtext</t></r><r>...
          // textContent concatenates children, which gives us the full
          // string regardless of structure.
          shared.push((siNodes[i].textContent || "").replace(/\s+/g, " "));
        }
      }
    }
  }

  // Enumerate sheets numerically.
  const sheetPaths = [];
  for (const name of entries.keys()) {
    const m = name.match(/^xl\/worksheets\/sheet(\d+)\.xml$/);
    if (m) sheetPaths.push({ name, n: parseInt(m[1], 10) });
  }
  if (!sheetPaths.length) return null;
  sheetPaths.sort((a, b) => a.n - b.n);

  const out = [];
  for (const s of sheetPaths) {
    const xml = await readZipEntry(bytes, entries.get(s.name));
    if (!xml) continue;
    const doc = parseXML(xml);
    if (!doc) continue;
    // Iterate every <c> cell. Type attribute determines how to read the
    // value:
    //   (no t) or t="n" → <v> is a number literal
    //   t="s"           → <v> is a shared-strings index
    //   t="str" or "inlineStr" → <is><t> inline text
    //   t="b"           → boolean 0/1
    // We concatenate value-by-value; row/column structure doesn't affect
    // the canonical text content.
    const cells = doc.getElementsByTagNameNS("*", "c");
    const parts = [];
    for (let i = 0; i < cells.length; i++) {
      const c = cells[i];
      const t = c.getAttribute("t");
      if (t === "s") {
        const v = c.getElementsByTagNameNS("*", "v")[0];
        if (v) {
          const idx = parseInt(v.textContent || "", 10);
          if (!isNaN(idx) && idx >= 0 && idx < shared.length) {
            parts.push(shared[idx]);
          }
        }
      } else if (t === "inlineStr" || t === "str") {
        const is = c.getElementsByTagNameNS("*", "is")[0];
        if (is) parts.push(is.textContent || "");
        else parts.push(c.textContent || "");
      } else {
        // Number, boolean, date — read the <v> verbatim.
        const v = c.getElementsByTagNameNS("*", "v")[0];
        if (v) parts.push(v.textContent || "");
      }
    }
    out.push(parts.join(" "));
  }
  return out.join(" ");
}

async function extractPlainText(bytes) {
  // Try UTF-8 first; fall back to latin-1 if invalid.
  try {
    const s = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return s;
  } catch (e) {
    return new TextDecoder("latin1", { fatal: false }).decode(bytes);
  }
}

// ---------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------

/** Compute content_hash_canonical for a file. Returns the lowercase-hex
 *  SHA-256 string, or null if the file type isn't supported or the
 *  extractor fails. Callers treat null as "no canonical hash available"
 *  and emit the receipt without this optional field. */
async function computeCanonicalHash(file, bytes) {
  if (!bytes || !file) return null;
  const ext = fileExtension(file.name);

  let text = null;
  try {
    if (ext === "docx") {
      text = await extractDocx(bytes);
    } else if (ext === "xlsx" || ext === "xlsm") {
      text = await extractXlsx(bytes);
    } else if (ext === "pptx") {
      text = await extractPptx(bytes);
    } else if (ext === "pdf") {
      // PDF handled by sibling module if loaded.
      if (self.AIAuthPDF && typeof self.AIAuthPDF.extractPdfText === "function") {
        text = await self.AIAuthPDF.extractPdfText(bytes);
      }
    } else if (looksLikePlainText(file, bytes)) {
      text = await extractPlainText(bytes);
    }
  } catch (e) {
    // Any extractor error → null result. The caller skips canonical-hash
    // inclusion. The signature is still valid via output_hash; we just
    // can't participate in cross-format chain tracking.
    return null;
  }

  if (text == null) return null;
  const canonical = normalize(text);
  if (!canonical) return null;
  return sha256Hex(canonical);
}

self.AIAuthCanonical = {
  computeCanonicalHash,
  // Exported for tests + mirror-verification.
  normalize,
  extractDocx,
  extractXlsx,
  extractPptx,
  extractPlainText,
  parseZipCentralDir,
  readZipEntry,
  fileExtension,
  looksLikePlainText,
};
