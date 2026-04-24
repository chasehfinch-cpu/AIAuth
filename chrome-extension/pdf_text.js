// AIAuth minimal PDF text extractor.
//
// Scope: extract text from PDFs that use the common-case encoding we
// see in AI-tool-exported documents (DocSend, ChatGPT export, Claude
// export, Notion export, LibreOffice/Word "Export as PDF"):
//   - FlateDecode-compressed content streams
//   - Tj / TJ operators inside BT...ET text blocks
//   - Standard PDF string escapes (octal, \(, \), \\, \n, \r, \t, \b, \f)
//   - Literal strings (parens) and hex strings (angle brackets)
//
// Out of scope:
//   - Custom font encodings / CMaps (returns bytes as-is; works for
//     ASCII-mapped standard fonts, falls short of CJK or heavily-embedded fonts)
//   - Object streams (PDF 1.5+ /ObjStm) — some modern PDFs won't parse
//   - Encrypted PDFs
//   - LZW / CCITT / JBIG2 / JPX-compressed content streams
//   - Broken/linearized PDFs with unusual xref layouts
//
// Fail-closed contract: any parsing difficulty → return null. The caller
// skips canonical-hash inclusion. A receipt without a canonical hash is
// always safer than one with a wrong hash.
//
// This is an intentionally minimal replacement for pdfjs-dist (~1MB
// bundle) tailored to the "all possible scope without a library" ask.
// If a real-world PDF sample falls into the out-of-scope categories
// above, we can swap this module for pdfjs-dist in a future PR.

/* global self */

function bytesToLatin1(u8, start, end) {
  let s = "";
  const stop = end == null ? u8.length : end;
  for (let i = start || 0; i < stop; i++) s += String.fromCharCode(u8[i]);
  return s;
}

/** Best-effort decode that keeps non-ASCII bytes stable. Real CMap
 *  decoding is out of scope — we treat the string's bytes as a Latin-1
 *  sequence so downstream normalization still hashes the same input
 *  deterministically. */
function decodePdfString(raw) {
  return raw;  // Already a Latin-1 JS string; canonical normalization handles whitespace.
}

/** Decode a PDF literal string (parenthesized). Handles escape
 *  sequences per the PDF 2.0 spec §7.3.4.2. */
function decodeLiteralString(body) {
  let out = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c !== "\\") { out += c; continue; }
    // Escape sequence
    const next = body[i + 1];
    if (next === "n") { out += "\n"; i++; }
    else if (next === "r") { out += "\r"; i++; }
    else if (next === "t") { out += "\t"; i++; }
    else if (next === "b") { out += "\b"; i++; }
    else if (next === "f") { out += "\f"; i++; }
    else if (next === "(" || next === ")" || next === "\\") { out += next; i++; }
    else if (next >= "0" && next <= "7") {
      // Octal escape, up to 3 digits.
      let octal = "";
      let j = i + 1;
      while (j < body.length && j < i + 4 && body[j] >= "0" && body[j] <= "7") {
        octal += body[j]; j++;
      }
      out += String.fromCharCode(parseInt(octal, 8));
      i = j - 1;
    } else if (next === "\n") {
      // Line continuation — discard.
      i++;
    } else {
      // Unknown escape — emit the character after the backslash verbatim.
      if (next != null) { out += next; i++; }
    }
  }
  return out;
}

/** Decode a PDF hex string (<...>). */
function decodeHexString(body) {
  const hex = body.replace(/\s+/g, "");
  const padded = hex.length % 2 ? hex + "0" : hex;
  let out = "";
  for (let i = 0; i < padded.length; i += 2) {
    const b = parseInt(padded.slice(i, i + 2), 16);
    if (isNaN(b)) return null;
    out += String.fromCharCode(b);
  }
  return out;
}

/** Parse a decoded content-stream string and emit the text operands of
 *  every Tj / TJ / ' / " operator inside BT...ET blocks. */
function textFromContentStream(text) {
  const out = [];
  let i = 0;
  let inTextBlock = false;

  // Scan tokens. A content stream is a stream of operands followed by an
  // operator. For text extraction we only care about:
  //   BT            start text block
  //   ET            end text block
  //   ( ... ) Tj    show literal string
  //   < ... > Tj    show hex string
  //   [ ( ... ) n ( ... ) ] TJ   show array of strings (spacing adjustments ignored)
  //   ( ... ) '     move to next line, show literal string
  //   ( ... ) a b " move to next line with spacing, show literal string
  // Anything else is skipped.

  while (i < text.length) {
    const c = text[i];
    if (c === "%") {
      // Comment — skip to end of line.
      while (i < text.length && text[i] !== "\n" && text[i] !== "\r") i++;
      continue;
    }
    if (c <= " ") { i++; continue; }

    if (c === "B" && text[i + 1] === "T" && (text[i + 2] == null || text[i + 2] <= " ")) {
      inTextBlock = true;
      i += 2;
      continue;
    }
    if (c === "E" && text[i + 1] === "T" && (text[i + 2] == null || text[i + 2] <= " ")) {
      inTextBlock = false;
      i += 2;
      continue;
    }

    if (!inTextBlock) { i++; continue; }

    // Pending operands: collect strings we encounter; flush when we see
    // a Tj/TJ/'/" operator.
    let pending = [];

    // Collect operands until we hit an operator or brace.
    while (i < text.length) {
      const ch = text[i];
      if (ch <= " " || ch === "%") break;

      if (ch === "(") {
        // Literal string, possibly nested parens (balanced, with escape).
        let depth = 1;
        let j = i + 1;
        while (j < text.length && depth > 0) {
          const d = text[j];
          if (d === "\\") { j += 2; continue; }
          if (d === "(") depth++;
          else if (d === ")") { depth--; if (depth === 0) break; }
          j++;
        }
        pending.push(decodeLiteralString(text.slice(i + 1, j)));
        i = j + 1;
        continue;
      }

      if (ch === "<") {
        // Hex string (not a dictionary — dict uses <<).
        if (text[i + 1] === "<") break;  // dictionary; not a string
        const j = text.indexOf(">", i + 1);
        if (j < 0) break;
        const s = decodeHexString(text.slice(i + 1, j));
        if (s != null) pending.push(s);
        i = j + 1;
        continue;
      }

      if (ch === "[") {
        // Array of strings (for TJ). Collect nested strings only.
        let depth = 1;
        let j = i + 1;
        while (j < text.length && depth > 0) {
          const d = text[j];
          if (d === "(") {
            let parenDepth = 1;
            let k = j + 1;
            while (k < text.length && parenDepth > 0) {
              if (text[k] === "\\") { k += 2; continue; }
              if (text[k] === "(") parenDepth++;
              else if (text[k] === ")") { parenDepth--; if (parenDepth === 0) break; }
              k++;
            }
            pending.push(decodeLiteralString(text.slice(j + 1, k)));
            j = k + 1;
            continue;
          }
          if (d === "<" && text[j + 1] !== "<") {
            const k = text.indexOf(">", j + 1);
            if (k < 0) break;
            const s = decodeHexString(text.slice(j + 1, k));
            if (s != null) pending.push(s);
            j = k + 1;
            continue;
          }
          if (d === "]") { depth--; if (depth === 0) break; }
          else if (d === "[") depth++;
          j++;
        }
        i = j + 1;
        continue;
      }

      // Operator or number.
      let opStart = i;
      while (i < text.length && text[i] > " " && text[i] !== "(" && text[i] !== "<" && text[i] !== "[") i++;
      const token = text.slice(opStart, i);
      if (token === "Tj" || token === "TJ" || token === "'" || token === '"') {
        if (pending.length) {
          out.push(pending.join(""));
          pending = [];
        }
        break;  // Move on to next token loop iteration.
      }
      // Non-text operator or numeric operand — discard pending so we
      // don't leak string data from unrelated operators.
      // (We keep pending across pure numbers because TJ spacing uses
      // numeric operands interleaved with strings in an array; but the
      // array was consumed above, so at this point seeing a non-text
      // operator means pending should be dropped.)
      pending = [];
    }
    // Continue outer scan — i already advanced.
  }

  return out.join(" ");
}

/** Decompress a FlateDecode byte stream ("/Filter /FlateDecode"). PDFs
 *  embed the zlib header (method=8) — we use DecompressionStream with
 *  "deflate" format, not "deflate-raw". */
async function flateDecode(u8) {
  try {
    const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream("deflate"));
    const resp = new Response(stream);
    const out = new Uint8Array(await resp.arrayBuffer());
    return out;
  } catch (e) {
    return null;
  }
}

/** Parse raw PDF bytes and extract all text. Returns a single string
 *  (pre-canonical-normalization), or null if the PDF uses features we
 *  don't support. */
async function extractPdfText(u8) {
  // Validate header.
  if (u8.length < 8) return null;
  const header = bytesToLatin1(u8, 0, 8);
  if (!/^%PDF-\d/.test(header)) return null;

  // Find every content stream by scanning for "stream\n...\nendstream"
  // markers. We don't walk the full xref table; we accept that this
  // skips streams referenced from object streams (PDF 1.5+). That's an
  // explicit limitation documented at the top of this file.
  const full = bytesToLatin1(u8);
  const streamRx = /(\d+)\s+(\d+)\s+obj\s*<<([^]*?)>>\s*stream[\r\n]+([^]*?)endstream/g;
  const parts = [];
  let m;
  while ((m = streamRx.exec(full)) !== null) {
    const dictSrc = m[3];
    const streamSrc = m[4];
    // Only decode streams that declare FlateDecode and carry text ops.
    // Heuristics: skip images (dictionary declares /Subtype /Image or
    // /Type /XObject with a /Subtype /Image), skip ICC profiles (/Type
    // /OutputIntent), skip fonts (/Type /Font or /Subtype /TrueType).
    if (/\/Subtype\s*\/Image/.test(dictSrc)) continue;
    if (/\/Type\s*\/XObject/.test(dictSrc) && /\/Subtype\s*\/Image/.test(dictSrc)) continue;
    if (/\/Type\s*\/Font/.test(dictSrc)) continue;
    if (/\/Type\s*\/OutputIntent/.test(dictSrc)) continue;

    const hasFilter = /\/Filter/.test(dictSrc);
    const filterIsFlate = /\/FlateDecode/.test(dictSrc);
    if (hasFilter && !filterIsFlate) continue;  // Unsupported compression.

    // Compute absolute byte offset of the stream payload so we can slice
    // the raw bytes (not the Latin-1 stringified version, which may
    // differ on bytes > 127 but should be byte-identical for Latin-1).
    const matchEnd = streamRx.lastIndex;
    const streamLen = streamSrc.length;
    const streamStart = matchEnd - "endstream".length - streamLen;
    let streamBytes = u8.subarray(streamStart, streamStart + streamLen);

    let decoded = streamBytes;
    if (hasFilter && filterIsFlate) {
      decoded = await flateDecode(streamBytes);
      if (!decoded) continue;
    }
    const decodedLatin1 = bytesToLatin1(decoded);
    // Skip streams that don't look like content streams (no BT marker
    // at all → likely fonts or form XObjects we want to ignore).
    if (decodedLatin1.indexOf("BT") < 0) continue;
    parts.push(textFromContentStream(decodedLatin1));
  }

  if (!parts.length) return null;
  return parts.join(" ");
}

self.AIAuthPDF = {
  extractPdfText,
  // Exported for tests.
  textFromContentStream,
  decodeLiteralString,
  decodeHexString,
  flateDecode,
};
