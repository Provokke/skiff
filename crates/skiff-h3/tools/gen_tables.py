"""Generate skiff-h3 tables from the RFC text files (RFC 9204 App. A, RFC 7541 App. B).

Usage: python gen_tables.py RFC9204.txt RFC7541.txt OUT_STATIC.rs OUT_HUFFMAN.rs
(the plain-text RFCs from https://www.rfc-editor.org/rfc/rfc9204.txt and
rfc7541.txt; outputs are src/qpack/static_table.rs and huffman_code.rs, then
run `cargo fmt`).
Validates: 99 static entries with indices 0..98; 257 Huffman codes, bits == hex,
len matches, Kraft sum exactly 1 (complete prefix code), no duplicates.
"""
import re
import sys
from fractions import Fraction


def static_table(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    start = next(i for i, l in enumerate(lines) if l.startswith("Appendix A.  Static Table"))
    end = next(i for i, l in enumerate(lines) if l.startswith("Appendix B."))
    rows = []
    for l in lines[start:end]:
        m = re.match(r"^   \| (\d*)\s*\| (.*?)\s*\| (.*?)\s*\|$", l)
        if not m:
            continue
        idx, name, value = m.group(1), m.group(2).strip(), m.group(3).strip()
        if idx:
            rows.append([int(idx), name, value])
        else:
            # Continuation of a wrapped value: the RFC breaks after '-' or '/'
            # inside a token, and after ';' between parameters (a space).
            assert not name, l
            prev = rows[-1][2]
            sep = "" if prev.endswith(("-", "/")) else " "
            rows[-1][2] = prev + sep + value
    assert [r[0] for r in rows] == list(range(99)), rows
    return rows


def huffman(path):
    text = open(path, encoding="utf-8").read()
    start = text.index("Appendix B.  Huffman Code")
    end = text.index("Appendix C.  Examples", start)
    codes = {}
    pat = re.compile(r"^\s+(?:'.'|EOS)?\s*\(\s*(\d+)\)\s+\|([01|]+)\s+([0-9a-f]+)\s+\[\s*(\d+)\]", re.M)
    for m in pat.finditer(text[start:end]):
        sym, bits, hx, ln = int(m.group(1)), m.group(2).replace("|", ""), int(m.group(3), 16), int(m.group(4))
        assert len(bits) == ln, m.group(0)
        assert int(bits, 2) == hx, m.group(0)
        assert sym not in codes
        codes[sym] = (hx, ln)
    assert sorted(codes) == list(range(257)), len(codes)
    assert sum(Fraction(1, 2 ** l) for _, l in codes.values()) == 1
    assert len({c for c in codes.values()}) == 257
    return [codes[i] for i in range(257)]


def rust_bytes(s):
    return 'b"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    rfc9204, rfc7541, out_static, out_huff = sys.argv[1:5]
    rows = static_table(rfc9204)
    with open(out_static, "w", newline="\n") as f:
        f.write("// @generated from RFC 9204 Appendix A by gen_tables.py; do not edit.\n\n")
        f.write("/// The QPACK static table (RFC 9204 Appendix A): `(name, value)` by index.\n")
        f.write("pub const STATIC_TABLE: [(&[u8], &[u8]); 99] = [\n")
        for i, n, v in rows:
            f.write(f"    ({rust_bytes(n)}, {rust_bytes(v)}), // {i}\n")
        f.write("];\n")
    codes = huffman(rfc7541)
    with open(out_huff, "w", newline="\n") as f:
        f.write("// @generated from RFC 7541 Appendix B by gen_tables.py; do not edit.\n\n")
        f.write("/// The HPACK/QPACK Huffman code (RFC 7541 Appendix B): `(code, bit length)`\n")
        f.write("/// by symbol, code aligned to the least significant bit; symbol 256 is EOS.\n")
        f.write("pub const CODES: [(u32, u8); 257] = [\n")
        for i, (c, l) in enumerate(codes):
            f.write(f"    (0x{c:x}, {l}), // {i}\n")
        f.write("];\n")
    print("static", len(rows), "huffman", len(codes))
    for r in rows:
        if r[0] in (30, 41, 52, 54, 57, 58, 85):
            print(r)


if __name__ == "__main__":
    main()
