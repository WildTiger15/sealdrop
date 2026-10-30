"""Draw README charts (SVG, no dependencies) from target/criterion medians.

Run from the repo root:  python -I scripts/make_charts.py
Writes docs/images/bench-primitives.svg and docs/images/bench-files.svg.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
CRIT = ROOT / "target" / "criterion"
IMG = ROOT / "docs" / "images"

PQ, CLASSIC = "#3b6fd4", "#9aa3ad"  # one accent, one neutral; readable on light and dark
TEXT = "#6b7280"                    # mid gray works on GitHub's light and dark themes


def median_ns(*parts):
    est = json.loads((CRIT.joinpath(*map(str, parts)) / "new" / "estimates.json").read_text())
    return est["median"]["point_estimate"]


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;")


def paired_bars(title, unit, rows, legend, path, fmt):
    """rows: [(label, value_a, value_b)] drawn as two horizontal bars per row."""
    w, left, right, top, row_h, bar_h = 760, 170, 110, 56, 46, 15
    h = top + row_h * len(rows) + 20
    vmax = max(max(a, b) for _, a, b in rows)
    scale = (w - left - right) / vmax
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
           f'font-family="system-ui,-apple-system,Segoe UI,sans-serif" font-size="13">',
           f'<text x="0" y="20" font-size="15" font-weight="600" fill="{TEXT}">{esc(title)}</text>']
    lx = 0
    for name, color in zip(legend, (PQ, CLASSIC)):
        out.append(f'<rect x="{lx}" y="32" width="11" height="11" rx="2" fill="{color}"/>'
                   f'<text x="{lx + 16}" y="42" fill="{TEXT}">{esc(name)}</text>')
        lx += 22 + 7.5 * len(name)
    out.append(f'<text x="{w}" y="42" text-anchor="end" fill="{TEXT}">{esc(unit)}</text>')
    for i, (label, a, b) in enumerate(rows):
        y = top + i * row_h
        out.append(f'<text x="{left - 10}" y="{y + bar_h + 4}" text-anchor="end" fill="{TEXT}">{esc(label)}</text>')
        for j, (v, color) in enumerate(((a, PQ), (b, CLASSIC))):
            yy = y + j * (bar_h + 3)
            bw = max(2, v * scale)
            out.append(f'<rect x="{left}" y="{yy}" width="{bw:.1f}" height="{bar_h}" rx="3" fill="{color}"/>'
                       f'<text x="{left + bw + 6:.1f}" y="{yy + 12}" fill="{TEXT}">{fmt(v)}</text>')
    out.append("</svg>")
    path.write_text("\n".join(out), encoding="utf-8")
    print("wrote", path.relative_to(ROOT))


us = lambda ns: ns / 1e3
paired_bars(
    "Post quantum vs classic primitives (median time, lower is better)",
    "microseconds",
    [
        ("KEM keygen", us(median_ns("kem", "xwing_keygen")), us(median_ns("kem", "x25519_keygen"))),
        ("KEM encapsulate", us(median_ns("kem", "xwing_encapsulate")), us(median_ns("kem", "x25519_encapsulate"))),
        ("KEM decapsulate", us(median_ns("kem", "xwing_decapsulate")), us(median_ns("kem", "x25519_decapsulate"))),
        ("Sign", us(median_ns("sig", "mldsa65_sign")), us(median_ns("sig", "ed25519_sign"))),
        ("Verify", us(median_ns("sig", "mldsa65_verify")), us(median_ns("sig", "ed25519_verify"))),
    ],
    ["X-Wing / ML-DSA-65", "X25519 / Ed25519"],
    IMG / "bench-primitives.svg",
    lambda v: f"{v:,.0f} µs",
)

mib_s = lambda size, ns: size / (1 << 20) / (ns / 1e9)
rows = []
for size, label in [(65536, "64 KiB file"), (1048576, "1 MiB file"), (16777216, "16 MiB file")]:
    rows.append((label, mib_s(size, median_ns("file", "sealdrop_seal", size)),
                 mib_s(size, median_ns("file", "classic_x25519_ed25519_seal", size))))
paired_bars(
    "Encrypt + sign a file (median throughput, higher is better)",
    "MiB/s",
    rows,
    ["SealDrop (X-Wing + ML-DSA-65)", "Same format, X25519 + Ed25519"],
    IMG / "bench-files.svg",
    lambda v: f"{v:,.0f} MiB/s",
)
