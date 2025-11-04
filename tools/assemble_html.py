#!/usr/bin/env python3
"""
Inline the client CSS and JS into a single HTML file.
Keep it tiny and purpose-built for the current project layout.
"""

from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "assets"
HTML_IN = ASSETS_DIR / "client.html"
CSS_FILE = ASSETS_DIR / "client.css"
HTML_OUT = ASSETS_DIR / "client_assembled.html"

CSS_TAG = '<link rel="stylesheet" href="client.css">'
QR_TAG = '<script src="qrcode.js"></script>'
CLIENT_TAG = '<script src="client.js"></script>'


def read_text(path: Path) -> str:
    if not path.is_file():
        sys.exit(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def prefer_min_js(stem: str) -> Path:
    """Return the minified JS if it exists, otherwise the regular version."""
    min_path = ASSETS_DIR / f"{stem}.min.js"
    if min_path.is_file():
        return min_path
    return ASSETS_DIR / f"{stem}.js"


def main() -> None:
    html = read_text(HTML_IN)
    css = read_text(CSS_FILE)
    qr = read_text(prefer_min_js("qrcode"))
    client = read_text(prefer_min_js("client"))

    for tag in (CSS_TAG, QR_TAG, CLIENT_TAG):
        if tag not in html:
            sys.exit(f"expected '{tag}' in {HTML_IN}")

    html = html.replace(CSS_TAG, f"<style>\n{css.rstrip()}\n</style>", 1)

    bundle = (
        "<script>(function(){\n"
        f"{qr.rstrip()}\n"
        'if (typeof globalThis !== "undefined" && typeof QRCode !== "undefined") { globalThis.QRCode = QRCode; }\n'
        f"{client.rstrip()}\n"
        "})();</script>"
    )

    html = html.replace(QR_TAG, bundle, 1)
    html = html.replace(CLIENT_TAG, "", 1)

    HTML_OUT.write_text(html, encoding="utf-8")
    print(f"Wrote {HTML_OUT}")


if __name__ == "__main__":
    main()
