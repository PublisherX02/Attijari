"""test_extraction_qrcode_phishing.py — "quishing" (QR-code phishing) is a
real and growing vector precisely because the malicious URL never exists
as literal text anywhere in the email: it's only pixels inside an embedded
image, invisible to masked_link_mismatch, hidden_url_phishing_tactic,
feed_malicious_url, and every other text/URL-based check this pipeline
otherwise has. Uses OpenCV's built-in QRCodeDetector (already an installed
dependency here) rather than pyzbar, avoiding a new system libzbar
dependency this project doesn't otherwise need. Runs locally, same
established pattern as Tesseract OCR (not routed through the Docker
sandbox -- both are read-only image decoding, not attacker-controlled-
format parsing of the riskier kind oletools/pdfid/py7zr do).

Real QR test images are generated with OpenCV's own QRCodeEncoder rather
than a hand-rolled bitmap -- keeps the test honest (decoding a real,
structurally valid QR code) without adding a new dependency just for
tests.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import cv2
import extraction


def _make_qr_png(data: str) -> bytes:
    encoder = cv2.QRCodeEncoder.create()
    qr_img = encoder.encode(data)
    success, png_bytes = cv2.imencode(".png", qr_img)
    assert success
    return png_bytes.tobytes()


def test_decodes_real_qr_code_url():
    content = _make_qr_png("http://totally-legit-paypal.security-verify.tk/login")
    result = extraction._local_qrcode(content)
    assert result["status"] == "ok"
    assert "http://totally-legit-paypal.security-verify.tk/login" in result["urls"]


def test_qr_decode_survives_tight_crop_with_no_quiet_zone():
    # OpenCV's own bare encoder output (no margin at all) is exactly this
    # case -- confirmed during development that decoding fails at native
    # resolution without the fallback upscale/border retry.
    content = _make_qr_png("http://evil-lookalike.tk/x")
    result = extraction._local_qrcode(content)
    assert result["status"] == "ok"
    assert "http://evil-lookalike.tk/x" in result["urls"]


def test_non_qr_image_returns_empty_not_error():
    import numpy as np
    photo = (np.random.rand(200, 200, 3) * 255).astype("uint8")
    _, photo_bytes = cv2.imencode(".png", photo)
    result = extraction._local_qrcode(photo_bytes.tobytes())
    assert result["status"] == "ok"
    assert result["urls"] == []


def test_corrupt_image_bytes_does_not_crash():
    result = extraction._local_qrcode(b"not a real image at all")
    assert result["status"] == "ok"
    assert result["urls"] == []


def test_extract_attachment_flags_qr_decoded_url_and_feeds_ioc_extraction(tmp_path):
    content = _make_qr_png("http://totally-legit-paypal.security-verify.tk/login")
    f = tmp_path / "scan_document.png"
    f.write_bytes(content)
    att = {"stored_path": str(f), "original_name": "scan_document.png",
           "declared_type": "image/png", "real_type": None, "sha256": "a" * 64}
    res = extraction.extract_attachment(att)
    assert any("qr_code_url_found" in fl for fl in res["flags"])
    assert any("totally-legit-paypal.security-verify.tk" in fl for fl in res["flags"])
    # The decoded URL is fed into text_parts -> IOC extraction, so it gets
    # the same threat-feed/domain checks any other body URL would.
    assert "http://totally-legit-paypal.security-verify.tk/login" in res.get("extracted_text", "")
