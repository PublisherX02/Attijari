"""Sandboxed OCR text extraction via Tesseract."""
import json
import sys

try:
    import pytesseract
    from PIL import Image

    img = Image.open("/work/input")
    text = pytesseract.image_to_string(img, lang="fra+eng+ara")
    json.dump({
        "tool": "tesseract",
        "status": "ok",
        "text": text[:5000],
        "text_length": len(text),
    }, sys.stdout)
except Exception as e:
    json.dump({"tool": "tesseract", "status": "error", "error": str(e)}, sys.stdout)
