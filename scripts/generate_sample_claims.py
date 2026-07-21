"""generate_sample_claims.py — synthetic insurance-claim email generator.

Produces a handful of realistic, entirely synthetic .eml files covering the
scenarios ImaniIA's pipeline is designed to handle: a clean minor claim, a
severe claim, a claim missing required fields, and a staged/fraudulent
claim. Each includes a small synthetic "damage photo" (a plain PNG drawn
with PIL — no real photo, no personal data) so the CV/vision extraction
steps have something to run against.

No live services required. Safe to commit and share publicly — every name,
policy number, and address below is made up.

Usage:
    python scripts/generate_sample_claims.py
    # writes .eml files + PNGs into data/samples/synthetic_claims/
"""
from __future__ import annotations

import io
import os
from email.message import EmailMessage
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "samples" / "synthetic_claims"


def _make_damage_photo(label: str, color: tuple[int, int, int]) -> bytes:
    """Tiny synthetic 'damage photo' — a colored rectangle with a caption.
    Not a real photo; just enough for the pipeline's image-handling paths
    (OCR, CV damage model, vision LLM) to have something to process."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (480, 320), color=(235, 235, 235))
    draw = ImageDraw.Draw(img)
    draw.rectangle([40, 60, 440, 260], outline=(60, 60, 60), width=3)
    draw.rectangle([160, 120, 320, 200], fill=color)
    draw.text((50, 20), f"SYNTHETIC SAMPLE — {label}", fill=(20, 20, 20))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _build_eml(
    sender: str,
    subject: str,
    body: str,
    photo_bytes: bytes | None = None,
    photo_name: str = "damage_photo.png",
) -> bytes:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "claims@imania-claims.example"
    msg["Subject"] = subject
    msg.set_content(body)
    if photo_bytes:
        msg.add_attachment(photo_bytes, maintype="image", subtype="png", filename=photo_name)
    return msg.as_bytes()


SCENARIOS = [
    {
        "filename": "01_legitimate_minor_claim.eml",
        "sender": "sana.trabelsi@example.com",
        "subject": "Claim — minor dent, policy AUTO-1120",
        "body": (
            "Bonjour,\n\n"
            "Je m'appelle Sana Trabelsi, numero de police AUTO-1120 (assurance auto). "
            "J'ai un petit bosse sur la portiere avant droite suite a un accrochage "
            "sur un parking hier. Voici une photo. Merci de me dire les prochaines etapes.\n\n"
            "Cordialement,\nSana"
        ),
        "photo_label": "minor dent",
        "photo_color": (200, 60, 60),
    },
    {
        "filename": "02_legitimate_severe_claim.eml",
        "sender": "karim.belhadj@example.com",
        "subject": "Accident report — policy AUTO-4471, rear-end collision",
        "body": (
            "Hello,\n\n"
            "My name is Karim Belhadj, policy number AUTO-4471. My car was hit from "
            "behind on March 12th — the rear panel is badly damaged and the vehicle "
            "may not be driveable. Photos attached along with the amicable accident "
            "report. Please advise on next steps and whether I need a rental car.\n\n"
            "Best,\nKarim"
        ),
        "photo_label": "severe rear damage",
        "photo_color": (120, 20, 20),
    },
    {
        "filename": "03_missing_information_claim.eml",
        "sender": "unknown.claimant@example.com",
        "subject": "my car",
        "body": (
            "hi i need to file a claim my car got damaged please help me out asap "
            "i dont have my policy number with me right now will send later"
        ),
        "photo_label": None,
        "photo_color": None,
    },
    {
        "filename": "04_suspicious_staged_claim.eml",
        "sender": "claimant@secure-imania-payout.example",
        "subject": "URGENT — total loss, settle in 24h to new IBAN",
        "body": (
            "My car was rear-ended, total loss, please settle in 24h to this new "
            "IBAN: TN59 0000 0000 0000 0000 0000. Policy POL-9981. I need this "
            "resolved immediately or I will involve a lawyer."
        ),
        "photo_label": "no visible damage",
        "photo_color": (235, 235, 235),
    },
]


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    written = []
    for scenario in SCENARIOS:
        photo_bytes = None
        if scenario["photo_label"]:
            photo_bytes = _make_damage_photo(scenario["photo_label"], scenario["photo_color"])
        raw = _build_eml(
            sender=scenario["sender"],
            subject=scenario["subject"],
            body=scenario["body"],
            photo_bytes=photo_bytes,
        )
        out_path = OUT_DIR / scenario["filename"]
        out_path.write_bytes(raw)
        written.append(out_path)

    print(f"Wrote {len(written)} synthetic claim emails to {OUT_DIR}:")
    for p in written:
        print(f"  - {p.name}")
    print(
        "\nThese are standalone .eml files — feed one through the real ingestion "
        "parser to see it work without needing a live IMAP inbox, e.g.:\n"
        "  python -c \"import sys; sys.path.insert(0,'src'); from email_extraction "
        "import EmailIngestion; raw=open('data/samples/synthetic_claims/"
        "01_legitimate_minor_claim.eml','rb').read(); "
        "ing=EmailIngestion(host='unused', user='unused', password='unused'); "
        "print(ing.parse_email(raw)['status'])\""
    )


if __name__ == "__main__":
    main()
