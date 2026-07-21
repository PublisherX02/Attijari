import base64
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import extraction

# 1x1 transparent PNG — real, valid image bytes so PIL.Image.open succeeds.
_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def test_local_cv_damage_unavailable_when_no_model_configured(monkeypatch):
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", None)
    result = extraction._local_cv_damage(b"fake image bytes")
    assert result == {"tool": "cv_damage", "status": "unavailable"}


def test_local_cv_damage_returns_severity_on_detection(monkeypatch, tmp_path):
    fake_model_path = tmp_path / "damage.pt"
    fake_model_path.write_bytes(b"not a real model")
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", str(fake_model_path))

    fake_box = MagicMock()
    fake_box.cls = [MagicMock(item=lambda: 0)]
    fake_box.conf = [MagicMock(item=lambda: 0.87)]
    fake_result = MagicMock()
    fake_result.boxes = [fake_box]
    fake_result.names = {0: "dent"}

    fake_model = MagicMock(return_value=[fake_result])

    with patch.object(extraction, "_load_cv_model", return_value=fake_model):
        result = extraction._local_cv_damage(_TINY_PNG)

    assert result["tool"] == "cv_damage"
    assert result["status"] == "ok"
    assert result["damage_detected"] is True
    assert "dent" in result["damage_classes"]
    assert result["confidence"] == 0.87
    assert result["severity_estimate"] in {"minor", "moderate", "severe"}


def test_local_cv_damage_error_is_fail_safe_not_fail_open(monkeypatch, tmp_path):
    fake_model_path = tmp_path / "damage.pt"
    fake_model_path.write_bytes(b"not a real model")
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", str(fake_model_path))

    with patch.object(extraction, "_load_cv_model", side_effect=RuntimeError("model load failed")):
        result = extraction._local_cv_damage(_TINY_PNG)

    assert result["status"] == "error"
    assert result["damage_detected"] is False


def test_extract_attachment_includes_cv_damage_assessment(monkeypatch, tmp_path):
    monkeypatch.setattr(extraction, "CV_DAMAGE_MODEL_PATH", None)  # unavailable path, deterministic
    fake_image = tmp_path / "claim_photo.png"
    fake_image.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)

    attachment = {
        "stored_path": str(fake_image),
        "original_name": "claim_photo.png",
        "declared_type": "image/png",
        "real_type": "image/png",
        "type_mismatch": False,
        "sha256": "deadbeef",
    }
    result = extraction.extract_attachment(attachment)
    assert "cv_damage_assessment" in result
    assert result["cv_damage_assessment"]["status"] == "unavailable"
