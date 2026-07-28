import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.email_extraction import EmailIngestion


def test_fetch_pending_smtp_reads_eml_files(tmp_path, monkeypatch):
    ingestion = EmailIngestion(host="unused", user="unused", password="unused")
    monkeypatch.setattr(ingestion, "PENDING_SMTP_DIR", tmp_path)

    (tmp_path / "aaa.eml").write_bytes(b"message one")
    (tmp_path / "bbb.eml").write_bytes(b"message two")
    (tmp_path / "not-an-eml.txt").write_bytes(b"ignore me")

    result = ingestion.fetch_pending_smtp()

    assert len(result) == 2
    assert b"message one" in result
    assert b"message two" in result


def test_fetch_pending_smtp_empty_dir_returns_empty_list(tmp_path, monkeypatch):
    ingestion = EmailIngestion(host="unused", user="unused", password="unused")
    monkeypatch.setattr(ingestion, "PENDING_SMTP_DIR", tmp_path / "does_not_exist")

    result = ingestion.fetch_pending_smtp()

    assert result == []


def test_fetch_pending_smtp_respects_limit(tmp_path, monkeypatch):
    ingestion = EmailIngestion(host="unused", user="unused", password="unused")
    monkeypatch.setattr(ingestion, "PENDING_SMTP_DIR", tmp_path)

    for i in range(5):
        (tmp_path / f"{i}.eml").write_bytes(f"message {i}".encode())

    result = ingestion.fetch_pending_smtp(limit=3)

    assert len(result) == 3
