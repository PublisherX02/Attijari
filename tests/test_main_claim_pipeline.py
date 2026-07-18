import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_find_claim_photo_picks_first_image_attachment():
    import main

    attachments = [
        {"original_name": "invoice.pdf", "stored_path": "/tmp/invoice.pdf"},
        {"original_name": "damage.jpg", "stored_path": "/tmp/damage.jpg"},
    ]
    result = main._find_claim_photo(attachments)
    assert result is not None
    assert result["original_name"] == "damage.jpg"


def test_find_claim_photo_returns_none_when_no_image():
    import main

    attachments = [{"original_name": "invoice.pdf", "stored_path": "/tmp/invoice.pdf"}]
    assert main._find_claim_photo(attachments) is None


def test_find_claim_photo_returns_none_for_empty_list():
    import main

    assert main._find_claim_photo([]) is None
