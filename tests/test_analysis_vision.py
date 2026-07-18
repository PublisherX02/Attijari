import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import analysis


def test_call_ollama_http_includes_images_in_payload():
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"response": "{}"}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        import json as _json
        captured["payload"] = _json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analysis._call_ollama_http("gemma3:4b", "prompt text", images=["ZmFrZWJhc2U2NA=="])

    assert captured["payload"]["images"] == ["ZmFrZWJhc2U2NA=="]


def test_call_ollama_http_omits_images_key_when_none():
    captured = {}

    class FakeResponse:
        def read(self):
            return b'{"response": "{}"}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        import json as _json
        captured["payload"] = _json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        analysis._call_ollama_http("gemma3:4b", "prompt text")

    assert "images" not in captured["payload"]
