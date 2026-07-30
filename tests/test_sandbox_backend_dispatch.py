"""sandbox.run_tool() dispatches to the Docker backend by default and the
Kubernetes backend when SANDBOX_BACKEND=kubernetes — a thin test, not a
re-test of either backend's internals (those are covered in
test_sandbox_backend_dispatch's sibling files)."""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()


def test_defaults_to_docker_backend(monkeypatch):
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    import importlib
    import sandbox
    importlib.reload(sandbox)  # re-read SANDBOX_BACKEND after monkeypatch
    with patch.object(sandbox, "_run_tool_docker", return_value={"tool": "yara", "status": "ok"}) as mock_docker:
        result = sandbox.run_tool("yara", "/tmp/x")
    mock_docker.assert_called_once()
    assert result["status"] == "ok"


def test_dispatches_to_kubernetes_backend_when_configured(monkeypatch):
    monkeypatch.setenv("SANDBOX_BACKEND", "kubernetes")
    import importlib
    import sandbox
    importlib.reload(sandbox)
    with patch("sandbox_k8s.run_tool_k8s", return_value={"tool": "yara", "status": "ok"}) as mock_k8s:
        result = sandbox.run_tool("yara", "/tmp/x")
    mock_k8s.assert_called_once_with("yara", "/tmp/x", None, None)
    assert result["status"] == "ok"
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    importlib.reload(sandbox)  # restore default for any test run after this one in the same session
