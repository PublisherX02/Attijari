"""sandbox_k8s.run_tool_k8s(): same contract as sandbox.run_tool() (a dict
with tool/status/result-or-error), but executes as a real Kubernetes Job
instead of a local `docker run`. The Kubernetes API is mocked throughout —
it's a true external boundary this project doesn't have a local instance
of, unlike Postgres/Redis which this project's other tests hit for real."""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from kubernetes.client.exceptions import ApiException


def _make_job_status(succeeded=0, failed=0, active=0):
    status = MagicMock()
    status.succeeded = succeeded
    status.failed = failed
    status.active = active
    return status


def test_unknown_tool_returns_error_without_calling_k8s():
    import sandbox_k8s
    with patch("sandbox_k8s._batch_api") as mock_batch:
        result = sandbox_k8s.run_tool_k8s("not_a_real_tool", "/tmp/x")
        mock_batch.assert_not_called()
    assert result["status"] == "error"
    assert "unknown tool" in result["error"]


def test_successful_job_returns_parsed_json_from_pod_log():
    import sandbox_k8s
    fake_job = MagicMock()
    fake_job.metadata.name = "attijari-sandbox-oletools-abc123"
    # MagicMock(name="pod-1") would NOT set the .name attribute — `name` is
    # a reserved MagicMock constructor kwarg for the mock's own repr, not a
    # generic attribute setter. Set it post-construction instead, so this
    # test actually exercises the real pod-name-lookup path rather than
    # silently passing regardless of what pod_name resolves to.
    fake_pod = MagicMock()
    fake_pod.metadata.name = "pod-1"

    # _batch_api/_core_api are FUNCTIONS being patched — the mock returned
    # by patch() stands in for the function itself, so configuring
    # behavior on calls made via _batch_api() (i.e. the api OBJECT the
    # function returns) requires going through mock_batch.return_value,
    # not mock_batch directly.
    with patch("sandbox_k8s._batch_api") as mock_batch, \
         patch("sandbox_k8s._core_api") as mock_core, \
         patch("sandbox_k8s._write_input_to_pvc", return_value="job-abc123/input"), \
         patch("sandbox_k8s._cleanup_pvc_subpath"), \
         patch("sandbox_k8s._wait_for_job_completion", return_value=_make_job_status(succeeded=1)):
        mock_batch.return_value.create_namespaced_job.return_value = fake_job
        mock_core.return_value.list_namespaced_pod.return_value.items = [fake_pod]
        mock_core.return_value.read_namespaced_pod_log.return_value = '{"tool": "oletools", "status": "ok", "macros": []}'

        result = sandbox_k8s.run_tool_k8s("oletools", "/tmp/fake_attachment")

    assert result["status"] == "ok"
    assert result["tool"] == "oletools"
    assert result["sandboxed"] is True
    mock_batch.return_value.create_namespaced_job.assert_called_once()
    mock_batch.return_value.delete_namespaced_job.assert_called_once()
    mock_core.return_value.read_namespaced_pod_log.assert_called_once_with(name="pod-1", namespace=sandbox_k8s.NAMESPACE)


def test_job_timeout_returns_timeout_error_matching_docker_backend_shape():
    import sandbox_k8s
    with patch("sandbox_k8s._batch_api") as mock_batch, \
         patch("sandbox_k8s._core_api"), \
         patch("sandbox_k8s._write_input_to_pvc", return_value="job-xyz/input"), \
         patch("sandbox_k8s._cleanup_pvc_subpath"), \
         patch("sandbox_k8s._wait_for_job_completion", side_effect=TimeoutError()):
        result = sandbox_k8s.run_tool_k8s("pdfid", "/tmp/fake_attachment", timeout=5)

    assert result["status"] == "error"
    assert "timeout" in result["error"]
    assert "5" in result["error"]


def test_job_creation_failure_returns_error_never_raises():
    import sandbox_k8s
    with patch("sandbox_k8s._batch_api") as mock_batch, \
         patch("sandbox_k8s._core_api"), \
         patch("sandbox_k8s._write_input_to_pvc", return_value="job-err/input"), \
         patch("sandbox_k8s._cleanup_pvc_subpath"):
        mock_batch.return_value.create_namespaced_job.side_effect = ApiException(status=403, reason="Forbidden")
        result = sandbox_k8s.run_tool_k8s("yara", "/tmp/fake_attachment")

    assert result["status"] == "error"
    assert "403" in result["error"] or "Forbidden" in result["error"]
