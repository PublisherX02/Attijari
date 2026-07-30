"""sandbox_k8s.py — Kubernetes-Job-based isolated execution for extraction
tools (the "managed pool" the roadmap calls for). Same contract as
sandbox.py's Docker-backed run_tool(): run_tool_k8s() takes a tool name and
an input file path, returns a dict with parsed tool results or an error.

Security posture, mapped from sandbox.py's Docker flags to their Kubernetes
equivalents (see docs/superpowers/specs/2026-07-30-kubernetes-orchestration-design.md):
  --network=none        -> NetworkPolicy denying all ingress/egress for
                            app=attijari-sandbox pods (deploy/k8s/sandbox-networkpolicy.yaml)
  --read-only            -> securityContext.readOnlyRootFilesystem
  --cap-drop=ALL          -> securityContext.capabilities.drop=["ALL"]
  --security-opt no-new-privileges -> securityContext.allowPrivilegeEscalation=False
  --cpus / --memory       -> resources.limits
  --pids-limit            -> namespace LimitRange (deploy/k8s/sandbox-limitrange.yaml)
  timeout / kill          -> Job.spec.activeDeadlineSeconds
  -v input:/work/input:ro -> shared ReadWriteMany PVC (sandbox-workdir),
                            written by this module, mounted read-only by the Job

Fail-safe: every code path returns a dict with status="error" on any
failure (K8s API error, timeout, malformed output) — never raises past this
module's boundary, matching SEC-H1's contract with extraction.py.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from kubernetes import client, config as k8s_config
from kubernetes.client.exceptions import ApiException

from sandbox import TOOL_IMAGES, CONTAINER_LIMITS, YARA_RULES_DIR

NAMESPACE = os.getenv("SANDBOX_NAMESPACE", "attijari")
WORKDIR_PVC = os.getenv("SANDBOX_WORKDIR_PVC", "sandbox-workdir")
SANDBOX_MOUNT_ROOT = "/sandbox-workdir"
SERVICE_ACCOUNT = "attijari-sandbox-runner"

_config_loaded = False


def _ensure_config_loaded():
    global _config_loaded
    if _config_loaded:
        return
    try:
        k8s_config.load_incluster_config()  # real deployment: running inside the cluster
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()  # local/dev: reads ~/.kube/config
    _config_loaded = True


def _batch_api() -> client.BatchV1Api:
    _ensure_config_loaded()
    return client.BatchV1Api()


def _core_api() -> client.CoreV1Api:
    _ensure_config_loaded()
    return client.CoreV1Api()


def _write_input_to_pvc(input_path: str, job_id: str) -> str:
    """Copy the attachment into the shared PVC's mount point (this function
    runs inside the app pod, which already has sandbox-workdir mounted at
    SANDBOX_MOUNT_ROOT per deploy/k8s/app-deployment.yaml). Returns the
    subPath (relative to the PVC root) the Job pod should mount."""
    sub_path = f"{job_id}/input"
    dest = Path(SANDBOX_MOUNT_ROOT) / job_id / "input"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(Path(input_path).read_bytes())
    return sub_path


def _cleanup_pvc_subpath(job_id: str) -> None:
    import shutil
    target = Path(SANDBOX_MOUNT_ROOT) / job_id
    shutil.rmtree(target, ignore_errors=True)


def _build_job(tool_name: str, image: str, sub_path: str, job_id: str,
               env: dict[str, str] | None, timeout: int) -> client.V1Job:
    container_env = []
    if env:
        import re
        _SAFE_ENV_RE = re.compile(r'^[\w\s.\-@/]+$')
        for k, v in env.items():
            sanitized = str(v) if _SAFE_ENV_RE.match(str(v)) else "SANITIZED_FOR_SECURITY"
            container_env.append(client.V1EnvVar(name=k, value=sanitized))

    volume_mounts = [
        client.V1VolumeMount(name="workdir", mount_path="/work/input", sub_path=sub_path, read_only=True),
    ]
    volumes = [
        client.V1Volume(name="workdir", persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(
            claim_name=WORKDIR_PVC)),
    ]
    if tool_name == "yara" and YARA_RULES_DIR.exists():
        # subPath is required here: without it this would mount the PVC's
        # entire root at /rules, including every other concurrent job's
        # per-job input subdirectory — a real cross-job data leak. Rules
        # live at this fixed subPath, seeded once at deploy time (a
        # deploy-time prerequisite on the bank VM, not done by this code —
        # e.g. `kubectl cp data/yara_rules/. <any-pod>:/sandbox-workdir/_yara_rules/`),
        # reusing the same "workdir" volume already mounted above rather
        # than declaring a second V1Volume for the same claim.
        volume_mounts.append(client.V1VolumeMount(
            name="workdir", mount_path="/rules", sub_path="_yara_rules", read_only=True))

    container = client.V1Container(
        name="tool",
        image=image,
        env=container_env,
        volume_mounts=volume_mounts,
        security_context=client.V1SecurityContext(
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"]),
            allow_privilege_escalation=False,
            run_as_non_root=True,
        ),
        resources=client.V1ResourceRequirements(
            # Mirrors sandbox.py's CONTAINER_LIMITS (cpus="0.5", memory="256m") in
            # Kubernetes' quantity format — kept as explicit literals rather than
            # string-transforming CONTAINER_LIMITS's Docker-flag values, since the
            # two syntaxes (Docker's "0.5"/"256m" vs K8s' "500m"/"256Mi") don't
            # share a reliable string-substitution rule in general.
            limits={"cpu": "500m", "memory": "256Mi"},
            requests={"cpu": "100m", "memory": "128Mi"},
        ),
    )
    pod_spec = client.V1PodSpec(
        containers=[container],
        volumes=volumes,
        restart_policy="Never",
        service_account_name=SERVICE_ACCOUNT,
        automount_service_account_token=False,  # sandboxed pods never need K8s API access themselves
    )
    template = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(labels={"app": "attijari-sandbox", "tool": tool_name}),
        spec=pod_spec,
    )
    job_spec = client.V1JobSpec(
        template=template,
        backoff_limit=0,  # never retry — a failed/timed-out tool run is reported as-is, not silently rerun
        active_deadline_seconds=timeout,
        ttl_seconds_after_finished=60,
    )
    return client.V1Job(
        api_version="batch/v1", kind="Job",
        metadata=client.V1ObjectMeta(name=f"attijari-sandbox-{tool_name}-{job_id}", namespace=NAMESPACE),
        spec=job_spec,
    )


def _wait_for_job_completion(job_name: str, timeout: int) -> Any:
    """Poll the Job's status until succeeded/failed or `timeout` elapses.
    Raises TimeoutError if the deadline passes without completion."""
    batch = _batch_api()
    deadline = time.time() + timeout + 5  # small grace margin over activeDeadlineSeconds itself
    while time.time() < deadline:
        job = batch.read_namespaced_job(job_name, NAMESPACE)
        status = job.status
        if (status.succeeded or 0) > 0 or (status.failed or 0) > 0:
            return status
        time.sleep(1)
    raise TimeoutError()


def run_tool_k8s(tool_name: str, input_path: str,
                 env: dict[str, str] | None = None,
                 timeout: int | None = None) -> dict[str, Any]:
    image = TOOL_IMAGES.get(tool_name)
    if not image:
        return {"tool": tool_name, "status": "error", "error": f"unknown tool: {tool_name}"}

    kill_timeout = timeout or CONTAINER_LIMITS["timeout"]
    job_id = uuid.uuid4().hex[:12]
    job_name = f"attijari-sandbox-{tool_name}-{job_id}"
    t0 = time.time()

    try:
        sub_path = _write_input_to_pvc(input_path, job_id)
    except Exception as e:
        return {"tool": tool_name, "status": "error", "error": f"pvc_write_failed: {e}"}

    try:
        job = _build_job(tool_name, image, sub_path, job_id, env, kill_timeout)
        _batch_api().create_namespaced_job(namespace=NAMESPACE, body=job)
    except ApiException as e:
        _cleanup_pvc_subpath(job_id)
        return {"tool": tool_name, "status": "error", "error": f"job_create_failed: {e.status} {e.reason}"}
    except Exception as e:
        _cleanup_pvc_subpath(job_id)
        return {"tool": tool_name, "status": "error", "error": f"job_create_failed: {e}"}

    try:
        _wait_for_job_completion(job_name, kill_timeout)
    except TimeoutError:
        elapsed = time.time() - t0
        _cleanup_job_and_pvc(job_name, job_id)
        return {"tool": tool_name, "status": "error",
                "error": f"timeout_killed_after_{kill_timeout}s", "elapsed_s": round(elapsed, 2)}
    except Exception as e:
        _cleanup_job_and_pvc(job_name, job_id)
        return {"tool": tool_name, "status": "error", "error": f"job_wait_failed: {e}"}

    try:
        pods = _core_api().list_namespaced_pod(namespace=NAMESPACE, label_selector=f"job-name={job_name}")
        if not pods.items:
            _cleanup_job_and_pvc(job_name, job_id)
            return {"tool": tool_name, "status": "error", "error": "no_pod_found_for_job"}
        pod_name = pods.items[0].metadata.name
        log = _core_api().read_namespaced_pod_log(name=pod_name, namespace=NAMESPACE)
    except Exception as e:
        _cleanup_job_and_pvc(job_name, job_id)
        return {"tool": tool_name, "status": "error", "error": f"log_read_failed: {e}"}

    elapsed = time.time() - t0
    _cleanup_job_and_pvc(job_name, job_id)

    stdout = (log or "").strip()
    if not stdout:
        return {"tool": tool_name, "status": "error", "error": "empty_output", "elapsed_s": round(elapsed, 2)}
    try:
        result = json.loads(stdout)
        result["elapsed_s"] = round(elapsed, 2)
        result["sandboxed"] = True
        return result
    except json.JSONDecodeError:
        return {"tool": tool_name, "status": "error", "error": "invalid_json_output",
                "raw_output": stdout[:1000], "elapsed_s": round(elapsed, 2)}


def _cleanup_job_and_pvc(job_name: str, job_id: str) -> None:
    try:
        _batch_api().delete_namespaced_job(job_name, NAMESPACE, propagation_policy="Background")
    except Exception:
        pass
    _cleanup_pvc_subpath(job_id)
