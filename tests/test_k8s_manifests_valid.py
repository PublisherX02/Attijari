"""Every manifest under deploy/k8s/ must be valid YAML. This is the only
validation possible without a live cluster or local docker/kubectl — full
`kubectl apply --dry-run=server` validation happens on the bank VM before
first real deploy, not here."""
import sys
from pathlib import Path

import yaml

_DEPLOY_K8S = Path(__file__).parent.parent / "deploy" / "k8s"


def _all_yaml_files():
    return sorted(_DEPLOY_K8S.rglob("*.yaml")) + sorted(_DEPLOY_K8S.rglob("*.yml"))


def test_deploy_k8s_directory_exists():
    assert _DEPLOY_K8S.is_dir(), "deploy/k8s/ must exist"


def test_every_manifest_is_valid_yaml():
    files = _all_yaml_files()
    assert files, "expected at least one manifest under deploy/k8s/"
    for f in files:
        try:
            list(yaml.safe_load_all(f.read_text(encoding="utf-8")))
        except yaml.YAMLError as e:
            assert False, f"{f} is not valid YAML: {e}"


def test_namespace_manifest_declares_attijari_namespace():
    content = list(yaml.safe_load_all((_DEPLOY_K8S / "namespace.yaml").read_text(encoding="utf-8")))
    assert any(doc.get("kind") == "Namespace" and doc.get("metadata", {}).get("name") == "attijari" for doc in content)


def test_configmap_has_expected_keys():
    content = list(yaml.safe_load_all((_DEPLOY_K8S / "configmap.yaml").read_text(encoding="utf-8")))
    cm = next(doc for doc in content if doc.get("kind") == "ConfigMap")
    assert cm["metadata"]["name"] == "attijari-config"
    data = cm["data"]
    for key in ("OLLAMA_BASE_URL", "SANDBOX_BACKEND", "POLL_INTERVAL_SECONDS", "DASHBOARD_HOST"):
        assert key in data, f"configmap missing expected key {key}"
    assert data["SANDBOX_BACKEND"] == "kubernetes"
    assert data["DASHBOARD_HOST"] == "0.0.0.0"


def test_postgres_statefulset_has_headless_service_and_pvc():
    docs = list(yaml.safe_load_all((_DEPLOY_K8S / "postgres-statefulset.yaml").read_text(encoding="utf-8")))
    kinds = {doc["kind"] for doc in docs}
    assert "StatefulSet" in kinds
    assert "Service" in kinds
    svc = next(d for d in docs if d["kind"] == "Service")
    assert svc["spec"]["clusterIP"] == "None", "postgres Service must be headless for stable StatefulSet DNS"
    sts = next(d for d in docs if d["kind"] == "StatefulSet")
    assert sts["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"] == ["ReadWriteOnce"]


def test_redis_statefulset_has_headless_service_and_pvc():
    docs = list(yaml.safe_load_all((_DEPLOY_K8S / "redis-statefulset.yaml").read_text(encoding="utf-8")))
    kinds = {doc["kind"] for doc in docs}
    assert "StatefulSet" in kinds
    assert "Service" in kinds
    svc = next(d for d in docs if d["kind"] == "Service")
    assert svc["spec"]["clusterIP"] == "None"


def test_ollama_deployment_has_no_gpu_by_default():
    docs = list(yaml.safe_load_all((_DEPLOY_K8S / "ollama-deployment.yaml").read_text(encoding="utf-8")))
    deploy = next(d for d in docs if d["kind"] == "Deployment")
    container = deploy["spec"]["template"]["spec"]["containers"][0]
    resources = container.get("resources", {})
    limits = resources.get("limits", {})
    assert "nvidia.com/gpu" not in limits, "base manifest must be GPU-free; GPU is opt-in via the overlay"
    assert "nodeSelector" not in deploy["spec"]["template"]["spec"]


def test_gpu_overlay_adds_gpu_resources():
    patch_docs = list(yaml.safe_load_all((_DEPLOY_K8S / "overlays" / "gpu" / "ollama-gpu-patch.yaml").read_text(encoding="utf-8")))
    assert patch_docs, "GPU overlay patch must not be empty"
    kustomization = yaml.safe_load((_DEPLOY_K8S / "overlays" / "gpu" / "kustomization.yaml").read_text(encoding="utf-8"))
    assert kustomization["resources"] == ["../../"]
