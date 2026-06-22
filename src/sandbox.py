"""sandbox.py — Docker-based isolated execution for extraction tools

Each tool runs in its own container with maximum security restrictions:
  - --network=none          : zero network access
  - --read-only             : immutable filesystem (except /tmp)
  - --cap-drop=ALL          : drop ALL Linux capabilities
  - --security-opt=no-new-privileges : prevent privilege escalation
  - --cpus=0.5              : half a CPU core max (prevents CPU bombs)
  - --memory=256m           : 256 MB RAM max (prevents memory bombs)
  - --pids-limit=50         : max 50 processes (prevents fork bombs)
  - --tmpfs /tmp:size=50m   : small writable scratch space

The attachment file is mounted READ-ONLY at /work/input.
YARA rules are mounted READ-ONLY at /rules/ (yara container only).
Container output is JSON on stdout.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
YARA_RULES_DIR = _PROJECT_ROOT / "data" / "yara_rules"

# Docker image name prefix
IMAGE_PREFIX = "tijari-extract"

# Security constraints for all containers
CONTAINER_LIMITS = {
    "cpus": "0.5",
    "memory": "256m",
    "pids_limit": "50",
    "timeout": 45,  # seconds — kill container after this
}

# Tool → Docker image mapping
TOOL_IMAGES = {
    "magic":      f"{IMAGE_PREFIX}-magic",
    "oletools":   f"{IMAGE_PREFIX}-oletools",
    "pdfid":      f"{IMAGE_PREFIX}-pdfid",
    "pymupdf":    f"{IMAGE_PREFIX}-pymupdf",
    "tesseract":  f"{IMAGE_PREFIX}-tesseract",
    "yara":       f"{IMAGE_PREFIX}-yara",
    "ioc_finder": f"{IMAGE_PREFIX}-ioc-finder",
    "markitdown": f"{IMAGE_PREFIX}-markitdown",
}


def _docker_available() -> bool:
    """Check if Docker daemon is running."""
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def _image_exists(image: str) -> bool:
    """Check if a Docker image is built."""
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except Exception:
        return False


def run_tool(tool_name: str, input_path: str,
             env: dict[str, str] | None = None,
             timeout: int | None = None) -> dict[str, Any]:
    """Run an extraction tool inside a sandboxed Docker container.

    Args:
        tool_name: one of the TOOL_IMAGES keys
        input_path: absolute path to the file to analyze
        env: optional environment variables to pass (e.g. ORIGINAL_NAME)
        timeout: override default timeout in seconds

    Returns:
        dict with tool results (parsed from JSON stdout), or error dict.
    """
    image = TOOL_IMAGES.get(tool_name)
    if not image:
        return {"tool": tool_name, "status": "error", "error": f"unknown tool: {tool_name}"}

    if not _docker_available():
        return {"tool": tool_name, "status": "error",
                "error": "docker_unavailable", "fallback": True}

    if not _image_exists(image):
        return {"tool": tool_name, "status": "error",
                "error": f"image_not_built: {image}", "fallback": True}

    input_abs = str(Path(input_path).resolve())
    kill_timeout = timeout or CONTAINER_LIMITS["timeout"]

    # Build docker run command with all security constraints
    cmd = [
        "docker", "run",
        "--rm",                                        # auto-cleanup
        "--network=none",                              # NO network access
        "--read-only",                                 # immutable filesystem
        "--cap-drop=ALL",                              # drop ALL capabilities
        "--security-opt=no-new-privileges",            # no privilege escalation
        f"--cpus={CONTAINER_LIMITS['cpus']}",          # CPU limit
        f"--memory={CONTAINER_LIMITS['memory']}",      # RAM limit
        f"--pids-limit={CONTAINER_LIMITS['pids_limit']}",  # fork bomb protection
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=50m",   # small scratch space, no exec
    ]

    # Mount input file read-only
    cmd += ["-v", f"{input_abs}:/work/input:ro"]

    # YARA: also mount rules directory read-only
    if tool_name == "yara" and YARA_RULES_DIR.exists():
        rules_abs = str(YARA_RULES_DIR.resolve())
        cmd += ["-v", f"{rules_abs}:/rules:ro"]

    # Pass environment variables (HIGH-06 Fix: Sanitize values)
    if env:
        import re
        _SAFE_ENV_RE = re.compile(r'^[\w\s.\-@/]+$')
        for k, v in env.items():
            sanitized = str(v) if _SAFE_ENV_RE.match(str(v)) else "SANITIZED_FOR_SECURITY"
            cmd += ["-e", f"{k}={sanitized}"]

    cmd.append(image)

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=kill_timeout,
            text=True,
        )
        elapsed = time.time() - t0

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()[:500]
            return {
                "tool": tool_name,
                "status": "error",
                "error": f"container_exit_{proc.returncode}: {stderr}",
                "elapsed_s": round(elapsed, 2),
            }

        # Parse JSON from stdout
        stdout = (proc.stdout or "").strip()
        if not stdout:
            return {
                "tool": tool_name,
                "status": "error",
                "error": "empty_output",
                "elapsed_s": round(elapsed, 2),
            }

        try:
            result = json.loads(stdout)
            result["elapsed_s"] = round(elapsed, 2)
            result["sandboxed"] = True
            return result
        except json.JSONDecodeError:
            return {
                "tool": tool_name,
                "status": "error",
                "error": "invalid_json_output",
                "raw_output": stdout[:1000],
                "elapsed_s": round(elapsed, 2),
            }

    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        # Force kill any lingering container
        return {
            "tool": tool_name,
            "status": "error",
            "error": f"timeout_killed_after_{kill_timeout}s",
            "elapsed_s": round(elapsed, 2),
        }
    except Exception as e:
        return {
            "tool": tool_name,
            "status": "error",
            "error": str(e),
            "elapsed_s": round(time.time() - t0, 2),
        }


def build_images(docker_dir: str | None = None) -> dict[str, bool]:
    """Build all extraction tool Docker images.

    Returns dict of tool_name -> success.
    """
    docker_dir = docker_dir or str(_PROJECT_ROOT / "docker")
    results = {}

    for tool_name, image in TOOL_IMAGES.items():
        dockerfile = os.path.join(docker_dir, f"{tool_name}.Dockerfile")
        if not os.path.exists(dockerfile):
            # try alternate naming
            alt = tool_name.replace("_", "-")
            dockerfile = os.path.join(docker_dir, f"{alt}.Dockerfile")

        if not os.path.exists(dockerfile):
            print(f"[SANDBOX] SKIP {tool_name}: no Dockerfile found")
            results[tool_name] = False
            continue

        print(f"[SANDBOX] Building {image} from {os.path.basename(dockerfile)}...")
        try:
            proc = subprocess.run(
                ["docker", "build", "-t", image, "-f", dockerfile, docker_dir],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode == 0:
                print(f"[SANDBOX] {image} built OK")
                results[tool_name] = True
            else:
                print(f"[SANDBOX] {image} FAILED: {proc.stderr[:200]}")
                results[tool_name] = False
        except Exception as e:
            print(f"[SANDBOX] {image} ERROR: {e}")
            results[tool_name] = False

    return results


def check_sandbox_status() -> dict:
    """Check Docker availability and which images are built."""
    docker_ok = _docker_available()
    images = {}
    if docker_ok:
        for tool_name, image in TOOL_IMAGES.items():
            images[tool_name] = _image_exists(image)
    return {
        "docker_available": docker_ok,
        "images": images,
        "all_built": all(images.values()) if images else False,
    }
