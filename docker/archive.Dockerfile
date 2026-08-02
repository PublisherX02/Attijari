# archive — sandboxed ZIP/7z/ISO member extraction, recursive YARA scan,
# and LNK command-line parsing. Closes the 2026-08-02 gap where this
# decompression ran unconditionally in the main pipeline process with no
# CPU/memory/timeout limits (see SANDBOX_REQUIRED_TOOLS in extraction.py).
#
# Uses python:3.12-slim (Debian/glibc), NOT Alpine like most sibling
# containers here: py7zr's compression-codec dependencies (bcj-cffi,
# pyppmd, pyzstd, brotli) ship prebuilt manylinux (glibc) wheels, not musl
# ones. This Dockerfile could not be build-tested on the dev machine that
# wrote it (no local Docker daemon) — glibc wheel compatibility was chosen
# over Alpine's smaller image size specifically to avoid an unverified
# from-source compile step. Build and verify on a host with Docker before
# relying on this in production.
FROM python:3.12-slim

RUN pip install --no-cache-dir \
        yara-python==4.5.4 \
        pycdlib==1.16.0 \
        py7zr==1.1.3 \
        LnkParse3==1.6.0 \
    && find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

RUN groupadd -r sandbox && useradd -r -g sandbox -d /home/sandbox -s /usr/sbin/nologin sandbox \
    && mkdir -p /work /rules && chown sandbox:sandbox /work /rules

COPY scripts/archive_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
