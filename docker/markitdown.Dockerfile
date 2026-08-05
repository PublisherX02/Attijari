# markitdown — text extraction (complementary only, NEVER standalone for security)
# Needs git to install from GitHub; multi-stage keeps git out of runtime.
#
# Uses python:3.12-slim (Debian/glibc), NOT Alpine: markitdown's hard
# dependency `magika` requires `onnxruntime`, which ships only manylinux
# (glibc) wheels, no musl ones — confirmed live 2026-08-05, pip's resolver
# reports this as a confusing "conflicting dependencies" ResolutionImpossible
# rather than "no matching distribution", but the real cause is Alpine
# simply has no installable onnxruntime wheel at all. Same class of fix as
# archive.Dockerfile (py7zr's codecs, same glibc-wheel constraint).
#
# The [pdf] extra is required explicitly: bare `markitdown` has no PDF
# support at all (raises MissingDependencyException) -- confirmed live
# 2026-08-05. The main venv's requirements.txt install (no extras) happens
# to work anyway because something else already pulls in pdfminer.six as a
# transitive dependency, but that's not something to rely on here where
# nothing else in this image installs it.
FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir "markitdown[pdf] @ git+https://github.com/microsoft/markitdown.git#subdirectory=packages/markitdown" \
    && find /usr/local/lib/python3.12/site-packages -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       find /usr/local/lib/python3.12/site-packages -type d -name tests -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

FROM python:3.12-slim

COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/

RUN groupadd -r sandbox && useradd -r -g sandbox -d /home/sandbox -s /usr/sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/markitdown_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
