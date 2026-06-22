# pymupdf — PDF text + structure extraction
# Uses slim (not Alpine) — pymupdf ships manylinux wheels, no musllinux
# Multi-stage: install in builder, copy site-packages to runtime
FROM python:3.12-slim AS builder

RUN pip install --no-cache-dir --target=/install pymupdf \
    && find /install -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       find /install -type d -name tests -exec rm -rf {} + 2>/dev/null; \
       find /install -name "*.dist-info" -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

FROM python:3.12-slim

COPY --from=builder /install /usr/local/lib/python3.12/site-packages/

RUN groupadd -r sandbox && useradd -r -g sandbox -d /home/sandbox -s /usr/sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work \
    && rm -rf /var/lib/apt/lists/* /tmp/* /root/.cache

COPY scripts/pymupdf_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
