# markitdown — text extraction (complementary only, NEVER standalone for security)
# Needs git to install from GitHub; multi-stage keeps git out of runtime
FROM python:3.12-alpine AS builder

RUN apk add --no-cache git \
    && pip install --no-cache-dir git+https://github.com/microsoft/markitdown.git \
    && find /usr/local/lib/python3.12/site-packages -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       find /usr/local/lib/python3.12/site-packages -type d -name tests -exec rm -rf {} + 2>/dev/null; \
       find /usr/local/lib/python3.12/site-packages -name "*.dist-info" -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

FROM python:3.12-alpine

COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/markitdown_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
