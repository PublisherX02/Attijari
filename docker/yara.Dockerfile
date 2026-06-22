# yara — pattern-based malware signature scanning
# Multi-stage: compile yara-python in builder, copy .so + packages to runtime
FROM python:3.12-alpine AS builder

RUN apk add --no-cache --virtual .build-deps \
        gcc musl-dev openssl-dev automake autoconf libtool \
    && pip install --no-cache-dir --target=/install yara-python==4.5.4 \
    && apk del .build-deps \
    && find /install -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

FROM python:3.12-alpine

RUN apk add --no-cache libssl3 libcrypto3

COPY --from=builder /install /usr/local/lib/python3.12/site-packages/

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work /rules && chown sandbox:sandbox /work /rules

COPY scripts/yara_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
