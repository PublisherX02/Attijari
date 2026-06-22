# python-magic — file type detection via magic bytes
# ~55 MB total (Alpine + libmagic)
FROM python:3.12-alpine

RUN apk add --no-cache libmagic \
    && pip install --no-cache-dir python-magic==0.4.27 \
    && find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/magic_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
