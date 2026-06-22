# oletools — VBA macro + OLE object extraction
# ~70 MB (Alpine + oletools pure-Python)
FROM python:3.12-alpine

RUN pip install --no-cache-dir oletools==0.60.2 \
    && find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       find /usr/local -type d -name tests -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/oletools_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
