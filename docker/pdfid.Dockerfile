# pdfid — PDF suspicious keyword detection
# ~52 MB (Alpine + tiny pure-Python package)
FROM python:3.12-alpine

RUN pip install --no-cache-dir pdfid \
    && find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/pdfid_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
