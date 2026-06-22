# ioc-finder — IOC extraction (IPs, domains, URLs, hashes)
# ~65 MB (Alpine + pure-Python ioc-finder)
FROM python:3.12-alpine

RUN pip install --no-cache-dir ioc-finder==9.4.1 \
    && find /usr/local -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       find /usr/local -type d -name tests -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/ioc_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
