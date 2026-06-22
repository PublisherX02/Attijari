# tesseract — OCR text extraction from images
# Alpine has tesseract-ocr in repos; Pillow needs build deps only at install time
# Multi-stage: compile Pillow in builder, copy to lean runtime
FROM python:3.12-alpine AS builder

RUN apk add --no-cache --virtual .build-deps \
        gcc musl-dev zlib-dev jpeg-dev libffi-dev \
    && pip install --no-cache-dir --target=/install pytesseract==0.3.13 Pillow \
    && apk del .build-deps \
    && find /install -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; \
       find /install -type d -name tests -exec rm -rf {} + 2>/dev/null; \
       rm -rf /root/.cache

FROM python:3.12-alpine

# Runtime deps only — no compiler, no -dev headers
RUN apk add --no-cache tesseract-ocr tesseract-ocr-data-fra tesseract-ocr-data-ara \
        zlib libjpeg-turbo

COPY --from=builder /install /usr/local/lib/python3.12/site-packages/

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

COPY scripts/tesseract_scan.py /opt/scan.py
USER sandbox
WORKDIR /work
ENTRYPOINT ["python", "/opt/scan.py"]
