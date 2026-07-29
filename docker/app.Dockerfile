# app.Dockerfile — production image for the Attijari FastAPI dashboard/pipeline.
# Multi-stage: build stage installs deps into a venv, runtime stage is slim
# and non-root. Mirrors docker/base.Dockerfile's non-root-user pattern used
# by the extraction sandbox images.

FROM python:3.12-slim AS build
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /venv \
    && /venv/bin/pip install --no-cache-dir --upgrade pip \
    && /venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime
RUN groupadd -r app && useradd -r -g app -d /app -s /usr/sbin/nologin app \
    && mkdir -p /app/data && chown -R app:app /app
COPY --from=build /venv /venv
COPY --chown=app:app src/ /app/src/
COPY --chown=app:app data/yara_rules/ /app/data/yara_rules/
ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1
WORKDIR /app/src
USER app
EXPOSE 8000
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
