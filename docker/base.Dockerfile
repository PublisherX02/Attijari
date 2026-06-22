# Shared Alpine base — ~50MB vs ~150MB for python:slim
FROM python:3.12-alpine AS base

RUN addgroup -S sandbox && adduser -S -G sandbox -h /home/sandbox -s /sbin/nologin sandbox \
    && mkdir -p /work && chown sandbox:sandbox /work

USER sandbox
WORKDIR /work
