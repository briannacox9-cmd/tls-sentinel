FROM python:3.13-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-slim
RUN groupadd --system sentinel && useradd --system --gid sentinel --home /app sentinel
WORKDIR /app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
COPY config.example.yaml /app/config.yaml
RUN mkdir /data && chown sentinel:sentinel /data && sed -i 's#./data/history.jsonl#/data/history.jsonl#' /app/config.yaml
USER sentinel
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"]
ENTRYPOINT ["tls-sentinel"]
CMD ["serve", "--config", "/app/config.yaml"]
