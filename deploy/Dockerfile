# syntax=docker/dockerfile:1
# IMPLEMENTATION_PLAN.md M3-T7: one image -- the backend serves the built SPA on one port.

FROM node:22-slim AS web
WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY docs/openapi.json /build/docs/openapi.json
RUN npm run gen:api:file && npm run build

FROM python:3.12-slim AS app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MAKA_ENV=demo \
    MAKA_DB_URL=sqlite:////app/var/maka.db \
    MAKA_BIND=0.0.0.0:8000 \
    MAKA_STATIC_DIR=/app/web/dist
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY eval ./eval
COPY formal ./formal
# the Evaluation page reads these beside the source tree (REPO_ROOT), so install in place (-e)
COPY artifacts/eval ./artifacts/eval
COPY docs/baseline ./docs/baseline
RUN pip install --no-cache-dir -e ".[server]"
COPY --from=web /build/web/dist ./web/dist
RUN useradd --system --uid 10001 maka && mkdir -p /app/var && chown maka /app/var
USER maka
EXPOSE 8000
VOLUME ["/app/var"]
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
CMD ["python", "-m", "maka_server", "serve"]
