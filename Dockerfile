# syntax=docker/dockerfile:1.7

FROM ghcr.io/astral-sh/uv:0.9.27 AS uv


FROM python:3.12-slim-bookworm AS python-builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/crimsonflux

COPY --from=uv /uv /uvx /usr/local/bin/
WORKDIR /build

# Keep dependency resolution tied to the repository lock. A missing or stale
# uv.lock is a build failure, never an invitation to resolve newer packages.
COPY pyproject.toml uv.lock README.md LICENSE THIRD_PARTY_NOTICES.md ./
RUN uv sync --frozen --no-dev --no-install-project --no-editable

COPY src ./src
RUN uv sync --frozen --no-dev --no-editable


FROM python:3.12-slim-bookworm AS runtime

ARG APP_UID=1000
ARG APP_GID=1000

ENV PATH=/opt/crimsonflux/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp/crimsonflux-home \
    CRIMSONFLUX_HOST=0.0.0.0 \
    CRIMSONFLUX_ALLOW_CONTAINER_BIND=1 \
    CRIMSONFLUX_PORT=8765 \
    CRIMSONFLUX_NO_BROWSER=1 \
    CRIMSONFLUX_STATE_DIR=/var/lib/crimsonflux \
    CRIMSONFLUX_EXPORT_DIR=/app/exports

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid "${APP_GID}" app \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --home-dir /home/app app \
    && install --directory --owner=app --group=app /app /app/exports /var/lib/crimsonflux

COPY --from=python-builder /opt/crimsonflux /opt/crimsonflux

WORKDIR /app
COPY --chown=app:app LICENSE THIRD_PARTY_NOTICES.md README.md ./

USER app:app

EXPOSE 8765
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import socket; s=socket.create_connection(('127.0.0.1',8765),2); s.close()"]

ENTRYPOINT ["crimsonflux"]
CMD ["serve"]
