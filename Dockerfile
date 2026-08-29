FROM python:3.12-slim

ARG VCS_REF=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/app/.venv/bin:$PATH"

LABEL org.opencontainers.image.source="https://github.com/shogun301/ha-chatgpt-mcp" \
      org.opencontainers.image.version="2.7.1" \
      org.opencontainers.image.revision="${VCS_REF}"

RUN useradd --system --uid 10001 --create-home --home-dir /app mcp
WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir "uv==0.11.15" && \
    uv sync --frozen --group dev --no-install-project

COPY app ./app
COPY collector ./collector
COPY home_assistant ./home_assistant
COPY tests ./tests
COPY scripts ./scripts
RUN uv sync --frozen --group dev

USER 10001:10001
CMD ["uvicorn", "app.server:app", "--host", "127.0.0.1", "--port", "8000", "--no-proxy-headers"]
