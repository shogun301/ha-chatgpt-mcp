FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --system --uid 10001 --create-home --home-dir /app mcp
WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
COPY tests ./tests
COPY scripts/production_mcp_verify.py ./scripts/
RUN pip install --upgrade pip && pip install .

USER 10001:10001
CMD ["uvicorn", "app.server:app", "--host", "127.0.0.1", "--port", "8000", "--no-proxy-headers"]
