FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        curl \
        file \
        gcc \
        jq \
        make \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests

COPY analyzer/ /app/analyzer/

CMD ["python", "-m", "analyzer.main"]
