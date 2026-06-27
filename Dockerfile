FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN printf 'Acquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/99force-ipv4

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        clang \
        coreutils \
        curl \
        file \
        gcc \
        jq \
        libclang-rt-19-dev \
        make \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests

COPY analyzer/ /app/analyzer/

CMD ["python", "-m", "analyzer.main"]
