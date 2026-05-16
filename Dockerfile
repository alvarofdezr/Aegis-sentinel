
FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvX /usr/local/bin/

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libnetfilter-queue-dev \
    iptables \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN /usr/local/bin/uv sync --no-cache

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["/usr/local/bin/uv", "run", "python", "-m", "aegis.core.engine"]