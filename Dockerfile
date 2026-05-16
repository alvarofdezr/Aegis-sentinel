FROM ghcr.io/astral-sh/uv:python3.11-debian-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libnetfilter-queue-dev \
    iptables \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock ./

RUN uv sync --no-cache

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["uv", "run", "python", "-m", "aegis.core.engine"]