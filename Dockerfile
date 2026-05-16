FROM ghcr.io/astral-sh/uv:python3.11-alpine

RUN apk add --no-cache \
    gcc \
    musl-dev \
    libnetfilter_queue-dev \
    iptables \
    wireguard-tools

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

COPY . .

ENV PYTHONUNBUFFERED=1

CMD ["uv", "run", "python", "-m", "aegis.core.engine"]