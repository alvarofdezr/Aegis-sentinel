FROM python:3.11-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libnetfilter-queue-dev \
    iptables \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/aegis && chmod 777 /var/log/aegis

WORKDIR /app

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

COPY pyproject.toml uv.lock ./

RUN /usr/local/bin/uv sync --frozen --no-dev --no-install-project

COPY . .

RUN /usr/local/bin/uv sync --frozen --no-dev

CMD ["/usr/local/bin/uv", "run", "python", "-m", "aegis.core.engine"]