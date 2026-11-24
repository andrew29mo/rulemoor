FROM python:3.15.2-slim-bookworm@sha256:96599df822d0e1c6bb700014a05c7f3c8cabc6e0f7ff3c4f9f69cee033b4b5d9
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY rulemoor rulemoor
COPY tests tests
COPY tools tools
COPY deploy deploy
COPY pyproject.toml Dockerfile ./
CMD ["python", "-m", "tools.linux_validate"]
