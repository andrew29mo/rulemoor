FROM python:3.15.0-slim-bookworm@sha256:2a41267d9de9d358f77a1de356e0f16ecba8d39827855be0ce9ef4792edce402
RUN apt-get update && apt-get install -y --no-install-recommends nftables iproute2 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY rulemoor rulemoor
COPY tests tests
COPY tools tools
COPY deploy deploy
COPY pyproject.toml Dockerfile ./
CMD ["python", "-m", "tools.linux_validate"]
