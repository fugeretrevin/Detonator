FROM node:20-slim
# curl/wget/nc are intentionally present so realistic payloads can run and be observed.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl wget netcat-openbsd git python3 \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 runner
USER runner
WORKDIR /work
