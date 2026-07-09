FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      cmake \
      gcc-mingw-w64-x86-64 \
      ninja-build && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
