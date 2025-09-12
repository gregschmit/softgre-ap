FROM alpine:latest

WORKDIR /app
COPY . .

RUN apk add --no-cache \
    git \
    vim \
    build-base \
    gdb \
    linux-headers \
    clang \
    libbpf-dev \
    zlib-static \
    zstd-static

CMD ["/bin/sh"]
