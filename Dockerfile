FROM alpine:latest

RUN apk update && apk upgrade
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

WORKDIR /app
COPY . .

CMD ["/bin/sh"]
