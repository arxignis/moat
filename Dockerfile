ARG IMAGE="debian"
ARG IMAGE_TAG="13"

FROM ${IMAGE}:${IMAGE_TAG} AS builder

RUN apt-get update && apt-get install -y git build-essential clang llvm libelf-dev libssl-dev \
    zlib1g-dev libzstd-dev pkg-config libcap-dev binutils-multiarch-dev curl cmake ca-certificates libelf-dev libelf1 libssl3

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
  . "$HOME/.cargo/env"  && \
  rustup default stable && \
  rustup update stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

COPY . .

RUN cargo build --release

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /app/target/release/synapse /usr/local/bin/synapse
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/lib/*/libelf.so.1 /usr/lib/
COPY --from=builder /usr/lib/*/libzstd.so.1 /usr/lib/

ENTRYPOINT ["/usr/local/bin/synapse"]
