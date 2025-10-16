ARG IMAGE="ubuntu"
ARG IMAGE_TAG="24.04"

FROM ${IMAGE}:${IMAGE_TAG} AS builder

RUN apt-get update && apt-get install -y git build-essential clang llvm libelf-dev libssl-dev \
    zlib1g-dev libzstd-dev pkg-config libcap-dev binutils-multiarch-dev curl

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
  . "$HOME/.cargo/env"  && \
  rustup default stable && \
  rustup update stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

COPY moat/ .

RUN cargo build --release

FROM ${IMAGE}:${IMAGE_TAG}

USER root

RUN apt-get update && apt-get install -y libelf1 libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

# Add capabilities needed for BPF programs
# Note: This container needs to be run with --privileged or specific capabilities

COPY --from=builder /app/target/release/moat /usr/local/bin/moat

ENTRYPOINT ["/usr/local/bin/moat"]
