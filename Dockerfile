# Use a Linux base image (Ubuntu is a common choice for eBPF dev)
FROM ubuntu:22.04

# Set up environment variables for non-interactive install
ENV DEBIAN_FRONTEND=noninteractive

# Install essential build tools and eBPF dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    git \
    iproute2 \
    sudo \
    # Clean up to reduce image size
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# (Optional, but recommended) Install Go if you're using a Go user-space library (like cilium/ebpf)
# You can customize this with your preferred language/toolchain (e.g., Python, Rust)
RUN apt-get update && \
    apt-get install -y golang-go \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add a non-root user (optional, but good practice)
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd -s /bin/bash --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

# Set the default user and working directory
USER $USERNAME
WORKDIR /home/$USERNAME/workspace
