# Development environment
Install deps (Ubuntu 24.04):
```bash
sudo apt-get install -y git build-essential clang llvm \
libelf-dev libssl-dev \
zlib1g-dev libzstd-dev pkg-config libcap-dev \
binutils-multiarch-dev curl
```

# vmlinux.h generation notes

This workspace contains a `vmlinux.h` header generated from the running kernel's BTF.

How it was fixed:

- The error `failed to load BTF from /sys/kernel/btf/vmlinux: Invalid argument` occurred because the system `bpftool` (v5.15.x) was too old to parse the kernel 6.10 BTF types.
- We built a newer `bpftool` from the Linux v6.10 sources, which uses a recent libbpf with support for new BTF kinds.

Steps to regenerate:

1. Build bpftool from kernel tools:
   ```bash
   git clone --depth=1 --branch v6.10 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git /tmp/linux
   make -C /tmp/linux/tools/bpf/bpftool -j$(nproc)
   sudo make install -C /tmp/linux/tools/bpf/bpftool
   ```
3. Generate header:
   ```bash
   /usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
   ```

Tip: You can also use `/usr/local/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux > vmlinux.json` if you want to inspect raw BTF in JSON form.

bpftool version used during this run:

- `/usr/local/sbin/bpftool -V` => v7.5.0, libbpf v1.5
