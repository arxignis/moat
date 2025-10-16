🌋 The Legend of Arxignis and the Moat

In the age of digital kingdoms, where empires rise and fall at the speed of code, there stands a fortress unlike any other — Arxignis, the Citadel of Fire.

Forged from lines of code and tempered by the flames of countless cyber battles, Arxignis was built for one purpose: to protect your realm.

But no fortress stands alone.

Surrounding Arxignis is Moat — not water, but an invisible, intelligent barrier that shifts and shimmers like living magic. It sees threats before they even know they exist. When invaders approach — bot armies, malicious payloads, or the darkest zero-day beasts — Moat awakens.

With a whisper of algorithmic incantation, it analyzes intent, bends logic, and casts away the unworthy.

Attackers see nothing but endless reflection — their own attacks bouncing back into the void. To them, it’s as if your citadel never existed. To you, it’s silent peace behind walls of flame and light.

Because this is your Citadel, your Arx, your Ignis.
And with Moat, the fire never reaches your gates. 🔥

![Story](./images/story.png)

# vmlinux.h generation notes

This workspace contains a `vmlinux.h` header generated from the running kernel's BTF.

How it was fixed:

- The error `failed to load BTF from /sys/kernel/btf/vmlinux: Invalid argument` occurred because the system `bpftool` (v5.15.x) was too old to parse the kernel 6.10 BTF types.
- We built a newer `bpftool` from the Linux v6.10 sources, which uses a recent libbpf with support for new BTF kinds.

Steps to regenerate:

1. Install deps (Ubuntu 24.04):
   ```bash
   sudo apt-get install -y git build-essential clang llvm libelf-dev libssl-dev \
    zlib1g-dev libzstd-dev pkg-config libcap-dev binutils-multiarch-dev
   ```
2. Build bpftool from kernel tools:
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
