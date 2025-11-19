// build.rs
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/filter.bpf.c";
const HEADER_DIR: &str = "src/bpf";

fn main() {
    println!("cargo:rerun-if-changed={}", SRC);
    println!("cargo:rerun-if-changed={}/filter.h", HEADER_DIR);

    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH must be set");

    let vmlinux_include = vmlinux::include_path_root().join(arch);
    assert!(Path::new(&vmlinux_include).exists(), "vmlinux.h not found");

    let bpf_include = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set")).join(HEADER_DIR);

    // ✅ Construct full output path in OUT_DIR
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));
    let skel_path = out_dir.join("filter.skel.rs");

    // ✅ Pass the full path to build_and_generate
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            vmlinux_include.as_os_str(),
            OsStr::new("-I"),
            bpf_include.as_os_str(),
            OsStr::new("-O2"),              // Enable level 2 optimizations
            OsStr::new("-g"),               // Keep debug info for verifier
            OsStr::new("-Wall"),            // Enable all warnings
            OsStr::new("-Wextra"),          // Extra warnings
        ])
        .build_and_generate(skel_path.to_str().expect("Invalid UTF-8 in path"))
        .expect("Failed to generate skeleton");

    println!("✅ Wrote skeleton to: {:?}", skel_path);
}
