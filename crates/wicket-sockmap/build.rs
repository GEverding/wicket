use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "linux" {
        #[cfg(target_os = "linux")]
        {
            use std::path::PathBuf;

            let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

            let src = format!("{}/bpf/sockmap.bpf.c", manifest_dir);
            let skel = out_dir.join("sockmap.skel.rs");

            libbpf_cargo::SkeletonBuilder::new()
                .source(&src)
                .clang_args([format!("-I{}/bpf", manifest_dir)])
                .build_and_generate(&skel)
                .expect("Failed to build sockmap BPF skeleton");

            println!("cargo:rerun-if-changed=bpf/sockmap.bpf.c");
            println!("cargo:rerun-if-changed=bpf/include/common.h");
            println!("cargo:rerun-if-changed=bpf/include/vmlinux.h");
        }
    }

    println!("cargo:rerun-if-changed=build.rs");
}
