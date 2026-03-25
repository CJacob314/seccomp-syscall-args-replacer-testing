use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h"); // Should only need to be rerun if the wrapper.h file
    // changes.

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_var("AUDIT_ARCH_X86_64")
        .allowlist_var("SYS_SECCOMP")
        .allowlist_var("SECCOMP_IOCTL_NOTIF_RECV")
        .allowlist_var("SECCOMP_IOCTL_NOTIF_SEND")
        .allowlist_type("siginfo_t") // The libc crate siginfo_t type is seemingly incomplete?
        .clang_arg("-D__USE_GNU") // Just in case
        .generate_comments(false)
        .generate()
        .expect("bindgen failed");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("could not write bindings");
}
