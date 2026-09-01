//! Emits the link directive for libkrun, and only when the library is actually present.
//!
//! **An absent libkrun is not a build failure anywhere in the workspace.** The host-safe gate runs
//! on machines with no hypervisor stack at all, and an undefined symbol fails an executable's link
//! even when the call is unreachable. So an absent library leaves the link directive unemitted and
//! `sys` compiles stub twins instead: every call then reports the library as missing through a
//! typed error, and this crate's own tests that touch the library are compiled out
//! (`cfg(krun_linked)`) with a printed reason.
//!
//! `pkg-config` is shelled rather than taken as a build dependency: one probe on one platform does
//! not earn a crate, and the fallback is the plain `-l krun` any linker already understands.

use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(krun_linked)");
    println!("cargo::rerun-if-env-changed=BSX_KRUN_LIB_DIR");

    if let Some(dir) = std::env::var_os("BSX_KRUN_LIB_DIR") {
        // An explicit override wins and is trusted: the operator naming a directory is asserting
        // the library is there, so a wrong path should fail loudly at link rather than be probed
        // away into a silent skip.
        println!("cargo::rustc-link-search=native={}", dir.to_string_lossy());
        emit_link();
        return;
    }

    match Command::new("pkg-config")
        .args(["--libs", "libkrun"])
        .output()
    {
        Ok(out) if out.status.success() => {
            for token in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                if let Some(dir) = token.strip_prefix("-L") {
                    println!("cargo::rustc-link-search=native={dir}");
                }
            }
            emit_link();
        }
        _ => println!(
            "cargo::warning=libkrun not found (no pkg-config entry). bsx-krun compiled its \
             declarations, but nothing can link them: install libkrun, or set BSX_KRUN_LIB_DIR."
        ),
    }
}

fn emit_link() {
    println!("cargo::rustc-link-lib=dylib=krun");
    println!("cargo::rustc-cfg=krun_linked");
}
