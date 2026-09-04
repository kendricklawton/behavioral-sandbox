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
//!
//! It also finds **libkrunfw**, which is a different problem: libkrun loads its kernel payload with
//! `dlopen("libkrunfw.5.dylib")`, a bare name, so the dynamic loader searches its own paths and
//! never the linker's. There is no `libkrunfw.pc` to ask, and libkrun's own `-L` need not hold it
//! (Homebrew gives each formula its own prefix; Arch puts both in `/usr/lib`). So it is searched
//! for by name, and the directory is baked in for `bsx-supervisor` to put on the helper's
//! `DYLD_FALLBACK_LIBRARY_PATH`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(krun_linked)");
    println!("cargo::rerun-if-env-changed=BSX_KRUN_LIB_DIR");
    println!("cargo::rerun-if-env-changed=BSX_KRUNFW_LIB_DIR");

    if let Some(dir) = std::env::var_os("BSX_KRUN_LIB_DIR") {
        // An override is trusted: a wrong path should fail at link, not be probed into a skip.
        println!("cargo::rustc-link-search=native={}", dir.to_string_lossy());
        emit_link();
        emit_krunfw_dir(&[PathBuf::from(dir)]);
        return;
    }

    match Command::new("pkg-config")
        .args(["--libs", "libkrun"])
        .output()
    {
        Ok(out) if out.status.success() => {
            let mut searched = Vec::new();
            for token in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                if let Some(dir) = token.strip_prefix("-L") {
                    println!("cargo::rustc-link-search=native={dir}");
                    searched.push(PathBuf::from(dir));
                }
            }
            emit_link();
            emit_krunfw_dir(&searched);
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

/// Bakes in the directory holding libkrunfw, for the platforms whose loader will not find it.
///
/// Only macOS needs this: its `dlopen` of a bare name searches `DYLD_*` and `/usr/lib`, where
/// Homebrew installs to a prefix of its own. On Linux `libkrunfw.so` sits in the default loader
/// path beside libkrun, so nothing is emitted and the helper is spawned with no such variable.
fn emit_krunfw_dir(near: &[PathBuf]) {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    if let Some(dir) = std::env::var_os("BSX_KRUNFW_LIB_DIR") {
        println!("cargo::rustc-env=BSX_KRUNFW_DIR={}", dir.to_string_lossy());
        return;
    }
    match near.iter().find_map(|dir| find_krunfw(dir)) {
        Some(found) => println!("cargo::rustc-env=BSX_KRUNFW_DIR={}", found.display()),
        None => println!(
            "cargo::warning=libkrunfw not found near libkrun. A sandbox will fail to boot with \
             \"Couldn't find or load libkrunfw\": set BSX_KRUNFW_LIB_DIR to the directory holding \
             it."
        ),
    }
}

/// The directory holding a `libkrunfw*.dylib`: `from` itself, else the `lib` of an ancestor.
///
/// The ancestor walk is what finds a Homebrew install, where libkrun resolves to its own
/// `<prefix>/Cellar/libkrun/<version>/lib` while libkrunfw is reachable as `<prefix>/lib`. It asks
/// whether the file is there rather than assuming a layout, so a prefix nobody anticipated is
/// found and one that does not exist is not guessed at.
fn find_krunfw(from: &Path) -> Option<PathBuf> {
    std::iter::once(from.to_path_buf())
        .chain(from.ancestors().map(|a| a.join("lib")))
        .find(|dir| holds_krunfw(dir))
}

/// Whether `dir` holds a file named `libkrunfw*.dylib`.
fn holds_krunfw(dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.starts_with("libkrunfw") && name.ends_with(".dylib")
    })
}
