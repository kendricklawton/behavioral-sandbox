//! The `bsx` binary's library target, and deliberately empty by default: the CLI's internals are
//! not public API, so a git pin of this package reaches the `bsx` binary and nothing else. The
//! `fuzzing` feature exposes the items the harness in `fuzz/` drives, the same pattern
//! `bsx-channel` uses for its fuzz entry points. The binary compiles the same files as its own
//! modules.
//!
//! Nothing here is exposed today: the `.bsx.toml` layering and the egress grammar the harness used
//! to fuzz went with the engine that gave them their keys, and phase 3 writes their successors
//! against the libkrun surface.
#![forbid(unsafe_code)]
