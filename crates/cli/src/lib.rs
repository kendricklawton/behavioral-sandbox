//! The `bsx` binary's library target, and deliberately empty by default: the CLI's internals are
//! not public API (`docs/embedding-scope.md` names the pinned surface, and this package is not on
//! it), so a git pin of this package reaches the `bsx` binary and nothing else. The one consumer
//! is the fuzz harness in `fuzz/`, which needs the attacker-facing parsers (the `.bsx.toml`
//! layering in `config`, the egress-rule grammar in `policy`) as library items; the off-by-default
//! `fuzzing` feature exposes exactly those, the same pattern `bsx-channel` and `bsx-protocol`
//! use for their fuzz entry points. The binary compiles the same files as its own modules.
#![forbid(unsafe_code)]

#[cfg(feature = "fuzzing")]
pub mod config;
#[cfg(feature = "fuzzing")]
pub mod policy;
// Private: `config`'s user-file read goes through it, but it is filesystem IO rather than a parser,
// so it is not part of what the harness drives.
#[cfg(feature = "fuzzing")]
mod trust;
