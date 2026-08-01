//! Fuzz the `.ekvm.toml` configuration file parser and operator policy builder.
//! The engine parses `.ekvm.toml` walking up from cwd, so hostile TOML contents must
//! always yield a typed deserialization/validation error, never panic.

#![no_main]

use ekvm_cli::config::EkvmToml;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(config) = toml::from_str::<EkvmToml>(s) {
            let policy = config.policy();
            let _ = policy.resolve(&ekvm_cli::policy::Requested::default());

        }
    }
});
