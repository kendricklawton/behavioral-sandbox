//! Fuzz the `.bsx.toml` configuration file parser and operator policy builder.
//! The engine parses `.bsx.toml` walking up from cwd, so hostile TOML contents must
//! always yield a typed deserialization/validation error, never panic.

#![no_main]

use bsx::config::BsxToml;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(config) = toml::from_str::<BsxToml>(s)
    {
        let policy = config.policy();
        let _ = policy.resolve(&bsx::policy::Requested::default());
    }
});
