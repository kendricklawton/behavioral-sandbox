//! Fuzz the `.bsx.toml` configuration file parser, the operator policy builder, and the narrowing
//! that decides what a project-local file may carry.
//!
//! Two attacker-facing steps, not one. A file found walking up from the cwd can arrive with the code
//! it configures, so hostile TOML contents must always yield a typed deserialization/validation
//! error, never a panic, and `project_from` must either refuse such a file or hand back one holding
//! none of the keys that reach a host binary, a key, or a jail id.

#![no_main]

use bsx::config::{UserConfig, project_from};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(config) = toml::from_str::<UserConfig>(s)
    {
        let policy = config.policy();
        let _ = policy.resolve(&bsx::policy::Requested::default());

        // The narrowing a project-local file goes through. Either it names user-only keys and is
        // refused, or what survives carries only knobs, ceilings, and postures.
        if let Ok(project) = project_from(config) {
            let _ = project.marker();
            let _ = project.log();
            let _ = project.require_limits();
            let _ = project.policy().resolve(&bsx::policy::Requested::default());
        }
    }
});
