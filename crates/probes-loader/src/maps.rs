//! The shared aya-object plumbing: the map and program opens every surface runs, the toggle
//! write, and the per-cgroup map removal every teardown path runs, in one place.
//!
//! - **An absent key is the intended outcome, any other failure is not.** Teardown is idempotent:
//!   removing a cgroup that was never registered, or that a previous close already removed, must
//!   read as success. Every other syscall error (a permission or fd fault) must surface, because a
//!   removal that silently "succeeded" leaves the cgroup registered in the map while the caller
//!   believes it is gone, and the probes go on charging and emitting for it. The kernel recycles
//!   cgroup ids, so the next sandbox handed that id inherits the attribution in its signed record.

use aya::maps::{Array, HashMap as AyaHashMap, Map, MapData, MapError};
use aya::programs::Program;
use aya::{Ebpf, Pod};

use crate::ProbeError;

/// Open the named map read-only as `M`; `noun` names the expected shape in the error message,
/// article included ("an array", "a hash map").
pub(crate) fn open<'a, M>(ebpf: &'a Ebpf, name: &str, noun: &str) -> Result<M, ProbeError>
where
    M: TryFrom<&'a Map, Error = MapError>,
{
    let map = ebpf
        .map(name)
        .ok_or_else(|| ProbeError::Map(format!("map `{name}` not found")))?;
    M::try_from(map).map_err(|e| ProbeError::Map(format!("open `{name}` as {noun}: {e}")))
}

/// The writable twin of [`open`].
pub(crate) fn open_mut<'a, M>(ebpf: &'a mut Ebpf, name: &str, noun: &str) -> Result<M, ProbeError>
where
    M: TryFrom<&'a mut Map, Error = MapError>,
{
    let map = ebpf
        .map_mut(name)
        .ok_or_else(|| ProbeError::Map(format!("map `{name}` not found")))?;
    M::try_from(map).map_err(|e| ProbeError::Map(format!("open `{name}` as {noun}: {e}")))
}

/// Write `on` into `slot` of the named single-`u32` toggle array.
pub(crate) fn set_flag(ebpf: &mut Ebpf, name: &str, slot: u32, on: bool) -> Result<(), ProbeError> {
    let mut toggle: Array<_, u32> = open_mut(ebpf, name, "an array")?;
    toggle
        .set(slot, u32::from(on), 0)
        .map_err(|e| ProbeError::Map(format!("write `{name}`: {e}")))
}

/// Fetch the named program as `P`; `kind` names the expected program type in the error message.
pub(crate) fn program_mut<'a, P>(
    ebpf: &'a mut Ebpf,
    name: &str,
    kind: &str,
) -> Result<P, ProbeError>
where
    P: TryFrom<&'a mut Program>,
    <P as TryFrom<&'a mut Program>>::Error: std::fmt::Display,
{
    let program = ebpf
        .program_mut(name)
        .ok_or_else(|| ProbeError::Load(format!("program `{name}` not found in object")))?;
    P::try_from(program)
        .map_err(|e| ProbeError::Load(format!("program `{name}` is not a {kind}: {e}")))
}

/// Remove `cgroup_id` from a per-cgroup map, treating an absent key as success. `what` is the whole
/// phrase naming the removal, so each caller keeps its own message without this one guessing at it.
///
/// # Errors
/// [`ProbeError::Map`] for any failure other than the key already being gone.
pub(crate) fn remove_cgroup_key<V: Pod>(
    map: &mut AyaHashMap<&mut MapData, u64, V>,
    cgroup_id: u64,
    what: &str,
) -> Result<(), ProbeError> {
    match map.remove(&cgroup_id) {
        Ok(()) => Ok(()),
        Err(e) if is_absent_key(&e) => Ok(()),
        Err(e) => Err(ProbeError::Map(format!("{what}: {e}"))),
    }
}

/// Whether a map error is the kernel saying the key was not there (`ENOENT`).
///
/// Split out so the one clause that decides what gets swallowed is testable without a loaded eBPF
/// object: constructing the error takes no privilege, removing from a real map takes `CAP_BPF`.
fn is_absent_key(e: &MapError) -> bool {
    matches!(e, MapError::SyscallError(e) if e.io_error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syscall_err(kind: std::io::ErrorKind) -> MapError {
        MapError::SyscallError(aya::sys::SyscallError {
            call: "bpf_map_delete_elem",
            io_error: std::io::Error::from(kind),
        })
    }

    /// Only `ENOENT` is swallowed, and only from a syscall failure.
    ///
    /// The widening this guards against reads as a tidy-up (`Err(_) => Ok(())`), and its cost is a
    /// teardown that reports success while the cgroup stays registered.
    #[test]
    fn an_absent_key_is_the_only_failure_a_removal_treats_as_success() {
        assert!(is_absent_key(&syscall_err(std::io::ErrorKind::NotFound)));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::Other,
        ] {
            assert!(
                !is_absent_key(&syscall_err(kind)),
                "{kind:?} is a real failure and must surface"
            );
        }
        // A non-syscall variant is never the absent-key case, whatever it says.
        assert!(!is_absent_key(&MapError::KeyNotFound));
    }
}
