//! A safe wrapper over libkrun: a builder that puts the library's call-ordering rules in the type
//! system, and turns its negative-errno returns into a typed [`Error`].
//!
//! **This is the one crate in the workspace that may use `unsafe`**, because libkrun is a C
//! library. `every_crate_forbids_unsafe` in the gate asserts the exempt list *equals* this crate, so
//! neither a second one nor the loss of this one passes quietly. The raw declarations live in a
//! private `sys` module rather than a separate `-sys` package, which makes the API below the only
//! way to reach libkrun instead of merely the recommended one.
//!
//! # What the types enforce
//!
//! - **A context is freed exactly once.** [`Context`] and [`Machine`] own the id and free it on
//!   drop, including on the error path out of [`Machine::enter`].
//! - **`disable_implicit_init` comes before the root is set.** The header requires it; here it
//!   exists only on [`Context`], and [`Context::root`] consumes `self` to produce a [`Machine`], so
//!   the wrong order does not compile.
//! - **`krun_start_enter` never returns.** [`Machine::enter`] returns [`Error`] and nothing else:
//!   if it returns at all, it failed. That is the fact the whole process topology rests on, stated
//!   where a caller cannot miss it rather than in a comment.
//!
//! # What it deliberately does not do
//!
//! No stop path. `krun_get_shutdown_eventfd` is efi-only and returns `-ENOTSUP` against a stock
//! libkrun, and what stops a running VM is a signal to the helper process (`bsx-supervisor`'s
//! `Vm::stop`), so there is nothing of libkrun's to wrap. Network and rlimits are phase 3's;
//! their declarations are already in `sys`.
//!
//! # Strings
//!
//! Every `CString` handed to libkrun is **retained in the builder until the VM starts**. The header
//! documents non-copying where it applies (`krun_fs_add_overlay_file` says so explicitly) and says
//! nothing either way for the setters used here. Owning them costs a pointer-sized allocation per
//! call and removes the question; betting on a copy that is not documented would be a dangling
//! pointer if the bet is wrong.

mod sys;

use std::ffi::{CString, NulError, OsStr};
use std::fmt;
use std::marker::PhantomData;
use std::num::{NonZeroU8, NonZeroU32};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub use sys::{
    KRUN_FEATURE_BLK, KRUN_FEATURE_EFI, KRUN_FEATURE_GPU, KRUN_FEATURE_INPUT, KRUN_FEATURE_NET,
    KRUN_FEATURE_SND, KRUN_FS_ROOT_TAG,
};

/// A libkrun call that failed, or an argument libkrun could not have been given.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A libkrun call returned a negative errno, carried here as the `io::Error` it names.
    Call {
        /// The `krun_*` function that failed, so a message names the call rather than the wrapper.
        call: &'static str,
        /// The errno libkrun returned, negated back into positive form.
        source: std::io::Error,
    },
    /// A path or string the caller passed contains an interior NUL, so it cannot cross into C.
    /// Rejected here rather than truncated, because a truncated path names a different file.
    InteriorNul {
        /// Which argument, so the caller knows which of several strings was rejected.
        what: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call { call, source } => write!(f, "{call} failed: {source}"),
            Self::InteriorNul { what } => {
                write!(
                    f,
                    "{what} contains an interior NUL byte and cannot be passed to libkrun"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Call { source, .. } => Some(source),
            Self::InteriorNul { .. } => None,
        }
    }
}

/// Turns libkrun's `int32_t` into a `Result`. Negative is a **negated errno**, so the sign is
/// flipped back before `io::Error` sees it; zero and positive are both success, since several calls
/// return a value (a context id, a feature answer) rather than only a status.
fn check(call: &'static str, rc: i32) -> Result<i32, Error> {
    if rc < 0 {
        Err(Error::Call {
            call,
            source: std::io::Error::from_raw_os_error(-rc),
        })
    } else {
        Ok(rc)
    }
}

/// A path as a `CString`, or [`Error::InteriorNul`] naming which argument was rejected.
fn c_path(what: &'static str, path: &Path) -> Result<CString, Error> {
    c_bytes(what, path.as_os_str())
}

/// See [`c_path`]. Split out because tags and argv entries are strings rather than paths.
fn c_bytes(what: &'static str, s: &OsStr) -> Result<CString, Error> {
    CString::new(s.as_bytes()).map_err(|_: NulError| Error::InteriorNul { what })
}

/// The context id, freed on drop.
///
/// `PhantomData<*const ()>` makes every handle `!Send` and `!Sync`. libkrun documents no
/// thread-safety for its context table, and an FFI handle whose threading rules are unstated is one
/// a caller should not be able to move across threads by accident. The helper process that calls
/// [`Machine::enter`] does so on the thread that built the context, which is all this project needs.
struct Ctx {
    id: u32,
    _not_send: PhantomData<*const ()>,
}

impl Drop for Ctx {
    fn drop(&mut self) {
        // Nothing useful to do with a failure here: the process is either about to exit or has
        // already reported the error that got us here, and a panic in `drop` would replace a
        // legible error with an abort.
        let _ = unsafe { sys::krun_free_ctx(self.id) };
    }
}

/// A fresh configuration context, before a root filesystem is chosen.
///
/// The stage exists so `disable_implicit_init` cannot be called too late: the header requires it
/// before `krun_set_root`, and [`root`](Self::root) consumes `self`.
pub struct Context {
    ctx: Ctx,
    retained: Vec<CString>,
}

impl Context {
    /// Creates a configuration context.
    pub fn new() -> Result<Self, Error> {
        let id = check("krun_create_ctx", unsafe { sys::krun_create_ctx() })?;
        Ok(Self {
            // A successful `krun_create_ctx` returns the id as a non-negative `i32`, so this cast
            // cannot wrap: `check` has already rejected everything below zero.
            ctx: Ctx {
                id: id as u32,
                _not_send: PhantomData,
            },
            retained: Vec::new(),
        })
    }

    /// Stops libkrun injecting its default `/init.krun` into the root filesystem.
    ///
    /// Only available before the root is set, which is the header's requirement made structural.
    pub fn disable_implicit_init(self) -> Result<Self, Error> {
        check("krun_disable_implicit_init", unsafe {
            sys::krun_disable_implicit_init(self.ctx.id)
        })?;
        Ok(self)
    }

    /// Serves `path`, a host directory, as the guest's root over virtiofs, and moves on to the
    /// stage where the rest of the machine is configured.
    pub fn root(mut self, path: &Path) -> Result<Machine, Error> {
        let c = c_path("the root path", path)?;
        check("krun_set_root", unsafe {
            sys::krun_set_root(self.ctx.id, c.as_ptr())
        })?;
        self.retained.push(c);
        Ok(Machine {
            ctx: self.ctx,
            retained: std::mem::take(&mut self.retained),
        })
    }
}

/// A context with a root filesystem, being configured toward [`enter`](Self::enter).
pub struct Machine {
    ctx: Ctx,
    retained: Vec<CString>,
}

impl Machine {
    /// Sets the vCPU count and RAM. Non-zero by type: libkrun rejects a zero either way, and a
    /// caller that has to handle that error has learned nothing the type could not have told it.
    pub fn vm_config(self, vcpus: NonZeroU8, ram_mib: NonZeroU32) -> Result<Self, Error> {
        check("krun_set_vm_config", unsafe {
            sys::krun_set_vm_config(self.ctx.id, vcpus.get(), ram_mib.get())
        })?;
        Ok(self)
    }

    /// Shares a host directory into the guest under `tag`, in addition to the root.
    pub fn share(mut self, tag: &str, path: &Path) -> Result<Self, Error> {
        let c_tag = c_bytes("a virtiofs tag", OsStr::new(tag))?;
        let c_dir = c_path("a shared directory", path)?;
        check("krun_add_virtiofs", unsafe {
            sys::krun_add_virtiofs(self.ctx.id, c_tag.as_ptr(), c_dir.as_ptr())
        })?;
        self.retained.push(c_tag);
        self.retained.push(c_dir);
        Ok(self)
    }

    /// Maps a guest vsock port onto a host unix socket. `listen` chooses which side binds.
    pub fn vsock_port(mut self, port: u32, socket: &Path, listen: bool) -> Result<Self, Error> {
        let c = c_path("a vsock socket path", socket)?;
        check("krun_add_vsock_port2", unsafe {
            sys::krun_add_vsock_port2(self.ctx.id, port, c.as_ptr(), listen)
        })?;
        self.retained.push(c);
        Ok(self)
    }

    /// Sets the guest working directory.
    pub fn workdir(mut self, path: &Path) -> Result<Self, Error> {
        let c = c_path("the working directory", path)?;
        check("krun_set_workdir", unsafe {
            sys::krun_set_workdir(self.ctx.id, c.as_ptr())
        })?;
        self.retained.push(c);
        Ok(self)
    }

    /// Sets the guest executable, its arguments, and its environment.
    ///
    /// `argv` is the arguments **after** the program name, matching how libkrun reads it. `env`
    /// entries are `KEY=VALUE`; neither array may contain an interior NUL, which is refused rather
    /// than truncated.
    pub fn exec(mut self, program: &Path, argv: &[&OsStr], env: &[&OsStr]) -> Result<Self, Error> {
        let c_prog = c_path("the guest program", program)?;
        let mut argv_c = Vec::with_capacity(argv.len());
        for a in argv {
            argv_c.push(c_bytes("a guest argument", a)?);
        }
        let mut env_c = Vec::with_capacity(env.len());
        for e in env {
            env_c.push(c_bytes("a guest environment entry", e)?);
        }
        // Both arrays are NULL-terminated, which is the contract the header states and not
        // something libkrun infers from a length.
        let argv_ptrs = null_terminated(&argv_c);
        let env_ptrs = null_terminated(&env_c);
        check("krun_set_exec", unsafe {
            sys::krun_set_exec(
                self.ctx.id,
                c_prog.as_ptr(),
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            )
        })?;
        self.retained.push(c_prog);
        self.retained.extend(argv_c);
        self.retained.extend(env_c);
        Ok(self)
    }

    /// Starts the microVM, **and does not return.**
    ///
    /// libkrun takes over the calling process and exits with the guest's status, so the only way
    /// this function returns is failure, which is why it returns [`Error`] rather than a `Result`.
    /// A caller cannot write code after a successful start, because there is no "after": this is
    /// the fact that makes every VM a helper process rather than a thread.
    ///
    /// The context is freed on the way out of the failure path, since `self` is consumed here.
    pub fn enter(self) -> Error {
        match check("krun_start_enter", unsafe {
            sys::krun_start_enter(self.ctx.id)
        }) {
            Err(e) => e,
            // libkrun returned a success code from a call that is documented never to return. That
            // is not something to paper over with an `unreachable!`: report it as the library
            // behaving other than its contract, and let the caller exit.
            Ok(rc) => Error::Call {
                call: "krun_start_enter",
                source: std::io::Error::other(format!(
                    "returned {rc} instead of taking over the process"
                )),
            },
        }
    }
}

/// A NULL-terminated pointer array over `items`, for the C arrays libkrun expects.
///
/// The pointers borrow `items`, so the returned vector must not outlive it. Both callers keep the
/// `CString`s alive for the whole call and then move them into the builder.
fn null_terminated(items: &[CString]) -> Vec<*const c_char> {
    let mut ptrs: Vec<*const c_char> = items.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    ptrs
}

/// Whether this libkrun build carries a `KRUN_FEATURE_*` capability.
///
/// A probe, never a version compare: which features a build has depends on how it was compiled.
/// An unknown constant is `-EINVAL` from an older library, which surfaces as an error rather than
/// as a silent `false`, so "this libkrun is too old to be asked" is distinguishable from "no".
pub fn has_feature(feature: u64) -> Result<bool, Error> {
    Ok(check("krun_has_feature", unsafe {
        sys::krun_has_feature(feature)
    })? == 1)
}

/// The hypervisor's vCPU ceiling on this host.
pub fn max_vcpus() -> Result<u32, Error> {
    // Non-negative by `check`, so the cast cannot wrap.
    check("krun_get_max_vcpus", unsafe { sys::krun_get_max_vcpus() }).map(|n| n as u32)
}

/// Whether this host can nest virtualization. `1` is yes and `0` is no, per the header.
pub fn nested_virt_supported() -> Result<bool, Error> {
    Ok(check("krun_check_nested_virt", unsafe {
        sys::krun_check_nested_virt()
    })? == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `check` is the whole of the error mapping, and its sign convention is the part that is easy
    /// to get backwards: libkrun returns a *negated* errno, so `-2` is `ENOENT` and not errno 2's
    /// negation being passed through to `io::Error` as-is.
    #[test]
    fn a_negative_return_is_read_as_a_negated_errno() {
        let err = check("krun_test", -2).expect_err("a negative return is a failure");
        assert!(
            matches!(&err, Error::Call { call, source }
                if *call == "krun_test"
                    && source.raw_os_error() == Some(2)
                    && source.kind() == std::io::ErrorKind::NotFound),
            "-2 is ENOENT named against its call, got {err:?}"
        );
    }

    /// Zero and positive are both success. Several calls return a value rather than a status, and a
    /// wrapper that treated non-zero as failure would refuse every context id libkrun ever issued.
    #[test]
    fn zero_and_positive_are_both_success() {
        assert_eq!(check("krun_test", 0).expect("zero is success"), 0);
        assert_eq!(check("krun_test", 7).expect("positive is success"), 7);
    }

    /// A path with an interior NUL is refused rather than silently truncated at the NUL, which
    /// would hand libkrun a different path from the one the caller asked for.
    #[test]
    fn an_interior_nul_is_refused_rather_than_truncated() {
        let path = Path::new(OsStr::from_bytes(b"/tmp/good\0/evil"));
        let err = c_path("the root path", path).expect_err("an interior NUL cannot cross into C");
        assert!(
            matches!(&err, Error::InteriorNul { what } if *what == "the root path"),
            "an interior NUL must be refused and name its argument, got {err:?}"
        );
    }

    /// The C arrays libkrun reads are NULL-terminated, not length-carrying, so the terminator is
    /// load-bearing: without it libkrun walks off the end of the array.
    #[test]
    fn a_pointer_array_carries_its_null_terminator() {
        let items = vec![
            CString::new("one").expect("no interior NUL"),
            CString::new("two").expect("no interior NUL"),
        ];
        let ptrs = null_terminated(&items);
        assert_eq!(ptrs.len(), items.len() + 1);
        assert!(ptrs[..items.len()].iter().all(|p| !p.is_null()));
        assert!(ptrs[items.len()].is_null(), "the array must end in NULL");
        assert!(
            null_terminated(&[])[0].is_null(),
            "an empty array is just NULL"
        );
    }

    /// An error has to name the call that failed, or a supervisor log says only that "libkrun
    /// failed" for any of twenty-seven functions.
    #[test]
    fn the_message_names_the_call_and_the_errno() {
        let msg = check("krun_set_root", -13)
            .expect_err("a negative return is a failure")
            .to_string();
        assert!(msg.contains("krun_set_root"), "{msg}");
        // Case-insensitive: the wording comes from the platform's `strerror`, and macOS and glibc
        // do not agree on capitalisation. What is being pinned is that the errno reached the
        // message at all, not how libc spells it.
        assert!(msg.to_lowercase().contains("permission denied"), "{msg}");
    }

    /// The handles are `!Send` by construction, so a context cannot be built on one thread and
    /// entered on another. libkrun documents no thread-safety for its context table, and an FFI
    /// handle whose threading rules are unstated should not be movable across threads by accident.
    ///
    /// A negative bound cannot be written in a where-clause, so this uses the stable
    /// inherent-method-beats-trait-method trick, and checks the probe against a known-`Send` type
    /// and a known-`!Send` one in the same test: a probe that answered `false` for everything would
    /// pass this assertion while proving nothing, which is exactly how the first version of this
    /// test was wrong.
    #[test]
    fn a_context_cannot_cross_threads() {
        assert!(
            SendProbe::<u32>::new().is_send(),
            "the probe must see a Send type"
        );
        assert!(
            !SendProbe::<*const ()>::new().is_send(),
            "the probe must see a !Send type, or it proves nothing below"
        );
        assert!(
            !SendProbe::<Ctx>::new().is_send(),
            "Ctx must stay thread-bound"
        );
        assert!(
            !SendProbe::<Context>::new().is_send(),
            "Context must stay thread-bound"
        );
        assert!(
            !SendProbe::<Machine>::new().is_send(),
            "Machine must stay thread-bound"
        );
    }

    struct SendProbe<T>(PhantomData<T>);

    impl<T> SendProbe<T> {
        fn new() -> Self {
            Self(PhantomData)
        }
    }

    /// The fallback: reached only when `T: Send` does not hold, because an inherent method wins
    /// method resolution over a trait method when both apply.
    trait NotSend {
        fn is_send(&self) -> bool {
            false
        }
    }

    impl<T> NotSend for SendProbe<T> {}

    impl<T: Send> SendProbe<T> {
        fn is_send(&self) -> bool {
            true
        }
    }
}
