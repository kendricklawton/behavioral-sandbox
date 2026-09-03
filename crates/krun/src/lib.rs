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
//! `Vm::stop`), so there is nothing of libkrun's to wrap.
//!
//! No accelerated GPU. [`Machine::gpu_device`] enables virtio-gpu with the one virglrenderer flag
//! set measured to carry a frame, because a display needs the device; a posture that lets the
//! guest use the host GPU for its own rendering is phase 5's, behind `krun_has_feature`.
//!
//! # Strings
//!
//! Every `CString` handed to libkrun is **retained in the builder until the VM starts**. The header
//! documents non-copying where it applies (`krun_fs_add_overlay_file` says so explicitly) and says
//! nothing either way for the setters used here. Owning them costs a pointer-sized allocation per
//! call and removes the question; betting on a copy that is not documented would be a dangling
//! pointer if the bet is wrong.
//!
//! # The display vtable
//!
//! [`Machine::display_backend`] hands libkrun a table of C callbacks that call back into a
//! [`DisplayBackend`], from libkrun's gpu thread, for as long as the VM runs.
//!
//! - **A panic must not unwind into libkrun.** Every callback runs the backend under
//!   `catch_unwind` and reports a panic as `KRUN_DISPLAY_ERR_INTERNAL`.
//! - **The backend is shared, not moved.** It lives behind a lock the callbacks take, so a
//!   compositor reading the latest frame holds libkrun off for exactly as long as it reads.
//! - **libkrun writes into a buffer after the call that handed it out has returned**, which no
//!   borrow can say: [`DisplayBackend`] is an `unsafe trait` for that one obligation.
//! - **A frame has crossed it.** Measured 2026-09-02: a guest drawing through a DRM dumb buffer
//!   arrives as `configure_scanout` (B8G8R8X8) and a `present_frame` per flush, pixels intact
//!   (`a_frame_the_guest_draws_reaches_the_host` in `crates/cli/tests/e2e.rs`).
//!
//! # The input tables
//!
//! [`Machine::input_device`] hands libkrun two more tables: one answering the identity queries
//! the guest's virtio-input driver makes at probe, one handing over queued events. The same rules
//! hold (panics caught, instances shared by count), and the provider is a queue behind an eventfd
//! that is readable exactly while an event waits, because libkrun polls the fd level-triggered
//! and never reads it: a fd left armed on an empty queue is a worker thread spinning.

mod sys;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{CString, NulError, OsStr};
use std::fmt;
use std::marker::PhantomData;
use std::num::{NonZeroI32, NonZeroU8, NonZeroU32, NonZeroUsize};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub use sys::{
    KRUN_DISPLAY_ERR_INTERNAL, KRUN_DISPLAY_ERR_INVALID_PARAM, KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID,
    KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED, KRUN_DISPLAY_ERR_OUT_OF_BUFFERS,
    KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER, KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM,
    KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM, KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM,
    KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM, KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM,
    KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM, KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM,
    KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM, KRUN_FEATURE_BLK, KRUN_FEATURE_EFI, KRUN_FEATURE_GPU,
    KRUN_FEATURE_INPUT, KRUN_FEATURE_NET, KRUN_FEATURE_SND, KRUN_FS_ROOT_TAG, KRUN_TSI_HIJACK_INET,
    KRUN_TSI_HIJACK_UNIX,
};

/// A libkrun call that failed, or an argument libkrun could not have been given.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A libkrun call returned a negative errno, or a host call a device needs failed, carried
    /// here as the `io::Error` it names.
    Call {
        /// The function that failed, so a message names the call rather than the wrapper.
        call: &'static str,
        /// The errno, in positive form.
        source: std::io::Error,
    },
    /// A path or string the caller passed contains an interior NUL, so it cannot cross into C.
    /// Rejected here rather than truncated, because a truncated path names a different file.
    InteriorNul {
        /// Which argument, so the caller knows which of several strings was rejected.
        what: &'static str,
    },
    /// This build links no libkrun: `build.rs` found none, so every call is a stub that reports
    /// the library as missing rather than an errno a stub would have had to invent.
    NotLinked {
        /// The `krun_*` function that was asked for.
        call: &'static str,
    },
    /// A value libkrun's tables cannot carry, refused before the call that would have carried it.
    OutOfRange {
        /// Which value.
        what: &'static str,
        /// The value given.
        value: u32,
        /// The largest the table holds.
        max: u32,
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
            Self::NotLinked { call } => write!(
                f,
                "{call} cannot be called: this build links no libkrun (install libkrun, or set \
                 BSX_KRUN_LIB_DIR, and rebuild)"
            ),
            Self::OutOfRange { what, value, max } => {
                write!(
                    f,
                    "{what} is {value}, above the {max} libkrun's tables can hold"
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Call { source, .. } => Some(source),
            Self::InteriorNul { .. } | Self::NotLinked { .. } | Self::OutOfRange { .. } => None,
        }
    }
}

/// Turns libkrun's `int32_t` into a `Result`. Negative is a **negated errno**, so the sign is
/// flipped back before `io::Error` sees it; zero and positive are both success, since several calls
/// return a value (a context id, a feature answer) rather than only a status.
fn check(call: &'static str, rc: i32) -> Result<i32, Error> {
    if rc < 0 {
        Err(call_failed(call, rc))
    } else {
        Ok(rc)
    }
}

#[cfg(krun_linked)]
fn call_failed(call: &'static str, rc: i32) -> Error {
    Error::Call {
        call,
        source: std::io::Error::from_raw_os_error(-rc),
    }
}

/// In a build with no libkrun every call is a stub, so the one truthful failure is "the library
/// is not here", not whichever value the stub returned.
#[cfg(not(krun_linked))]
fn call_failed(call: &'static str, _rc: i32) -> Error {
    Error::NotLinked { call }
}

/// A path as a `CString`, or [`Error::InteriorNul`] naming which argument was rejected.
fn c_path(what: &'static str, path: &Path) -> Result<CString, Error> {
    c_bytes(what, path.as_os_str())
}

/// See [`c_path`]. Split out because tags and argv entries are strings rather than paths.
fn c_bytes(what: &'static str, s: &OsStr) -> Result<CString, Error> {
    CString::new(s.as_bytes()).map_err(|_: NulError| Error::InteriorNul { what })
}

/// The DAX SHM window size passed with every virtiofs device here: none.
///
/// `krun_set_root` was the whole root surface until [`Context::root`] moved to the long form, and
/// it takes no window, so zero is what the tree has always run. Sizing one is a performance
/// question with its own measurement, not something to change while changing the access mode.
const NO_DAX_WINDOW: u64 = 0;

/// What a guest may do to a virtiofs tree: the `read_only` flag `krun_add_virtiofs3` takes.
///
/// An enum rather than the header's `bool`, so `root(path, ReadOnly)` says at the call site what
/// `root(path, true)` would not. Deliberately this crate's own type and not a re-export of a
/// posture from higher up: this one is a device flag, and the product's posture is
/// `bsx_supervisor`'s business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum FsAccess {
    /// Writes fail with `EROFS` at the device. Default here for the same reason the supervisor's
    /// posture defaults to it: the safe answer should be the one a caller gets for saying nothing.
    #[default]
    ReadOnly,
    /// Writes go through to the host tree.
    ReadWrite,
}

impl FsAccess {
    /// The `read_only` argument for this access mode. Private-facing: the boolean exists at the
    /// FFI boundary and nowhere above it.
    fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }
}

/// What a display callback reports back to libkrun: one of the header's `KRUN_DISPLAY_ERR_*`
/// codes, or a negative code of the backend's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisplayError {
    /// The backend failed for a reason it has no better name for (`KRUN_DISPLAY_ERR_INTERNAL`).
    Internal,
    /// The backend does not implement this call (`KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED`).
    MethodUnsupported,
    /// No such scanout (`KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID`).
    InvalidScanoutId,
    /// An argument the backend cannot act on (`KRUN_DISPLAY_ERR_INVALID_PARAM`).
    InvalidParam,
    /// Every buffer is handed out (`KRUN_DISPLAY_ERR_OUT_OF_BUFFERS`).
    OutOfBuffers,
    /// A code of the backend's own. Non-zero by type, because zero is libkrun's success and an
    /// error that reports success is the one thing this enum must not be able to say.
    Custom(NonZeroI32),
}

impl DisplayError {
    /// The code libkrun reads. Always negative: a positive `Custom` is negated rather than sent
    /// as a success, so no value of this type crosses the boundary as anything but a failure.
    #[must_use]
    pub fn to_raw(self) -> i32 {
        match self {
            Self::Internal => sys::KRUN_DISPLAY_ERR_INTERNAL,
            Self::MethodUnsupported => sys::KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED,
            Self::InvalidScanoutId => sys::KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID,
            Self::InvalidParam => sys::KRUN_DISPLAY_ERR_INVALID_PARAM,
            Self::OutOfBuffers => sys::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS,
            // `i32::MIN` has no positive twin, and is already negative.
            Self::Custom(code) => code.get().checked_abs().map_or(i32::MIN, |a| -a),
        }
    }

    /// The error a raw code names, or `None` for a code that is not a failure at all.
    #[must_use]
    pub fn from_raw(code: i32) -> Option<Self> {
        Some(match code {
            sys::KRUN_DISPLAY_ERR_INTERNAL => Self::Internal,
            sys::KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED => Self::MethodUnsupported,
            sys::KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID => Self::InvalidScanoutId,
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM => Self::InvalidParam,
            sys::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS => Self::OutOfBuffers,
            other if other < 0 => Self::Custom(NonZeroI32::new(other)?),
            _ => return None,
        })
    }
}

impl fmt::Display for DisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Internal => f.write_str("the display backend failed internally"),
            Self::MethodUnsupported => {
                f.write_str("the display backend does not support this call")
            }
            Self::InvalidScanoutId => f.write_str("no such scanout"),
            Self::InvalidParam => f.write_str("the display backend refused an argument"),
            Self::OutOfBuffers => f.write_str("every frame buffer is handed out"),
            Self::Custom(code) => write!(f, "the display backend failed with code {code}"),
        }
    }
}

impl std::error::Error for DisplayError {}

/// A scanout's pixel layout, as libkrun names it (`KRUN_DISPLAY_FORMAT_*`, the virtio-gpu numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PixelFormat {
    /// `B8G8R8A8_UNORM`.
    B8G8R8A8Unorm,
    /// `B8G8R8X8_UNORM`.
    B8G8R8X8Unorm,
    /// `A8R8G8B8_UNORM`.
    A8R8G8B8Unorm,
    /// `X8R8G8B8_UNORM`.
    X8R8G8B8Unorm,
    /// `R8G8B8A8_UNORM`.
    R8G8B8A8Unorm,
    /// `X8B8G8R8_UNORM`.
    X8B8G8R8Unorm,
    /// `A8B8G8R8_UNORM`.
    A8B8G8R8Unorm,
    /// `R8G8B8X8_UNORM`.
    R8G8B8X8Unorm,
    /// A number this build does not know, carried rather than guessed at.
    Unknown(u32),
}

impl PixelFormat {
    /// The format a raw libkrun number names.
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            sys::KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM => Self::B8G8R8A8Unorm,
            sys::KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM => Self::B8G8R8X8Unorm,
            sys::KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM => Self::A8R8G8B8Unorm,
            sys::KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM => Self::X8R8G8B8Unorm,
            sys::KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM => Self::R8G8B8A8Unorm,
            sys::KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM => Self::X8B8G8R8Unorm,
            sys::KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM => Self::A8B8G8R8Unorm,
            sys::KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM => Self::R8G8B8X8Unorm,
            other => Self::Unknown(other),
        }
    }

    /// The raw libkrun number for this format.
    #[must_use]
    pub fn to_raw(self) -> u32 {
        match self {
            Self::B8G8R8A8Unorm => sys::KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM,
            Self::B8G8R8X8Unorm => sys::KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM,
            Self::A8R8G8B8Unorm => sys::KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM,
            Self::X8R8G8B8Unorm => sys::KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM,
            Self::R8G8B8A8Unorm => sys::KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM,
            Self::X8B8G8R8Unorm => sys::KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM,
            Self::A8B8G8R8Unorm => sys::KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM,
            Self::R8G8B8X8Unorm => sys::KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM,
            Self::Unknown(raw) => raw,
        }
    }

    /// Bytes per pixel, or `None` for a format this build cannot size: a guessed stride is a
    /// buffer libkrun writes past the end of.
    #[must_use]
    pub fn bytes_per_pixel(self) -> Option<NonZeroUsize> {
        match self {
            Self::B8G8R8A8Unorm
            | Self::B8G8R8X8Unorm
            | Self::A8R8G8B8Unorm
            | Self::X8R8G8B8Unorm
            | Self::R8G8B8A8Unorm
            | Self::X8B8G8R8Unorm
            | Self::A8B8G8R8Unorm
            | Self::R8G8B8X8Unorm => NonZeroUsize::new(4),
            Self::Unknown(_) => None,
        }
    }
}

/// The part of a frame that changed since the last one, as libkrun reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rect {
    /// Left edge, in pixels.
    pub x: u32,
    /// Top edge, in pixels.
    pub y: u32,
    /// Width, in pixels.
    pub width: u32,
    /// Height, in pixels.
    pub height: u32,
}

impl Rect {
    /// A rectangle at `(x, y)` of `width` by `height`.
    #[must_use]
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

/// A buffer handed to libkrun to fill, and the id it will present it back under.
#[derive(Debug)]
#[non_exhaustive]
pub struct FrameAllocation<'a> {
    /// The id [`DisplayBackend::present_frame`] will name this buffer by. Must fit an `i32`,
    /// because that is how it crosses the vtable; a larger one is refused as an internal error.
    pub frame_id: u32,
    /// Where libkrun writes the pixels, after this call has returned.
    pub buffer: &'a mut [u8],
}

impl<'a> FrameAllocation<'a> {
    /// `buffer`, to be presented back as `frame_id`.
    #[must_use]
    pub fn new(frame_id: u32, buffer: &'a mut [u8]) -> Self {
        Self { frame_id, buffer }
    }
}

/// Where the guest's frames land: what libkrun's virtio-gpu device calls, from its own thread, as
/// the guest configures scanouts and renders into them.
///
/// # Safety
///
/// libkrun keeps writing into the buffer [`alloc_frame`](Self::alloc_frame) returned **after the
/// borrow has ended**, until it presents that frame id, disables the scanout, or reconfigures it.
/// An implementation must not move, shrink, or free that memory in between, and the compiler
/// cannot check that: a `configure_scanout` that reallocates the `Vec` a frame was handed out of
/// is safe Rust and a write into freed memory. Implementing this trait is the promise that it does
/// not happen.
pub unsafe trait DisplayBackend: Send {
    /// Configures or reconfigures scanout `scanout_id`. After this, any frame handed out for it
    /// is abandoned by libkrun and the backend may reuse or free that memory.
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> Result<(), DisplayError>;

    /// Disables scanout `scanout_id`, abandoning any frame handed out for it.
    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayError>;

    /// Hands libkrun a buffer to render the next frame of `scanout_id` into.
    fn alloc_frame(&mut self, scanout_id: u32) -> Result<FrameAllocation<'_>, DisplayError>;

    /// Takes back the frame libkrun has finished writing. `damage` is the part that changed, or
    /// `None` for all of it.
    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        damage: Option<Rect>,
    ) -> Result<(), DisplayError>;
}

/// The backend as libkrun holds it: behind a lock, because the compositor reading its frames is
/// on another thread. The callbacks are monomorphic over `B`, so the caller gets its own type
/// back from [`Machine::display_backend`] rather than a `dyn` it would have to downcast.
type Backend<B> = Mutex<B>;

/// A `Result` of a backend call as the code libkrun reads.
fn code_of(outcome: Result<(), DisplayError>) -> i32 {
    match outcome {
        Ok(()) => 0,
        Err(e) => e.to_raw(),
    }
}

/// Runs `f` on the backend behind `instance`, doing what every callback must do once: refuse a
/// null instance, take the lock, and catch a panic, which must not unwind into libkrun.
///
/// A poisoned lock is recovered rather than refused: the panic that poisoned it was already
/// reported as `KRUN_DISPLAY_ERR_INTERNAL` on the call that panicked, and a backend that has
/// stopped working keeps answering that way from its own methods.
fn with_backend<B: DisplayBackend>(instance: *mut c_void, f: impl FnOnce(&mut B) -> i32) -> i32 {
    if instance.is_null() {
        return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Borrowed, never owned: the count this pointer carries belongs to `c_create`, and a
        // `from_raw` that was allowed to drop would return it on every call.
        let shared = std::mem::ManuallyDrop::new(unsafe {
            Arc::from_raw(instance.cast_const().cast::<Backend<B>>())
        });
        let mut guard = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }));
    outcome.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

/// `create`: the instance is the userdata, holding one count for as long as libkrun's instance
/// lives, which `c_destroy` returns.
unsafe extern "C" fn c_create<B: DisplayBackend>(
    instance: *mut *mut c_void,
    userdata: *const c_void,
    _reserved: *const c_void,
) -> i32 {
    if instance.is_null() || userdata.is_null() {
        return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
    }
    unsafe {
        Arc::increment_strong_count(userdata.cast::<Backend<B>>());
        *instance = userdata.cast_mut();
    }
    0
}

/// `destroy`: returns the count `c_create` took. A backend's own `Drop` runs here, under the
/// same panic guard as its methods.
unsafe extern "C" fn c_destroy<B: DisplayBackend>(instance: *mut c_void) -> i32 {
    if instance.is_null() {
        return 0;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(unsafe { Arc::from_raw(instance.cast_const().cast::<Backend<B>>()) });
    }));
    match outcome {
        Ok(()) => 0,
        Err(_) => sys::KRUN_DISPLAY_ERR_INTERNAL,
    }
}

unsafe extern "C" fn c_configure_scanout<B: DisplayBackend>(
    instance: *mut c_void,
    scanout_id: u32,
    display_width: u32,
    display_height: u32,
    width: u32,
    height: u32,
    format: u32,
) -> i32 {
    with_backend::<B>(instance, |backend| {
        code_of(backend.configure_scanout(
            scanout_id,
            display_width,
            display_height,
            width,
            height,
            PixelFormat::from_raw(format),
        ))
    })
}

unsafe extern "C" fn c_disable_scanout<B: DisplayBackend>(
    instance: *mut c_void,
    scanout_id: u32,
) -> i32 {
    with_backend::<B>(instance, |backend| {
        code_of(backend.disable_scanout(scanout_id))
    })
}

unsafe extern "C" fn c_alloc_frame<B: DisplayBackend>(
    instance: *mut c_void,
    scanout_id: u32,
    buffer: *mut *mut u8,
    buffer_size: *mut usize,
) -> i32 {
    if buffer.is_null() || buffer_size.is_null() {
        return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
    }
    with_backend::<B>(instance, |backend| match backend.alloc_frame(scanout_id) {
        Ok(frame) => {
            // The id travels back as the non-negative half of an `i32`; one that does not fit
            // would arrive as some error code, so it is refused here as the one it really is.
            let Ok(id) = i32::try_from(frame.frame_id) else {
                return sys::KRUN_DISPLAY_ERR_INTERNAL;
            };
            unsafe {
                *buffer = frame.buffer.as_mut_ptr();
                *buffer_size = frame.buffer.len();
            }
            id
        }
        Err(e) => e.to_raw(),
    })
}

unsafe extern "C" fn c_present_frame<B: DisplayBackend>(
    instance: *mut c_void,
    scanout_id: u32,
    frame_id: u32,
    damage_area: *const sys::krun_rect,
) -> i32 {
    let damage = if damage_area.is_null() {
        None
    } else {
        let r = unsafe { &*damage_area };
        Some(Rect::new(r.x, r.y, r.width, r.height))
    };
    with_backend::<B>(instance, |backend| {
        code_of(backend.present_frame(scanout_id, frame_id, damage))
    })
}

/// A frame as libkrun left it: the latest one presented on its scanout.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Frame {
    /// The id it was presented under.
    pub frame_id: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The pixel layout.
    pub format: PixelFormat,
    /// `width * height * bytes_per_pixel` bytes, row-major.
    pub pixels: Vec<u8>,
    /// The part libkrun said changed, if it said.
    pub damage: Option<Rect>,
}

/// A scanout's shape, as libkrun configured it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanoutConfig {
    /// The display's own width, in pixels.
    pub display_width: u32,
    /// The display's own height, in pixels.
    pub display_height: u32,
    /// The scanout's width, in pixels.
    pub width: u32,
    /// The scanout's height, in pixels.
    pub height: u32,
    /// The pixel layout.
    pub format: PixelFormat,
}

impl ScanoutConfig {
    /// Bytes in one frame, or the error for a shape this cannot size.
    fn frame_size(&self) -> Result<usize, DisplayError> {
        let bpp = self
            .format
            .bytes_per_pixel()
            .ok_or(DisplayError::InvalidParam)?;
        (self.width as usize)
            .checked_mul(self.height as usize)
            .and_then(|px| px.checked_mul(bpp.get()))
            .ok_or(DisplayError::InvalidParam)
    }
}

/// The virglrenderer flags [`Machine::gpu_device`] sets: virgl on a surfaceless EGL/GLES context,
/// the one combination measured carrying a frame (see that method for the two that do not).
const DISPLAY_GPU_FLAGS: u32 =
    sys::VIRGLRENDERER_USE_EGL | sys::VIRGLRENDERER_USE_SURFACELESS | sys::VIRGLRENDERER_USE_GLES;

/// Buffers a scanout can have handed out at once. Two is a guest that renders the next frame
/// while the last is presented; a third is slack for one that runs ahead of that.
const RING: usize = 3;

/// Buffers a scanout owns: `RING` to hand out and one holding the latest frame.
const SLOTS: usize = RING + 1;

/// The largest frame id handed out: ids cross the vtable as the non-negative half of an `i32`.
const MAX_FRAME_ID: u32 = i32::MAX as u32;

/// A scanout's buffers: one allocation of `SLOTS` equal regions, on the heap or in a memfd.
enum Storage {
    Heap(Vec<u8>),
    Shared(SharedRegion),
}

impl Storage {
    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Heap(v) => v.as_mut_slice(),
            Self::Shared(r) => r.as_mut_slice(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Heap(v) => v.as_slice(),
            Self::Shared(r) => r.as_slice(),
        }
    }
}

impl fmt::Debug for Storage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Heap(v) => write!(f, "Heap({} bytes)", v.len()),
            Self::Shared(r) => write!(f, "Shared({} bytes, fd {:?})", r.len, r.fd),
        }
    }
}

/// A memfd of one fixed size, sealed against growing or shrinking, mapped shared. The sealing is
/// what lets a second process map it without either side being able to shrink it under the
/// other's mapping, which would turn a read into a `SIGBUS`.
struct SharedRegion {
    fd: OwnedFd,
    base: std::ptr::NonNull<u8>,
    len: usize,
}

// SAFETY: a shared mapping has no thread affinity; the region is only ever reached through
// `&self`/`&mut self`, which is what serialises access from this process.
unsafe impl Send for SharedRegion {}

impl SharedRegion {
    /// A new memfd of `len` bytes, zero-filled, sealed, and mapped read-write.
    fn create(len: usize) -> std::io::Result<Self> {
        use rustix::fs::{MemfdFlags, SealFlags};
        let fd = rustix::fs::memfd_create(
            "bsx-frames",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?;
        rustix::fs::ftruncate(&fd, len as u64)?;
        rustix::fs::fcntl_add_seals(&fd, SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL)?;
        let base = Self::map(
            &fd,
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
        )?;
        Ok(Self { fd, base, len })
    }

    /// Maps `len` bytes of `fd` shared with `prot`.
    fn map(
        fd: &OwnedFd,
        len: usize,
        prot: rustix::mm::ProtFlags,
    ) -> std::io::Result<std::ptr::NonNull<u8>> {
        // SAFETY: a fresh anonymous mapping of the memfd, whose size is sealed to `len`, at an
        // address the kernel chooses; nothing else aliases it.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                rustix::mm::MapFlags::SHARED,
                fd,
                0,
            )?
        };
        std::ptr::NonNull::new(ptr.cast::<u8>())
            .ok_or_else(|| std::io::Error::other("mmap returned a null mapping"))
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `base` is a live mapping of `len` bytes held for as long as `self` is, and
        // `&mut self` is the only way to reach it in this process.
        unsafe { std::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: as `as_mut_slice`, for reading.
        unsafe { std::slice::from_raw_parts(self.base.as_ptr(), self.len) }
    }
}

impl Drop for SharedRegion {
    fn drop(&mut self) {
        // SAFETY: `base`/`len` are the mapping `create`/`map` made, unmapped exactly once here.
        let _ = unsafe { rustix::mm::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

/// What a slot is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    /// Nobody's: the next `alloc_frame` may hand it out.
    Free,
    /// Handed out under this id, and libkrun may be writing into it.
    HandedOut(u32),
    /// Holds the frame last presented.
    Latest,
}

/// The frame last presented on a scanout: which slot, under which id, with what damage.
#[derive(Debug, Clone, Copy)]
struct Latest {
    slot: usize,
    frame_id: u32,
    damage: Option<Rect>,
}

/// One scanout: its shape, the buffers libkrun draws into, and the frame it last presented.
#[derive(Debug)]
struct Scanout {
    config: ScanoutConfig,
    /// Bytes per slot: the frame size, which also puts slot `i` at `i * slot_bytes`.
    slot_bytes: usize,
    storage: Storage,
    states: [SlotState; SLOTS],
    latest: Option<Latest>,
    next_id: u32,
    /// Bumped each time `storage` is replaced, so a process holding the old one can tell.
    generation: u32,
}

impl Scanout {
    fn region(&self, slot: usize) -> Option<&[u8]> {
        let at = slot.checked_mul(self.slot_bytes)?;
        self.storage
            .as_slice()
            .get(at..at.checked_add(self.slot_bytes)?)
    }
}

/// What a frame's memory looks like to a process that maps the scanout's memfd: `slots` regions
/// of `slot_bytes` each, back to back, each holding one `width` by `height` frame of `format`
/// at `stride` bytes a row. Handed over the control socket beside the fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SharedLayout {
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// The pixel layout.
    pub format: PixelFormat,
    /// Bytes per row.
    pub stride: u32,
    /// Regions in the memfd.
    pub slots: u32,
    /// Bytes per region.
    pub slot_bytes: u64,
    /// Which allocation this is; a reconfigure that changes the size makes a new one.
    pub generation: u32,
}

impl SharedLayout {
    /// A layout with these numbers, as a client reads them off the control socket.
    #[must_use]
    pub fn new(
        width: u32,
        height: u32,
        format: PixelFormat,
        stride: u32,
        slots: u32,
        slot_bytes: u64,
        generation: u32,
    ) -> Self {
        Self {
            width,
            height,
            format,
            stride,
            slots,
            slot_bytes,
            generation,
        }
    }
}

/// What a watcher is told: a present names the slot the frame is in, and a reconfigure says the
/// slots a watcher may hold are no longer this scanout's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Frame `frame_id` is in slot `slot` of `scanout_id`.
    Presented {
        /// The scanout.
        scanout_id: u32,
        /// The id it was presented under.
        frame_id: u32,
        /// The region it occupies.
        slot: u32,
    },
    /// `scanout_id` was reconfigured to a new size, so its memory is a new allocation.
    Reconfigured {
        /// The scanout.
        scanout_id: u32,
        /// The allocation now current.
        generation: u32,
    },
}

/// A frame as it sits in the backend: a borrow of the slot holding it, valid for the lock.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FrameView<'a> {
    /// The id it was presented under.
    pub frame_id: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// The pixel layout.
    pub format: PixelFormat,
    /// The part that changed, or `None` for all of it.
    pub damage: Option<Rect>,
    /// The slot it occupies.
    pub slot: u32,
    /// The pixels, `width * 4` bytes a row.
    pub pixels: &'a [u8],
}

impl FrameView<'_> {
    /// A copy of the frame that outlives the lock.
    #[must_use]
    pub fn to_frame(&self) -> Frame {
        Frame {
            frame_id: self.frame_id,
            width: self.width,
            height: self.height,
            format: self.format,
            pixels: self.pixels.to_vec(),
            damage: self.damage,
        }
    }
}

/// What [`MemoryFramebuffer::watch`] registers: told each event, kept while it answers `true`.
type Watcher = Box<dyn Fn(&Event) -> bool + Send>;

/// A display backend that keeps each scanout's latest frame in host RAM, for a compositor in
/// this process to read under the lock, or in a memfd a second process maps.
///
/// **No history, and no allocation once warm.** A scanout owns `SLOTS` regions of one allocation:
/// `RING` to hand out and one holding the latest frame. Presenting marks the filled slot latest
/// and frees the previous one, so at steady state nothing is copied, allocated or zeroed. A
/// history of frames would be that many copies of the screen for a reader that wants the newest.
///
/// **A watcher learns of a present under the lock.** Each present calls every watcher from
/// libkrun's gpu thread with the slot the frame landed in; a watcher that returns `false` is
/// dropped, which is how a client whose socket has gone leaves without a list to be cleaned.
#[derive(Default)]
pub struct MemoryFramebuffer {
    scanouts: HashMap<u32, Scanout>,
    /// Whether scanouts allocate in memfds a second process can map.
    shared: bool,
    watchers: Vec<Watcher>,
}

impl fmt::Debug for MemoryFramebuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryFramebuffer")
            .field("scanouts", &self.scanouts)
            .field("shared", &self.shared)
            .field("watchers", &self.watchers.len())
            .finish()
    }
}

impl MemoryFramebuffer {
    /// An empty framebuffer whose scanouts live on this process's heap.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty framebuffer whose scanouts live in sealed memfds, so [`share`](Self::share) can
    /// hand one to another process.
    #[must_use]
    pub fn shared() -> Self {
        Self {
            shared: true,
            ..Self::default()
        }
    }

    /// How `scanout_id` is configured, if it is.
    #[must_use]
    pub fn scanout_config(&self, scanout_id: u32) -> Option<ScanoutConfig> {
        self.scanouts.get(&scanout_id).map(|s| s.config)
    }

    /// The frame most recently presented on `scanout_id`, if one has been, borrowed from the
    /// slot it sits in.
    #[must_use]
    pub fn latest_frame(&self, scanout_id: u32) -> Option<FrameView<'_>> {
        let scanout = self.scanouts.get(&scanout_id)?;
        let latest = scanout.latest?;
        Some(FrameView {
            frame_id: latest.frame_id,
            width: scanout.config.width,
            height: scanout.config.height,
            format: scanout.config.format,
            damage: latest.damage,
            slot: latest.slot as u32,
            pixels: scanout.region(latest.slot)?,
        })
    }

    /// A duplicate of the memfd holding `scanout_id`'s slots and the layout to read it by, for a
    /// second process. `Ok(None)` while the scanout is not configured; refused as `Unsupported`
    /// on a framebuffer made by [`new`](Self::new), whose memory is not shareable.
    pub fn share(&self, scanout_id: u32) -> std::io::Result<Option<(OwnedFd, SharedLayout)>> {
        let Some(scanout) = self.scanouts.get(&scanout_id) else {
            return Ok(None);
        };
        let Storage::Shared(region) = &scanout.storage else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this framebuffer's slots are on the heap, not in a memfd",
            ));
        };
        let bpp = scanout
            .config
            .format
            .bytes_per_pixel()
            .map_or(4, NonZeroUsize::get);
        Ok(Some((
            region.fd.try_clone()?,
            SharedLayout {
                width: scanout.config.width,
                height: scanout.config.height,
                format: scanout.config.format,
                stride: scanout.config.width.saturating_mul(bpp as u32),
                slots: SLOTS as u32,
                slot_bytes: scanout.slot_bytes as u64,
                generation: scanout.generation,
            },
        )))
    }

    /// Calls `watch` on every present and reconfigure, from libkrun's gpu thread while the
    /// backend's lock is held, so it must return at once and must not take that lock. Returning
    /// `false` drops the watcher.
    pub fn watch(&mut self, watch: impl Fn(&Event) -> bool + Send + 'static) {
        self.watchers.push(Box::new(watch));
    }

    /// Calls `wake` each time a frame is presented, under the same rules as [`watch`](Self::watch).
    /// It is how a compositor learns of a frame the moment it lands instead of polling for it.
    pub fn set_wake(&mut self, wake: impl Fn() + Send + 'static) {
        self.watch(move |event| {
            if matches!(event, Event::Presented { .. }) {
                wake();
            }
            true
        });
    }

    fn notify(&mut self, event: &Event) {
        self.watchers.retain(|w| w(event));
    }
}

/// A scanout's slots as a second process sees them: the memfd from
/// [`MemoryFramebuffer::share`] mapped read-only, addressed by the layout that came with it.
///
/// **A slot is read while the helper may be reusing it.** The helper frees a slot two presents
/// after it was the latest, and hands it out again after that; a reader that takes longer than
/// that to consume a frame sees the next-but-one frame's pixels in it. A torn read is the cost
/// of no copy; a fault is not possible, because the region's size is sealed.
pub struct SharedFrames {
    region: SharedRegion,
    layout: SharedLayout,
}

impl SharedFrames {
    /// Maps `fd`, a memfd from [`MemoryFramebuffer::share`], by `layout`.
    pub fn map(fd: OwnedFd, layout: SharedLayout) -> std::io::Result<Self> {
        let len = usize::try_from(layout.slot_bytes.saturating_mul(u64::from(layout.slots)))
            .map_err(|_| std::io::Error::other("the layout does not fit in memory"))?;
        let base = SharedRegion::map(&fd, len, rustix::mm::ProtFlags::READ)?;
        Ok(Self {
            region: SharedRegion { fd, base, len },
            layout,
        })
    }

    /// The layout the mapping was made by.
    #[must_use]
    pub fn layout(&self) -> SharedLayout {
        self.layout
    }

    /// The frame in `slot`, presented as `frame_id`, or `None` for a slot the layout has not got.
    #[must_use]
    pub fn frame(&self, frame_id: u32, slot: u32) -> Option<FrameView<'_>> {
        let bytes = usize::try_from(self.layout.slot_bytes).ok()?;
        let at = usize::try_from(slot).ok()?.checked_mul(bytes)?;
        let pixels = self.region.as_slice().get(at..at.checked_add(bytes)?)?;
        Some(FrameView {
            frame_id,
            width: self.layout.width,
            height: self.layout.height,
            format: self.layout.format,
            damage: None,
            slot,
            pixels,
        })
    }
}

impl fmt::Debug for SharedFrames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedFrames")
            .field("layout", &self.layout)
            .finish_non_exhaustive()
    }
}

// SAFETY: the memory handed out is a region of a scanout's `storage`, whose allocation changes
// only in `configure_scanout` (to a new size, after which the header says libkrun has abandoned
// every frame of that scanout) and `disable_scanout`. A slot is handed out only while `Free` and
// no other slot's region overlaps it, so nothing else touches a handed-out slot.
unsafe impl DisplayBackend for MemoryFramebuffer {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> Result<(), DisplayError> {
        let config = ScanoutConfig {
            display_width,
            display_height,
            width,
            height,
            format,
        };
        // Refused before anything is recorded, so a shape that cannot be sized leaves the old
        // one in place rather than a scanout every `alloc_frame` then fails on.
        let slot_bytes = config.frame_size()?;
        let total = slot_bytes
            .checked_mul(SLOTS)
            .ok_or(DisplayError::InvalidParam)?;
        let shared = self.shared;
        let make_storage = || -> Result<Storage, DisplayError> {
            if shared {
                SharedRegion::create(total)
                    .map(Storage::Shared)
                    .map_err(|_| DisplayError::Internal)
            } else {
                Ok(Storage::Heap(vec![0; total]))
            }
        };
        let mut reconfigured = None;
        match self.scanouts.get_mut(&scanout_id) {
            Some(scanout) if scanout.slot_bytes == slot_bytes => {
                scanout.config = config;
                scanout.states = [SlotState::Free; SLOTS];
                scanout.latest = None;
            }
            Some(scanout) => {
                scanout.storage = make_storage()?;
                scanout.config = config;
                scanout.slot_bytes = slot_bytes;
                scanout.states = [SlotState::Free; SLOTS];
                scanout.latest = None;
                scanout.generation = scanout.generation.wrapping_add(1);
                reconfigured = Some(scanout.generation);
            }
            None => {
                self.scanouts.insert(
                    scanout_id,
                    Scanout {
                        config,
                        slot_bytes,
                        storage: make_storage()?,
                        states: [SlotState::Free; SLOTS],
                        latest: None,
                        next_id: 0,
                        generation: 0,
                    },
                );
            }
        }
        if let Some(generation) = reconfigured {
            self.notify(&Event::Reconfigured {
                scanout_id,
                generation,
            });
        }
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayError> {
        self.scanouts
            .remove(&scanout_id)
            .map(drop)
            .ok_or(DisplayError::InvalidScanoutId)
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<FrameAllocation<'_>, DisplayError> {
        let scanout = self
            .scanouts
            .get_mut(&scanout_id)
            .ok_or(DisplayError::InvalidScanoutId)?;
        let slot = scanout
            .states
            .iter()
            .position(|s| *s == SlotState::Free)
            .ok_or(DisplayError::OutOfBuffers)?;
        let frame_id = scanout.next_id;
        scanout.next_id = if frame_id == MAX_FRAME_ID {
            0
        } else {
            frame_id + 1
        };
        scanout.states[slot] = SlotState::HandedOut(frame_id);
        let bytes = scanout.slot_bytes;
        let region = scanout
            .storage
            .as_mut_slice()
            .get_mut(slot * bytes..(slot + 1) * bytes)
            .ok_or(DisplayError::Internal)?;
        Ok(FrameAllocation::new(frame_id, region))
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        damage: Option<Rect>,
    ) -> Result<(), DisplayError> {
        let scanout = self
            .scanouts
            .get_mut(&scanout_id)
            .ok_or(DisplayError::InvalidScanoutId)?;
        let slot = scanout
            .states
            .iter()
            .position(|s| *s == SlotState::HandedOut(frame_id))
            .ok_or(DisplayError::InvalidParam)?;
        // The filled slot becomes the frame, and the previous frame's slot becomes free: no bytes
        // copied, nothing allocated.
        if let Some(previous) = scanout.latest.take() {
            scanout.states[previous.slot] = SlotState::Free;
        }
        scanout.states[slot] = SlotState::Latest;
        scanout.latest = Some(Latest {
            slot,
            frame_id,
            damage,
        });
        self.notify(&Event::Presented {
            scanout_id,
            frame_id,
            slot: slot as u32,
        });
        Ok(())
    }
}

/// What [`Machine::display_backend`] hands libkrun and keeps alive: the count behind
/// `create_userdata`, and the table itself.
///
/// The count is taken back if the machine is dropped without starting (a failed `enter`, or a
/// caller that changed its mind); once started, `c_create` takes its own and the process ends
/// before this one could matter. The table is retained by the crate's rule for anything libkrun
/// is given a pointer to, though it was measured copying it (2026-09-02: overwriting the struct
/// after the call left `create` working).
struct DisplayHandle {
    userdata: *const c_void,
    /// Returns the count for the concrete `B` the pointer was made from; the handle itself is
    /// type-erased so [`Machine`] can hold one without knowing the backend.
    release: unsafe fn(*const c_void),
    _table: Box<sys::krun_display_backend>,
}

/// [`DisplayHandle::release`] for a backend of type `B`.
unsafe fn release_backend<B: DisplayBackend>(userdata: *const c_void) {
    drop(unsafe { Arc::from_raw(userdata.cast::<Backend<B>>()) });
}

impl Drop for DisplayHandle {
    fn drop(&mut self) {
        unsafe { (self.release)(self.userdata) }
    }
}

impl fmt::Debug for DisplayHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisplayHandle")
    }
}

// --- input -----------------------------------------------------------------------------------

/// The bits a capability bitmap holds: libkrun hands every query a 128-byte buffer.
const CAPABILITY_BITS: u16 = 128 * 8;

/// Events one device holds unread before [`InputSender::send`] refuses more, which bounds what a
/// guest that never reads its device can make this process keep.
pub const INPUT_QUEUE_CAP: usize = 4096;

/// `EV_SYN`: the type of the event that ends a report.
pub const EV_SYN: u16 = 0;
/// `EV_KEY`: a key or button.
pub const EV_KEY: u16 = 1;
/// `EV_REL`: a relative axis.
pub const EV_REL: u16 = 2;
/// `EV_ABS`: an absolute axis.
pub const EV_ABS: u16 = 3;
/// `SYN_REPORT`: the code that ends a report.
pub const SYN_REPORT: u16 = 0;

/// One evdev event as the guest receives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InputEvent {
    /// `EV_KEY`, `EV_REL`, `EV_ABS`, or `EV_SYN`; the header's `type`.
    pub type_: u16,
    /// A key code, an axis, or a `SYN_*` code.
    pub code: u16,
    /// Pressed or released, a delta, a position.
    pub value: i32,
}

impl InputEvent {
    /// An event of `type_`, `code` and `value`.
    #[must_use]
    pub const fn new(type_: u16, code: u16, value: i32) -> Self {
        Self { type_, code, value }
    }

    /// The `SYN_REPORT` that ends a report, so the guest applies what came before it together.
    #[must_use]
    pub const fn syn_report() -> Self {
        Self::new(EV_SYN, SYN_REPORT, 0)
    }
}

/// The range of an absolute axis, as `struct input_absinfo` has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct AbsInfo {
    /// Smallest value.
    pub min: u32,
    /// Largest value.
    pub max: u32,
    /// Noise the driver filters.
    pub fuzz: u32,
    /// Dead zone around the centre.
    pub flat: u32,
    /// Units per millimetre, or zero for none.
    pub res: u32,
}

impl AbsInfo {
    /// An axis running from `min` to `max`, with no fuzz, flat, or resolution.
    #[must_use]
    pub const fn range(min: u32, max: u32) -> Self {
        Self {
            min,
            max,
            fuzz: 0,
            flat: 0,
            res: 0,
        }
    }
}

/// What a device tells the guest it is, in the terms the virtio-input driver queries at probe:
/// a name, an identity, and the codes it emits for each event type. A device with no codes is
/// one the guest sees and never hears from.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InputDevice {
    name: Vec<u8>,
    serial: Vec<u8>,
    ids: sys::krun_input_device_ids,
    keys: BTreeSet<u16>,
    relative: BTreeSet<u16>,
    absolute: BTreeMap<u16, AbsInfo>,
    properties: BTreeSet<u16>,
}

impl InputDevice {
    /// A device called `name`, cut to what the guest's name buffer holds, with nothing else set.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            serial: Vec::new(),
            ids: sys::krun_input_device_ids {
                bustype: 0,
                vendor: 0,
                product: 0,
                version: 0,
            },
            keys: BTreeSet::new(),
            relative: BTreeSet::new(),
            absolute: BTreeMap::new(),
            properties: BTreeSet::new(),
        }
    }

    /// Sets the serial the guest reports.
    #[must_use]
    pub fn serial(mut self, serial: &str) -> Self {
        self.serial = serial.as_bytes().to_vec();
        self
    }

    /// Sets the evdev identity: bus type, vendor, product, version.
    #[must_use]
    pub fn ids(mut self, bustype: u16, vendor: u16, product: u16, version: u16) -> Self {
        self.ids = sys::krun_input_device_ids {
            bustype,
            vendor,
            product,
            version,
        };
        self
    }

    /// Adds `EV_KEY` codes the device emits: keys and buttons.
    #[must_use]
    pub fn keys(mut self, codes: impl IntoIterator<Item = u16>) -> Self {
        self.keys.extend(codes);
        self
    }

    /// Adds `EV_REL` axes the device emits.
    #[must_use]
    pub fn relative_axes(mut self, codes: impl IntoIterator<Item = u16>) -> Self {
        self.relative.extend(codes);
        self
    }

    /// Adds an `EV_ABS` axis and its range.
    #[must_use]
    pub fn absolute_axis(mut self, axis: u16, info: AbsInfo) -> Self {
        self.absolute.insert(axis, info);
        self
    }

    /// Adds `INPUT_PROP_*` bits.
    #[must_use]
    pub fn properties(mut self, bits: impl IntoIterator<Item = u16>) -> Self {
        self.properties.extend(bits);
        self
    }

    /// The codes of `event_type`, empty for a type the device does not emit.
    fn codes_of(&self, event_type: u16) -> Vec<u16> {
        match event_type {
            EV_KEY => self.keys.iter().copied().collect(),
            EV_REL => self.relative.iter().copied().collect(),
            EV_ABS => self.absolute.keys().copied().collect(),
            _ => Vec::new(),
        }
    }

    /// The largest code or property bit any query would have to set.
    fn largest_bit(&self) -> Option<u16> {
        [
            self.keys.last(),
            self.relative.last(),
            self.absolute.keys().next_back(),
            self.properties.last(),
        ]
        .into_iter()
        .flatten()
        .copied()
        .max()
    }

    /// Refuses a device whose bitmaps would not fit the buffers libkrun hands the queries, which
    /// is the one way its tables can answer wrong.
    fn check_fits(&self) -> Result<(), Error> {
        match self.largest_bit() {
            Some(bit) if bit >= CAPABILITY_BITS => Err(Error::OutOfRange {
                what: "an input code",
                value: u32::from(bit),
                max: u32::from(CAPABILITY_BITS - 1),
            }),
            _ => Ok(()),
        }
    }
}

/// Sets `bits` in `bitmap` and returns the bytes that covers, or `None` when one does not fit.
fn write_bitmap(bitmap: &mut [u8], bits: impl IntoIterator<Item = u16>) -> Option<usize> {
    let mut len = 0;
    for bit in bits {
        let byte = usize::from(bit / 8);
        *bitmap.get_mut(byte)? |= 1 << (bit % 8);
        len = len.max(byte + 1);
    }
    Some(len)
}

/// Copies as much of `src` as `dst` holds and returns how much that was.
fn copy_name(src: &[u8], dst: &mut [u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// A length as the code libkrun reads it: the length, or `KRUN_INPUT_ERR_INTERNAL` for one an
/// `i32` cannot say, which no 128-byte buffer produces.
fn length_code(len: usize) -> i32 {
    i32::try_from(len).unwrap_or(sys::KRUN_INPUT_ERR_INTERNAL)
}

/// Runs `f` on the `T` behind `instance`, doing what every input callback must do once: refuse a
/// null instance and catch a panic, which must not unwind into libkrun.
fn with_input<T>(instance: *mut c_void, f: impl FnOnce(&T) -> i32) -> i32 {
    if instance.is_null() {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Borrowed, never owned: the count belongs to `c_input_create`.
        let shared = std::mem::ManuallyDrop::new(unsafe {
            Arc::from_raw(instance.cast_const().cast::<T>())
        });
        f(&shared)
    }));
    outcome.unwrap_or(sys::KRUN_INPUT_ERR_INTERNAL)
}

/// `create` for either table: the instance is the userdata, holding one count that
/// `c_input_destroy` returns.
unsafe extern "C" fn c_input_create<T>(
    instance: *mut *mut c_void,
    userdata: *const c_void,
    _reserved: *const c_void,
) -> i32 {
    if instance.is_null() || userdata.is_null() {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    }
    unsafe {
        Arc::increment_strong_count(userdata.cast::<T>());
        *instance = userdata.cast_mut();
    }
    0
}

/// `destroy` for either table: returns the count `c_input_create` took.
unsafe extern "C" fn c_input_destroy<T>(instance: *mut c_void) -> i32 {
    if instance.is_null() {
        return 0;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(unsafe { Arc::from_raw(instance.cast_const().cast::<T>()) });
    }));
    match outcome {
        Ok(()) => 0,
        Err(_) => sys::KRUN_INPUT_ERR_INTERNAL,
    }
}

/// The `buf`/`len` pair of a query as a slice, or `None` for a null buffer.
unsafe fn query_buffer<'a>(buf: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if buf.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(buf, len) })
}

unsafe extern "C" fn c_query_device_name(instance: *mut c_void, buf: *mut u8, len: usize) -> i32 {
    let Some(dst) = (unsafe { query_buffer(buf, len) }) else {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    };
    with_input::<InputDevice>(instance, |d| length_code(copy_name(&d.name, dst)))
}

unsafe extern "C" fn c_query_serial_name(instance: *mut c_void, buf: *mut u8, len: usize) -> i32 {
    let Some(dst) = (unsafe { query_buffer(buf, len) }) else {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    };
    with_input::<InputDevice>(instance, |d| length_code(copy_name(&d.serial, dst)))
}

unsafe extern "C" fn c_query_device_ids(
    instance: *mut c_void,
    ids: *mut sys::krun_input_device_ids,
) -> i32 {
    if ids.is_null() {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    }
    with_input::<InputDevice>(instance, |d| {
        unsafe { *ids = d.ids };
        0
    })
}

unsafe extern "C" fn c_query_event_capabilities(
    instance: *mut c_void,
    event_type: u8,
    buf: *mut u8,
    len: usize,
) -> i32 {
    let Some(dst) = (unsafe { query_buffer(buf, len) }) else {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    };
    with_input::<InputDevice>(instance, |d| {
        match write_bitmap(dst, d.codes_of(u16::from(event_type))) {
            Some(n) => length_code(n),
            None => sys::KRUN_INPUT_ERR_INVALID_PARAM,
        }
    })
}

unsafe extern "C" fn c_query_abs_info(
    instance: *mut c_void,
    axis: u8,
    info: *mut sys::krun_input_absinfo,
) -> i32 {
    if info.is_null() {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    }
    with_input::<InputDevice>(instance, |d| {
        let a = d
            .absolute
            .get(&u16::from(axis))
            .copied()
            .unwrap_or_default();
        unsafe {
            *info = sys::krun_input_absinfo {
                min: a.min,
                max: a.max,
                fuzz: a.fuzz,
                flat: a.flat,
                res: a.res,
            };
        }
        0
    })
}

unsafe extern "C" fn c_query_properties(instance: *mut c_void, buf: *mut u8, len: usize) -> i32 {
    let Some(dst) = (unsafe { query_buffer(buf, len) }) else {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    };
    with_input::<InputDevice>(instance, |d| {
        match write_bitmap(dst, d.properties.iter().copied()) {
            Some(n) => length_code(n),
            None => sys::KRUN_INPUT_ERR_INVALID_PARAM,
        }
    })
}

/// The events waiting for one device, and the fd libkrun waits on, which is readable exactly
/// while an event waits.
#[derive(Debug)]
struct InputQueue {
    events: VecDeque<InputEvent>,
    ready: OwnedFd,
}

impl InputQueue {
    fn new() -> std::io::Result<Self> {
        use rustix::event::EventfdFlags;
        let ready = rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        Ok(Self {
            events: VecDeque::new(),
            ready,
        })
    }

    /// Queues `events` whole, or none of them, and arms the fd. Armed under the same lock `pop`
    /// disarms under, so a pop that finds the queue empty cannot slip between the two.
    fn push(&mut self, events: &[InputEvent]) -> Result<(), QueueFull> {
        if self.events.len().saturating_add(events.len()) > INPUT_QUEUE_CAP {
            return Err(QueueFull);
        }
        self.events.extend(events);
        let _ = rustix::io::write(&self.ready, &1u64.to_ne_bytes());
        Ok(())
    }

    /// The next event, disarming the fd when there is none.
    fn pop(&mut self) -> Option<InputEvent> {
        let next = self.events.pop_front();
        if next.is_none() {
            let mut counter = [0u8; 8];
            let _ = rustix::io::read(&self.ready, &mut counter);
        }
        next
    }
}

/// The queue holds [`INPUT_QUEUE_CAP`] events the guest has not read, and the batch was refused
/// whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

impl fmt::Display for QueueFull {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the guest has {INPUT_QUEUE_CAP} input events unread, so no more are queued"
        )
    }
}

impl std::error::Error for QueueFull {}

/// The sending half of a device's event queue: what a window feeds. Cloneable and `Send`, so it
/// can go to the thread that has the events.
#[derive(Debug, Clone)]
pub struct InputSender(Arc<Mutex<InputQueue>>);

impl InputSender {
    /// Queues `events` for the guest as one batch, all of them or none, so a report is never
    /// split.
    pub fn send(&self, events: &[InputEvent]) -> Result<(), QueueFull> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(events)
    }
}

unsafe extern "C" fn c_get_ready_efd(instance: *mut c_void) -> c_int {
    with_input::<Mutex<InputQueue>>(instance, |q| {
        q.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ready
            .as_raw_fd()
    })
}

unsafe extern "C" fn c_next_event(instance: *mut c_void, out: *mut sys::krun_input_event) -> i32 {
    if out.is_null() {
        return sys::KRUN_INPUT_ERR_INVALID_PARAM;
    }
    with_input::<Mutex<InputQueue>>(instance, |q| {
        let next = q
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop();
        match next {
            Some(e) => {
                unsafe {
                    *out = sys::krun_input_event {
                        type_: e.type_,
                        code: e.code,
                        value: u32::from_ne_bytes(e.value.to_ne_bytes()),
                    };
                }
                1
            }
            None => 0,
        }
    })
}

/// What [`Machine::input_device`] hands libkrun and keeps alive: the counts behind the two
/// tables' userdata, and the tables. libkrun copies the tables (`krun_add_input_device`
/// dereferences both before it returns); they are retained anyway, by the crate's rule.
struct InputHandle {
    device: *const c_void,
    queue: *const c_void,
    _config: Box<sys::krun_input_config>,
    _events: Box<sys::krun_input_event_provider>,
}

impl Drop for InputHandle {
    fn drop(&mut self) {
        unsafe {
            drop(Arc::from_raw(self.device.cast::<InputDevice>()));
            drop(Arc::from_raw(self.queue.cast::<Mutex<InputQueue>>()));
        }
    }
}

impl fmt::Debug for InputHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InputHandle")
    }
}

/// The context id, freed on drop.
///
/// `PhantomData<*const ()>` makes every handle `!Send` and `!Sync`. libkrun documents no
/// thread-safety for its context table, and an FFI handle whose threading rules are unstated is one
/// a caller should not be able to move across threads by accident. The helper process that calls
/// [`Machine::enter`] does so on the thread that built the context, which is all this project needs.
#[derive(Debug)]
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
#[derive(Debug)]
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

    /// Serves `path`, a host directory, as the guest's root over virtiofs under `access`, and
    /// moves on to the stage where the rest of the machine is configured.
    ///
    /// `krun_add_virtiofs3` with [`KRUN_FS_ROOT_TAG`] rather than `krun_set_root`, because the
    /// header names it as the way to get the read-only flag; the two are otherwise the same
    /// device. [`FsAccess::ReadOnly`] is enforced by the device, so a guest write fails with
    /// `EROFS` and nothing reaches the host tree (measured, 2026-09-01, libkrun 1.19.4).
    pub fn root(mut self, path: &Path, access: FsAccess) -> Result<Machine, Error> {
        let c_tag = c_bytes("the root tag", OsStr::new(sys::KRUN_FS_ROOT_TAG))?;
        let c_dir = c_path("the root path", path)?;
        check("krun_add_virtiofs3", unsafe {
            sys::krun_add_virtiofs3(
                self.ctx.id,
                c_tag.as_ptr(),
                c_dir.as_ptr(),
                NO_DAX_WINDOW,
                access.is_read_only(),
            )
        })?;
        self.retained.push(c_tag);
        self.retained.push(c_dir);
        Ok(Machine {
            ctx: self.ctx,
            retained: std::mem::take(&mut self.retained),
            retained_display: None,
            retained_inputs: Vec::new(),
        })
    }
}

/// A context with a root filesystem, being configured toward [`enter`](Self::enter).
#[derive(Debug)]
pub struct Machine {
    ctx: Ctx,
    retained: Vec<CString>,
    retained_display: Option<DisplayHandle>,
    retained_inputs: Vec<InputHandle>,
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

    /// Replaces libkrun's implicit vsock device with an explicit one carrying exactly
    /// `tsi_features`. `0` is a vsock with **no** transparent socket proxying: the guest's
    /// network syscalls are not hijacked onto the host, which is the no-network posture. The
    /// implicit device libkrun would otherwise add enables TSI hijacking by heuristic, so a
    /// machine that says nothing about the network still gets one; this is how a caller says no.
    ///
    /// Must come before [`vsock_port`](Self::vsock_port): the port mapping attaches to the vsock
    /// device, and libkrun allows only one, so the explicit device has to exist first.
    pub fn vsock(self, tsi_features: u32) -> Result<Self, Error> {
        check("krun_disable_implicit_vsock", unsafe {
            sys::krun_disable_implicit_vsock(self.ctx.id)
        })?;
        check("krun_add_vsock", unsafe {
            sys::krun_add_vsock(self.ctx.id, tsi_features)
        })?;
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

    /// Configures a display output of `width` by `height` for the microVM.
    ///
    /// Returns the updated `Machine` and the `display_id` (0..`KRUN_MAX_DISPLAYS - 1`) assigned by libkrun.
    pub fn add_display(self, width: u32, height: u32) -> Result<(Self, u32), Error> {
        let display_id = check("krun_add_display", unsafe {
            sys::krun_add_display(self.ctx.id, width, height)
        })?;
        Ok((self, display_id as u32))
    }

    /// Configures a custom EDID blob for `display_id`.
    pub fn display_set_edid(self, display_id: u32, edid: &[u8]) -> Result<Self, Error> {
        check("krun_display_set_edid", unsafe {
            sys::krun_display_set_edid(self.ctx.id, display_id, edid.as_ptr(), edid.len())
        })?;
        Ok(self)
    }

    /// Configures DPI reported to the guest for `display_id`.
    pub fn display_set_dpi(self, display_id: u32, dpi: u32) -> Result<Self, Error> {
        check("krun_display_set_dpi", unsafe {
            sys::krun_display_set_dpi(self.ctx.id, display_id, dpi)
        })?;
        Ok(self)
    }

    /// Configures physical width and height in millimeters for `display_id`.
    pub fn display_set_physical_size(
        self,
        display_id: u32,
        width_mm: u16,
        height_mm: u16,
    ) -> Result<Self, Error> {
        check("krun_display_set_physical_size", unsafe {
            sys::krun_display_set_physical_size(self.ctx.id, display_id, width_mm, height_mm)
        })?;
        Ok(self)
    }

    /// Configures refresh rate for `display_id`.
    pub fn display_set_refresh_rate(
        self,
        display_id: u32,
        refresh_rate: u32,
    ) -> Result<Self, Error> {
        check("krun_display_set_refresh_rate", unsafe {
            sys::krun_display_set_refresh_rate(self.ctx.id, display_id, refresh_rate)
        })?;
        Ok(self)
    }

    /// Adds the virtio-gpu device a display needs, with the one flag set measured to carry frames.
    ///
    /// Three were tried on this host (2026-09-02, libkrun 1.19.4): `0` segfaults the VMM inside
    /// `virgl_renderer_init`; `NO_VIRGL` boots but every guest `ResourceCreate2d` fails with
    /// rutabaga `ComponentError(22)`, so no scanout is ever configured; virgl on a surfaceless
    /// EGL/GLES context carries a dumb-buffer frame end to end. Only the last is offered. Phase
    /// 5's accelerated posture is a separate call, gated on `krun_has_feature`.
    pub fn gpu_device(self) -> Result<Self, Error> {
        check("krun_set_gpu_options", unsafe {
            sys::krun_set_gpu_options(self.ctx.id, DISPLAY_GPU_FLAGS)
        })?;
        Ok(self)
    }

    /// Adds a virtio-snd device, backed by the host audio server libkrun links (pipewire on this
    /// build). One boolean, so the guest gets a full sound card: **playback to the host's output
    /// and capture from its input**, the microphone included. libkrun's API cannot split the two,
    /// so a caller enabling audio opens both directions; the posture that keeps it off by default
    /// lives above this, in the supervisor's config and the CLI's `--sound` flag.
    ///
    /// Gated by the caller on [`has_feature`]`(`[`KRUN_FEATURE_SND`]`)`: a libkrun built without
    /// snd exports this symbol but adds no device, so a caller that did not probe would enable
    /// nothing and not know it.
    pub fn sound_device(self) -> Result<Self, Error> {
        check("krun_set_snd_device", unsafe {
            sys::krun_set_snd_device(self.ctx.id, true)
        })?;
        Ok(self)
    }

    /// Hands the guest's frames to `backend`, which libkrun calls from its gpu thread for as long
    /// as the VM runs, and returns the shared handle a compositor reads them through. Needs a
    /// display ([`add_display`](Self::add_display)) and [`gpu_device`](Self::gpu_device).
    pub fn display_backend<B: DisplayBackend + 'static>(
        mut self,
        backend: B,
    ) -> Result<(Self, Arc<Mutex<B>>), Error> {
        let shared: Arc<Backend<B>> = Arc::new(Mutex::new(backend));
        // Built before the call, so the `?` on a refused call drops it and takes the count back.
        let handle = DisplayHandle {
            userdata: Arc::into_raw(Arc::clone(&shared)).cast::<c_void>(),
            release: release_backend::<B>,
            _table: Box::new(sys::krun_display_backend {
                features: sys::KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER,
                create_userdata: std::ptr::null(),
                create: Some(c_create::<B>),
                vtable: sys::krun_display_vtable {
                    basic_framebuffer: sys::krun_display_basic_framebuffer_vtable {
                        destroy: Some(c_destroy::<B>),
                        disable_scanout: Some(c_disable_scanout::<B>),
                        configure_scanout: Some(c_configure_scanout::<B>),
                        alloc_frame: Some(c_alloc_frame::<B>),
                        present_frame: Some(c_present_frame::<B>),
                    },
                },
            }),
        };
        let mut table = handle._table.clone();
        table.create_userdata = handle.userdata;
        check("krun_set_display_backend", unsafe {
            sys::krun_set_display_backend(
                self.ctx.id,
                std::ptr::from_ref(&*table).cast::<c_void>(),
                std::mem::size_of::<sys::krun_display_backend>(),
            )
        })?;
        self.retained_display = Some(DisplayHandle {
            userdata: handle.userdata,
            release: handle.release,
            _table: table,
        });
        std::mem::forget(handle);
        Ok((self, shared))
    }

    /// Adds an input device the guest sees as `device`, and returns the sender its events go
    /// through. libkrun queries the identity at boot from its own thread and pulls events from
    /// another for as long as the VM runs.
    pub fn input_device(mut self, device: InputDevice) -> Result<(Self, InputSender), Error> {
        device.check_fits()?;
        let queue = InputQueue::new().map_err(|source| Error::Call {
            call: "eventfd",
            source,
        })?;
        let device = Arc::new(device);
        let shared = Arc::new(Mutex::new(queue));
        // Built before the call, so the `?` on a refused call drops it and takes the counts back.
        let handle = InputHandle {
            device: Arc::into_raw(Arc::clone(&device)).cast::<c_void>(),
            queue: Arc::into_raw(Arc::clone(&shared)).cast::<c_void>(),
            _config: Box::new(sys::krun_input_config {
                features: sys::KRUN_INPUT_CONFIG_FEATURE_QUERY,
                create_userdata: Arc::as_ptr(&device).cast::<c_void>(),
                create: Some(c_input_create::<InputDevice>),
                vtable: sys::krun_input_config_vtable {
                    destroy: Some(c_input_destroy::<InputDevice>),
                    query_device_name: Some(c_query_device_name),
                    query_serial_name: Some(c_query_serial_name),
                    query_device_ids: Some(c_query_device_ids),
                    query_event_capabilities: Some(c_query_event_capabilities),
                    query_abs_info: Some(c_query_abs_info),
                    query_properties: Some(c_query_properties),
                },
            }),
            _events: Box::new(sys::krun_input_event_provider {
                features: sys::KRUN_INPUT_EVENT_PROVIDER_FEATURE_QUEUE,
                create_userdata: Arc::as_ptr(&shared).cast::<c_void>(),
                create: Some(c_input_create::<Mutex<InputQueue>>),
                vtable: sys::krun_input_event_provider_vtable {
                    destroy: Some(c_input_destroy::<Mutex<InputQueue>>),
                    get_ready_efd: Some(c_get_ready_efd),
                    next_event: Some(c_next_event),
                },
            }),
        };
        check("krun_add_input_device", unsafe {
            sys::krun_add_input_device(
                self.ctx.id,
                std::ptr::from_ref(&*handle._config).cast::<c_void>(),
                std::mem::size_of::<sys::krun_input_config>(),
                std::ptr::from_ref(&*handle._events).cast::<c_void>(),
                std::mem::size_of::<sys::krun_input_event_provider>(),
            )
        })?;
        self.retained_inputs.push(handle);
        Ok((self, InputSender(shared)))
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
    /// negation being passed through to `io::Error` as-is. Only meaningful where a real library
    /// produced the value: the stub build reports every failure as [`Error::NotLinked`] instead.
    #[cfg(krun_linked)]
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

    /// The no-libkrun build: every call is a stub, and the report names the missing library and
    /// the fix rather than an errno a stub invented. Compiled only where `build.rs` found nothing,
    /// which is the CI case; where a real library is linked the twin below says what was skipped.
    #[cfg(not(krun_linked))]
    #[test]
    fn a_build_without_libkrun_reports_the_library_as_missing() {
        let err = Context::new().expect_err("no libkrun is linked into this build");
        assert!(
            matches!(&err, Error::NotLinked { call } if *call == "krun_create_ctx"),
            "got {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("BSX_KRUN_LIB_DIR"), "names the fix: {msg}");
    }

    #[cfg(krun_linked)]
    #[test]
    fn a_build_without_libkrun_reports_the_library_as_missing() {
        println!(
            "SKIPPED a_build_without_libkrun_reports_the_library_as_missing: this build links a \
             real libkrun, so the stub path is compiled out."
        );
    }

    /// The C arrays libkrun reads are NULL-terminated, not length-carrying, so the terminator is
    /// load-bearing: without it libkrun walks off the end of the array.
    /// The device flag is an enum so a call site reads as a posture, and the default is the safe
    /// one: a caller that says nothing gets a root it cannot write.
    #[test]
    fn the_root_access_default_is_read_only() {
        assert_eq!(FsAccess::default(), FsAccess::ReadOnly);
        assert!(FsAccess::ReadOnly.is_read_only());
        assert!(!FsAccess::ReadWrite.is_read_only());
    }

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
    #[cfg(krun_linked)]
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

    /// No value of the error type can reach libkrun as a success, whatever a backend puts in
    /// `Custom`, and a raw code that is not a failure does not become one.
    #[test]
    fn a_display_error_never_crosses_as_success() {
        let nz = |v: i32| NonZeroI32::new(v).expect("non-zero by construction");
        let all = [
            DisplayError::Internal,
            DisplayError::MethodUnsupported,
            DisplayError::InvalidScanoutId,
            DisplayError::InvalidParam,
            DisplayError::OutOfBuffers,
            DisplayError::Custom(nz(-22)),
            DisplayError::Custom(nz(22)),
            DisplayError::Custom(nz(i32::MIN)),
            DisplayError::Custom(nz(i32::MAX)),
        ];
        for err in all {
            assert!(err.to_raw() < 0, "{err:?} would cross as {}", err.to_raw());
        }
        for (err, raw) in [
            (DisplayError::Internal, sys::KRUN_DISPLAY_ERR_INTERNAL),
            (
                DisplayError::OutOfBuffers,
                sys::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS,
            ),
            (DisplayError::Custom(nz(-22)), -22),
        ] {
            assert_eq!(err.to_raw(), raw);
            assert_eq!(DisplayError::from_raw(raw), Some(err));
        }
        assert_eq!(
            DisplayError::from_raw(0),
            None,
            "zero is success, not an error"
        );
        assert_eq!(
            DisplayError::from_raw(7),
            None,
            "a positive code is not a failure"
        );
    }

    #[test]
    fn a_pixel_format_round_trips_and_only_known_ones_have_a_size() {
        for raw in [1, 2, 3, 4, 67, 68, 121, 134] {
            let fmt = PixelFormat::from_raw(raw);
            assert!(
                !matches!(fmt, PixelFormat::Unknown(_)),
                "{raw} is in the header"
            );
            assert_eq!(fmt.to_raw(), raw);
            assert_eq!(fmt.bytes_per_pixel().map(NonZeroUsize::get), Some(4));
        }
        assert_eq!(PixelFormat::from_raw(999), PixelFormat::Unknown(999));
        assert_eq!(PixelFormat::Unknown(999).bytes_per_pixel(), None);
    }

    /// A scanout hands out its ring, keeps only the newest frame, and recycles the previous
    /// frame's buffer into the ring, so a warm scanout moves bytes between owners and allocates
    /// nothing: the address libkrun wrote frame N into is the address frame N+RING is handed.
    #[test]
    fn a_scanout_reuses_its_buffers_and_keeps_only_the_latest_frame() {
        let mut fb = MemoryFramebuffer::new();
        assert_eq!(
            fb.alloc_frame(0).err(),
            Some(DisplayError::InvalidScanoutId)
        );
        assert_eq!(
            fb.disable_scanout(0).err(),
            Some(DisplayError::InvalidScanoutId)
        );

        fb.configure_scanout(0, 4, 4, 4, 4, PixelFormat::B8G8R8A8Unorm)
            .expect("a shape this can size");
        assert_eq!(fb.scanout_config(0).map(|c| c.width), Some(4));

        let first = fb.alloc_frame(0).expect("a free slot");
        assert_eq!(first.frame_id, 0);
        assert_eq!(first.buffer.len(), 4 * 4 * 4);
        first.buffer[..4].copy_from_slice(&[1, 2, 3, 4]);
        let first_addr = first.buffer.as_ptr();
        assert_eq!(
            fb.present_frame(0, 9, None).err(),
            Some(DisplayError::InvalidParam),
            "an id nobody was handed"
        );
        fb.present_frame(0, 0, Some(Rect::new(0, 0, 2, 2)))
            .expect("the id that was handed out");
        let latest = fb.latest_frame(0).expect("presented");
        assert_eq!(
            (latest.frame_id, &latest.pixels[..4]),
            (0, &[1, 2, 3, 4][..])
        );
        assert_eq!(latest.damage, Some(Rect::new(0, 0, 2, 2)));
        assert_eq!(
            latest.pixels.as_ptr(),
            first_addr,
            "the frame is the slot, not a copy"
        );
        assert_eq!(latest.to_frame().pixels[..4], [1, 2, 3, 4]);

        // Run the ring dry: RING allocations may be outstanding beside the latest, and the next
        // is refused.
        let mut handed = Vec::new();
        for _ in 0..RING {
            handed.push(fb.alloc_frame(0).expect("a free slot").frame_id);
        }
        assert_eq!(handed, [1, 2, 3]);
        assert_eq!(fb.alloc_frame(0).err(), Some(DisplayError::OutOfBuffers));
        for id in handed {
            fb.present_frame(0, id, None).expect("each comes back");
        }
        assert_eq!(fb.latest_frame(0).map(|f| f.frame_id), Some(3));

        // Warm: the slot frame 0 was written into has been freed and comes round again.
        let mut seen = Vec::new();
        for _ in 0..SLOTS {
            let f = fb.alloc_frame(0).expect("a free slot");
            seen.push(f.buffer.as_ptr());
            let id = f.frame_id;
            fb.present_frame(0, id, None).expect("back");
        }
        assert!(
            seen.contains(&first_addr),
            "the first slot never came back round"
        );

        fb.configure_scanout(0, 8, 8, 8, 8, PixelFormat::B8G8R8A8Unorm)
            .expect("reconfigure");
        assert_eq!(fb.alloc_frame(0).expect("resized").buffer.len(), 8 * 8 * 4);
        assert_eq!(
            fb.configure_scanout(1, 1, 1, 1, 1, PixelFormat::Unknown(5))
                .err(),
            Some(DisplayError::InvalidParam),
            "a shape this cannot size is refused, not sized by guess"
        );
        fb.disable_scanout(0).expect("configured");
        assert!(fb.scanout_config(0).is_none());
    }

    /// The ids `MemoryFramebuffer` hands out stay inside what the vtable can carry.
    #[test]
    fn frame_ids_wrap_inside_the_i32_range() {
        let mut fb = MemoryFramebuffer::new();
        fb.configure_scanout(0, 1, 1, 1, 1, PixelFormat::B8G8R8A8Unorm)
            .expect("a shape");
        let scanout = fb.scanouts.get_mut(&0).expect("configured");
        scanout.next_id = MAX_FRAME_ID;
        let id = fb.alloc_frame(0).expect("a slot").frame_id;
        assert_eq!(id, MAX_FRAME_ID);
        fb.present_frame(0, id, None).expect("back");
        assert_eq!(fb.alloc_frame(0).expect("a slot").frame_id, 0);
    }

    /// A backend for the trampoline tests: records every call, answers with whatever it was told
    /// to, and lends a buffer it never resizes while a frame is out.
    struct Recorder {
        calls: Vec<String>,
        answer: Result<(), DisplayError>,
        frame_id: u32,
        buffer: Vec<u8>,
        panic_next: bool,
    }

    impl Default for Recorder {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                answer: Ok(()),
                frame_id: 0,
                buffer: Vec::new(),
                panic_next: false,
            }
        }
    }

    // SAFETY: `buffer` is resized nowhere; the slice handed out is stable until the recorder is
    // destroyed, which happens after every frame is presented in these tests.
    unsafe impl DisplayBackend for Recorder {
        fn configure_scanout(
            &mut self,
            id: u32,
            dw: u32,
            dh: u32,
            w: u32,
            h: u32,
            format: PixelFormat,
        ) -> Result<(), DisplayError> {
            if self.panic_next {
                self.panic_next = false;
                #[allow(clippy::panic)]
                {
                    panic!("a backend that panics");
                }
            }
            self.calls
                .push(format!("configure {id} {dw}x{dh} {w}x{h} {format:?}"));
            self.answer
        }
        fn disable_scanout(&mut self, id: u32) -> Result<(), DisplayError> {
            self.calls.push(format!("disable {id}"));
            self.answer
        }
        fn alloc_frame(&mut self, id: u32) -> Result<FrameAllocation<'_>, DisplayError> {
            self.calls.push(format!("alloc {id}"));
            self.answer?;
            Ok(FrameAllocation::new(self.frame_id, &mut self.buffer))
        }
        fn present_frame(
            &mut self,
            id: u32,
            frame: u32,
            damage: Option<Rect>,
        ) -> Result<(), DisplayError> {
            self.calls.push(format!("present {id} {frame} {damage:?}"));
            self.answer
        }
    }

    /// A shared scanout lives in a memfd sealed to its size, and a second mapping of that fd
    /// reads the frame the backend presented, by the slot the event named, with no copy between.
    #[test]
    fn a_shared_scanout_is_a_sealed_memfd_a_second_mapping_reads() {
        use rustix::fs::SealFlags;
        let mut fb = MemoryFramebuffer::shared();
        assert!(fb.share(0).expect("no scanout is not an error").is_none());
        fb.configure_scanout(0, 2, 2, 2, 2, PixelFormat::B8G8R8X8Unorm)
            .expect("configured");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        fb.watch(move |e| {
            log.lock().expect("unpoisoned").push(*e);
            true
        });
        let alloc = fb.alloc_frame(0).expect("a slot");
        let id = alloc.frame_id;
        alloc.buffer[..4].copy_from_slice(&[7, 8, 9, 10]);
        fb.present_frame(0, id, None).expect("presented");

        let (fd, layout) = fb.share(0).expect("shareable").expect("configured");
        assert_eq!(
            (layout.width, layout.height, layout.slots),
            (2, 2, SLOTS as u32)
        );
        assert_eq!(layout.slot_bytes, 16);
        assert_eq!(layout.stride, 8);
        let seals = rustix::fs::fcntl_get_seals(&fd).expect("seals readable");
        assert!(seals.contains(SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL));

        let events = seen.lock().expect("unpoisoned").clone();
        assert!(
            matches!(events[..], [Event::Presented { .. }]),
            "one present event: {events:?}"
        );
        let Some(Event::Presented { frame_id, slot, .. }) = events.first().copied() else {
            return;
        };
        let mapped = SharedFrames::map(fd, layout).expect("mapped");
        let view = mapped.frame(frame_id, slot).expect("in the layout");
        assert_eq!(&view.pixels[..4], &[7, 8, 9, 10]);
        assert!(
            mapped.frame(0, layout.slots).is_none(),
            "a slot past the layout"
        );

        assert!(
            MemoryFramebuffer::new().share(0).is_ok(),
            "no scanout on a heap framebuffer is still None"
        );
        let mut heap = MemoryFramebuffer::new();
        heap.configure_scanout(0, 1, 1, 1, 1, PixelFormat::B8G8R8X8Unorm)
            .expect("configured");
        assert_eq!(
            heap.share(0)
                .map(drop)
                .expect_err("heap is not shareable")
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    /// A reconfigure to the same size keeps the allocation and tells nobody; one to a new size
    /// makes a new allocation, bumps the generation, and tells every watcher, and a watcher that
    /// answers `false` is dropped there and then.
    #[test]
    fn a_resize_tells_watchers_and_a_watcher_may_leave() {
        let mut fb = MemoryFramebuffer::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        fb.watch(move |e| {
            log.lock().expect("unpoisoned").push(*e);
            !matches!(e, Event::Reconfigured { .. })
        });
        fb.configure_scanout(0, 2, 2, 2, 2, PixelFormat::B8G8R8X8Unorm)
            .expect("configured");
        fb.configure_scanout(0, 2, 2, 2, 2, PixelFormat::B8G8R8X8Unorm)
            .expect("the same shape again");
        assert!(
            seen.lock().expect("unpoisoned").is_empty(),
            "same size: silent"
        );
        fb.configure_scanout(0, 4, 4, 4, 4, PixelFormat::B8G8R8X8Unorm)
            .expect("a new size");
        assert_eq!(
            seen.lock().expect("unpoisoned").as_slice(),
            &[Event::Reconfigured {
                scanout_id: 0,
                generation: 1
            }]
        );
        assert_eq!(fb.watchers.len(), 0, "the watcher left on the reconfigure");
        let id = fb.alloc_frame(0).expect("a slot").frame_id;
        fb.present_frame(0, id, None).expect("presented");
        assert_eq!(
            seen.lock().expect("unpoisoned").len(),
            1,
            "nobody left to tell"
        );
    }

    /// The wake runs once per present and for nothing else, so a compositor woken by it has a
    /// frame to show every time and is never woken for a configure or an allocation.
    #[test]
    fn a_present_wakes_the_listener_and_nothing_else_does() {
        let woken = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut fb = MemoryFramebuffer::new();
        let count = Arc::clone(&woken);
        fb.set_wake(move || {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        fb.configure_scanout(0, 2, 2, 2, 2, PixelFormat::B8G8R8X8Unorm)
            .expect("configured");
        let first = fb.alloc_frame(0).expect("a slot").frame_id;
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 0);
        fb.present_frame(0, first, None).expect("presented");
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 1);
        let second = fb.alloc_frame(0).expect("a slot").frame_id;
        fb.present_frame(0, second, None).expect("presented");
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(
            fb.present_frame(0, 999, None).is_err(),
            "a refused present wakes nobody"
        );
        assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    /// A recorder as libkrun would hold it: the shared handle, the raw userdata, and an instance
    /// created through the real `c_create`.
    fn instance_of(recorder: Recorder) -> (Arc<Backend<Recorder>>, *const c_void, *mut c_void) {
        let shared: Arc<Backend<Recorder>> = Arc::new(Mutex::new(recorder));
        let userdata = Arc::into_raw(Arc::clone(&shared)).cast::<c_void>();
        let mut instance: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe { c_create::<Recorder>(&mut instance, userdata, std::ptr::null()) },
            0
        );
        (shared, userdata, instance)
    }

    /// Finishes with the recorder: destroys the instance, returns the userdata count, and hands
    /// back what was recorded.
    fn calls_of(
        shared: Arc<Backend<Recorder>>,
        userdata: *const c_void,
        instance: *mut c_void,
    ) -> Vec<String> {
        assert_eq!(unsafe { c_destroy::<Recorder>(instance) }, 0);
        drop(unsafe { Arc::from_raw(userdata.cast::<Backend<Recorder>>()) });
        assert_eq!(Arc::strong_count(&shared), 1, "every count came back");
        // Recovered, not required: a backend that panicked poisoned it, and reading what it
        // recorded before that is the point.
        let guard = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.calls.clone()
    }

    /// Each callback reaches the backend with its arguments intact, hands libkrun the buffer and
    /// id it was given, and carries a backend's error back as the code it named.
    #[test]
    fn the_trampolines_carry_calls_and_answers_across_the_boundary() {
        let (shared, userdata, instance) = instance_of(Recorder {
            frame_id: 42,
            buffer: vec![0; 16],
            ..Recorder::default()
        });
        assert_eq!(
            unsafe { c_configure_scanout::<Recorder>(instance, 0, 320, 240, 32, 24, 1) },
            0
        );
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        assert_eq!(
            unsafe { c_alloc_frame::<Recorder>(instance, 0, &mut buf, &mut len) },
            42
        );
        assert_eq!(len, 16);
        unsafe { std::slice::from_raw_parts_mut(buf, 4) }.copy_from_slice(&[9, 8, 7, 6]);
        let damage = sys::krun_rect {
            x: 1,
            y: 2,
            width: 3,
            height: 4,
        };
        assert_eq!(
            unsafe { c_present_frame::<Recorder>(instance, 0, 42, &damage) },
            0
        );
        assert_eq!(
            unsafe { c_present_frame::<Recorder>(instance, 0, 42, std::ptr::null()) },
            0
        );
        assert_eq!(unsafe { c_disable_scanout::<Recorder>(instance, 0) }, 0);
        {
            let guard = shared
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(&guard.buffer[..4], &[9, 8, 7, 6], "libkrun's write landed");
        }
        assert_eq!(
            calls_of(shared, userdata, instance),
            [
                "configure 0 320x240 32x24 B8G8R8A8Unorm",
                "alloc 0",
                "present 0 42 Some(Rect { x: 1, y: 2, width: 3, height: 4 })",
                "present 0 42 None",
                "disable 0",
            ]
        );

        let custom = NonZeroI32::new(-9).expect("non-zero");
        let (shared, userdata, instance) = instance_of(Recorder {
            answer: Err(DisplayError::Custom(custom)),
            ..Recorder::default()
        });
        assert_eq!(unsafe { c_disable_scanout::<Recorder>(instance, 3) }, -9);
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        assert_eq!(
            unsafe { c_alloc_frame::<Recorder>(instance, 3, &mut buf, &mut len) },
            -9
        );
        assert!(
            buf.is_null() && len == 0,
            "a refused alloc writes nothing back"
        );
        calls_of(shared, userdata, instance);
    }

    /// What the trampolines refuse before the backend is asked: a null instance, a null output
    /// pointer, and a frame id the vtable cannot carry.
    #[test]
    fn the_trampolines_refuse_what_the_boundary_cannot_carry() {
        let null = std::ptr::null_mut();
        assert_eq!(
            unsafe { c_configure_scanout::<Recorder>(null, 0, 1, 1, 1, 1, 1) },
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM
        );
        assert_eq!(
            unsafe { c_disable_scanout::<Recorder>(null, 0) },
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM
        );
        assert_eq!(
            unsafe { c_present_frame::<Recorder>(null, 0, 0, std::ptr::null()) },
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM
        );
        assert_eq!(
            unsafe { c_destroy::<Recorder>(null) },
            0,
            "nothing to destroy is not an error"
        );
        let mut instance: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe { c_create::<Recorder>(&mut instance, std::ptr::null(), std::ptr::null()) },
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM
        );

        // `1 << 31`, not `u32::MAX`: the latter sign-flips to -1, which is `ERR_INTERNAL` too,
        // and the assertion held with the cap removed (watched). This one flips to `i32::MIN`.
        let (shared, userdata, instance) = instance_of(Recorder {
            frame_id: 1 << 31,
            buffer: vec![0; 4],
            ..Recorder::default()
        });
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 0;
        assert_eq!(
            unsafe { c_alloc_frame::<Recorder>(instance, 0, std::ptr::null_mut(), &mut len) },
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM
        );
        assert_eq!(
            unsafe { c_alloc_frame::<Recorder>(instance, 0, &mut buf, &mut len) },
            sys::KRUN_DISPLAY_ERR_INTERNAL,
            "an id above i32::MAX would arrive as some other error; it is refused as this one"
        );
        calls_of(shared, userdata, instance);

        // The largest id that fits is not refused: the cap is exactly the type's edge.
        let (shared, userdata, instance) = instance_of(Recorder {
            frame_id: MAX_FRAME_ID,
            buffer: vec![0; 4],
            ..Recorder::default()
        });
        assert_eq!(
            unsafe { c_alloc_frame::<Recorder>(instance, 0, &mut buf, &mut len) },
            i32::MAX
        );
        calls_of(shared, userdata, instance);
    }

    /// A panic in the backend is reported as an internal error, not unwound into libkrun, and
    /// the backend keeps answering afterwards: the lock it poisoned is recovered, not refused.
    #[test]
    fn a_panicking_backend_reports_internal_and_keeps_answering() {
        let (shared, userdata, instance) = instance_of(Recorder {
            panic_next: true,
            ..Recorder::default()
        });
        assert_eq!(
            unsafe { c_configure_scanout::<Recorder>(instance, 0, 1, 1, 1, 1, 1) },
            sys::KRUN_DISPLAY_ERR_INTERNAL
        );
        assert_eq!(
            unsafe { c_configure_scanout::<Recorder>(instance, 0, 1, 1, 1, 1, 1) },
            0
        );
        assert_eq!(
            calls_of(shared, userdata, instance),
            ["configure 0 1x1 1x1 B8G8R8A8Unorm"],
            "the panicking call recorded nothing; the next recorded normally"
        );
    }

    /// The count a machine hands libkrun as userdata comes back when the machine goes without
    /// starting, so a backend is not held forever by a `display_backend` that never booted.
    #[test]
    fn a_display_handle_returns_its_count_when_dropped() {
        let shared: Arc<Backend<MemoryFramebuffer>> =
            Arc::new(Mutex::new(MemoryFramebuffer::new()));
        let handle = DisplayHandle {
            userdata: Arc::into_raw(Arc::clone(&shared)).cast::<c_void>(),
            release: release_backend::<MemoryFramebuffer>,
            _table: Box::new(sys::krun_display_backend {
                features: 0,
                create_userdata: std::ptr::null(),
                create: None,
                vtable: sys::krun_display_vtable {
                    basic_framebuffer: sys::krun_display_basic_framebuffer_vtable {
                        destroy: None,
                        disable_scanout: None,
                        configure_scanout: None,
                        alloc_frame: None,
                        present_frame: None,
                    },
                },
            }),
        };
        assert_eq!(Arc::strong_count(&shared), 2);
        drop(handle);
        assert_eq!(Arc::strong_count(&shared), 1);
    }

    /// A device instance as libkrun would hold it: the shared handle, the raw userdata, and an
    /// instance created through the real `c_input_create`.
    fn input_instance<T>(shared: &Arc<T>) -> (*const c_void, *mut c_void) {
        let userdata = Arc::into_raw(Arc::clone(shared)).cast::<c_void>();
        let mut instance: *mut c_void = std::ptr::null_mut();
        assert_eq!(
            unsafe { c_input_create::<T>(&mut instance, userdata, std::ptr::null()) },
            0
        );
        (userdata, instance)
    }

    /// Destroys the instance and returns the userdata count, then checks both came back.
    fn input_finish<T>(shared: &Arc<T>, userdata: *const c_void, instance: *mut c_void) {
        assert_eq!(unsafe { c_input_destroy::<T>(instance) }, 0);
        drop(unsafe { Arc::from_raw(userdata.cast::<T>()) });
        assert_eq!(Arc::strong_count(shared), 1, "every count came back");
    }

    /// Whether `fd` is readable now, which for the ready fd means an event waits.
    fn readable(fd: &OwnedFd) -> bool {
        use rustix::event::{PollFd, PollFlags};
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        let now = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        rustix::event::poll(&mut fds, Some(&now)).expect("poll") == 1
    }

    /// The identity queries the guest's driver makes at probe come back through the table with
    /// the device's answers: names cut to the buffer, ids, bitmaps with the right bits and the
    /// right length, and axis ranges.
    #[test]
    fn an_input_device_answers_the_probe_queries_through_its_table() {
        let device = Arc::new(
            InputDevice::new("bsx test device")
                .serial("SERIAL-1")
                .ids(6, 0x1234, 0x5678, 2)
                .keys([1, 30, 0x110])
                .relative_axes([8])
                .absolute_axis(0, AbsInfo::range(0, 32767))
                .properties([1]),
        );
        let (userdata, instance) = input_instance(&device);

        let mut name = [0u8; 4];
        let got = unsafe { c_query_device_name(instance, name.as_mut_ptr(), name.len()) };
        assert_eq!((got, &name[..]), (4, &b"bsx "[..]), "cut to the buffer");
        let mut serial = [0u8; 128];
        let got = unsafe { c_query_serial_name(instance, serial.as_mut_ptr(), serial.len()) };
        assert_eq!((got, &serial[..8]), (8, &b"SERIAL-1"[..]));

        let mut ids = sys::krun_input_device_ids {
            bustype: 0,
            vendor: 0,
            product: 0,
            version: 0,
        };
        assert_eq!(unsafe { c_query_device_ids(instance, &mut ids) }, 0);
        assert_eq!(
            (ids.bustype, ids.vendor, ids.product, ids.version),
            (6, 0x1234, 0x5678, 2)
        );

        let mut bitmap = [0u8; 128];
        let got =
            unsafe { c_query_event_capabilities(instance, 1, bitmap.as_mut_ptr(), bitmap.len()) };
        assert_eq!(got, 0x110 / 8 + 1, "the length covers the highest key");
        assert_eq!(bitmap[0], 0b10, "key 1");
        assert_eq!(bitmap[3], 1 << 6, "key 30");
        assert_eq!(bitmap[0x110 / 8], 1, "BTN_LEFT");
        let mut bitmap = [0u8; 128];
        let got =
            unsafe { c_query_event_capabilities(instance, 3, bitmap.as_mut_ptr(), bitmap.len()) };
        assert_eq!((got, bitmap[0]), (1, 1), "ABS_X alone");
        let mut bitmap = [0u8; 128];
        let got =
            unsafe { c_query_event_capabilities(instance, 5, bitmap.as_mut_ptr(), bitmap.len()) };
        assert_eq!(got, 0, "a type the device does not emit");
        let mut small = [0u8; 1];
        let got = unsafe { c_query_event_capabilities(instance, 1, small.as_mut_ptr(), 1) };
        assert_eq!(
            got,
            sys::KRUN_INPUT_ERR_INVALID_PARAM,
            "a code past the buffer"
        );

        let mut info = sys::krun_input_absinfo {
            min: 9,
            max: 9,
            fuzz: 9,
            flat: 9,
            res: 9,
        };
        assert_eq!(unsafe { c_query_abs_info(instance, 0, &mut info) }, 0);
        assert_eq!((info.min, info.max, info.fuzz), (0, 32767, 0));
        assert_eq!(unsafe { c_query_abs_info(instance, 1, &mut info) }, 0);
        assert_eq!(info.max, 0, "an axis the device lacks reads as nothing");

        let mut props = [0u8; 128];
        let got = unsafe { c_query_properties(instance, props.as_mut_ptr(), props.len()) };
        assert_eq!((got, props[0]), (1, 0b10));

        assert_eq!(
            unsafe { c_query_device_name(instance, std::ptr::null_mut(), 8) },
            sys::KRUN_INPUT_ERR_INVALID_PARAM
        );
        input_finish(&device, userdata, instance);
    }

    /// Events cross in the order sent, a batch arrives whole or not at all, and the ready fd is
    /// readable exactly while one waits: libkrun polls it level-triggered and never reads it.
    #[test]
    fn queued_events_cross_in_order_and_arm_the_fd_only_while_one_waits() {
        let queue = Arc::new(Mutex::new(InputQueue::new().expect("an eventfd")));
        let sender = InputSender(Arc::clone(&queue));
        let (userdata, instance) = input_instance(&queue);
        let fd = unsafe { c_get_ready_efd(instance) };
        let ready = queue.lock().expect("unpoisoned").ready.as_raw_fd();
        assert_eq!(fd, ready, "the fd libkrun polls is the queue's");
        let fd_of = |q: &Arc<Mutex<InputQueue>>| {
            let guard = q.lock().expect("unpoisoned");
            guard.ready.try_clone().expect("dup")
        };
        assert!(!readable(&fd_of(&queue)), "nothing waits yet");

        sender
            .send(&[InputEvent::new(EV_KEY, 30, 1), InputEvent::syn_report()])
            .expect("queued");
        assert!(readable(&fd_of(&queue)), "armed by the send");
        let mut out = sys::krun_input_event {
            type_: 9,
            code: 9,
            value: 9,
        };
        assert_eq!(unsafe { c_next_event(instance, &mut out) }, 1);
        assert_eq!((out.type_, out.code, out.value), (EV_KEY, 30, 1));
        assert!(readable(&fd_of(&queue)), "still armed: one waits");
        assert_eq!(unsafe { c_next_event(instance, &mut out) }, 1);
        assert_eq!((out.type_, out.code, out.value), (EV_SYN, 0, 0));
        assert_eq!(unsafe { c_next_event(instance, &mut out) }, 0);
        assert!(
            !readable(&fd_of(&queue)),
            "disarmed by the pop that found nothing"
        );

        sender
            .send(&[InputEvent::new(EV_REL, 8, -1)])
            .expect("queued");
        assert!(readable(&fd_of(&queue)), "armed again");
        assert_eq!(unsafe { c_next_event(instance, &mut out) }, 1);
        assert_eq!(out.value, u32::MAX, "a negative value crosses as its bits");

        let filler = vec![InputEvent::syn_report(); INPUT_QUEUE_CAP];
        sender.send(&filler).expect("exactly the cap fits");
        assert_eq!(
            sender.send(&[InputEvent::syn_report()]),
            Err(QueueFull),
            "one more is refused"
        );
        assert_eq!(
            queue.lock().expect("unpoisoned").events.len(),
            INPUT_QUEUE_CAP,
            "and nothing of the refused batch was queued"
        );
        assert_eq!(
            unsafe { c_next_event(instance, std::ptr::null_mut()) },
            sys::KRUN_INPUT_ERR_INVALID_PARAM
        );
        drop(sender);
        input_finish(&queue, userdata, instance);
    }

    /// `with_input` refuses a null instance and turns a panic into the internal code.
    #[test]
    fn an_input_callback_refuses_a_null_and_contains_a_panic() {
        assert_eq!(
            with_input::<InputDevice>(std::ptr::null_mut(), |_| 0),
            sys::KRUN_INPUT_ERR_INVALID_PARAM
        );
        let device = Arc::new(InputDevice::new("p"));
        let (userdata, instance) = input_instance(&device);
        #[allow(clippy::panic)]
        let got = with_input::<InputDevice>(instance, |_| panic!("a callback that panics"));
        assert_eq!(got, sys::KRUN_INPUT_ERR_INTERNAL);
        assert_eq!(
            with_input::<InputDevice>(instance, |_| 7),
            7,
            "still answers"
        );
        input_finish(&device, userdata, instance);
    }

    /// A code the 128-byte bitmap cannot hold is refused before libkrun is asked, as the typed
    /// error, and one that just fits is not.
    #[test]
    fn an_input_code_past_the_bitmap_is_refused_before_the_call() {
        let fits = InputDevice::new("k").keys([CAPABILITY_BITS - 1]);
        assert!(fits.check_fits().is_ok());
        let over = InputDevice::new("k").properties([CAPABILITY_BITS]);
        let refused = over.check_fits();
        assert!(
            matches!(
                refused,
                Err(Error::OutOfRange {
                    value: 1024,
                    max: 1023,
                    ..
                })
            ),
            "expected OutOfRange, got {refused:?}"
        );
        assert_eq!(write_bitmap(&mut [0u8; 2], [15]), Some(2));
        assert_eq!(write_bitmap(&mut [0u8; 2], [16]), None);
        assert_eq!(write_bitmap(&mut [0u8; 2], []), Some(0));
    }

    /// An input handle returns both counts when dropped, which is the path a refused
    /// `krun_add_input_device` takes.
    #[test]
    fn an_input_handle_returns_its_counts_when_dropped() {
        let device = Arc::new(InputDevice::new("h"));
        let queue = Arc::new(Mutex::new(InputQueue::new().expect("an eventfd")));
        let handle = InputHandle {
            device: Arc::into_raw(Arc::clone(&device)).cast::<c_void>(),
            queue: Arc::into_raw(Arc::clone(&queue)).cast::<c_void>(),
            _config: Box::new(sys::krun_input_config {
                features: 0,
                create_userdata: std::ptr::null(),
                create: None,
                vtable: sys::krun_input_config_vtable {
                    destroy: None,
                    query_device_name: None,
                    query_serial_name: None,
                    query_device_ids: None,
                    query_event_capabilities: None,
                    query_abs_info: None,
                    query_properties: None,
                },
            }),
            _events: Box::new(sys::krun_input_event_provider {
                features: 0,
                create_userdata: std::ptr::null(),
                create: None,
                vtable: sys::krun_input_event_provider_vtable {
                    destroy: None,
                    get_ready_efd: None,
                    next_event: None,
                },
            }),
        };
        assert_eq!(
            (Arc::strong_count(&device), Arc::strong_count(&queue)),
            (2, 2)
        );
        drop(handle);
        assert_eq!(
            (Arc::strong_count(&device), Arc::strong_count(&queue)),
            (1, 1)
        );
    }
}
