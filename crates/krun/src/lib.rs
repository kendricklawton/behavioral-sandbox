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

mod sys;

use std::collections::HashMap;
use std::ffi::{CString, NulError, OsStr};
use std::fmt;
use std::marker::PhantomData;
use std::num::{NonZeroI32, NonZeroU8, NonZeroU32, NonZeroUsize};
use std::os::raw::{c_char, c_void};
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
    /// This build links no libkrun: `build.rs` found none, so every call is a stub that reports
    /// the library as missing rather than an errno a stub would have had to invent.
    NotLinked {
        /// The `krun_*` function that was asked for.
        call: &'static str,
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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Call { source, .. } => Some(source),
            Self::InteriorNul { .. } | Self::NotLinked { .. } => None,
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

/// The largest frame id handed out: ids cross the vtable as the non-negative half of an `i32`.
const MAX_FRAME_ID: u32 = i32::MAX as u32;

/// A buffer libkrun may be writing into, and the id it was handed out under.
#[derive(Debug, Default)]
struct Slot {
    /// `Some` while handed out and not yet presented.
    frame_id: Option<u32>,
    pixels: Vec<u8>,
}

/// One scanout: its shape, the buffers libkrun draws into, and the frame it last presented.
#[derive(Debug)]
struct Scanout {
    config: ScanoutConfig,
    ring: [Slot; RING],
    latest: Option<Frame>,
    next_id: u32,
}

/// A display backend that keeps each scanout's latest frame in host RAM, for a compositor in this
/// process to read under the lock.
///
/// **No history, and no allocation once warm.** A scanout owns `RING` buffers to hand out and
/// one presented frame; presenting swaps the filled buffer with the previous frame's, so at steady
/// state the bytes move owners and nothing is allocated or zeroed. A history of frames would be
/// that many copies of the screen for a reader that wants the newest one.
#[derive(Debug, Default)]
pub struct MemoryFramebuffer {
    scanouts: HashMap<u32, Scanout>,
}

impl MemoryFramebuffer {
    /// An empty framebuffer: no scanouts until libkrun configures one.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How `scanout_id` is configured, if it is.
    #[must_use]
    pub fn scanout_config(&self, scanout_id: u32) -> Option<ScanoutConfig> {
        self.scanouts.get(&scanout_id).map(|s| s.config)
    }

    /// The frame most recently presented on `scanout_id`, if one has been.
    #[must_use]
    pub fn latest_frame(&self, scanout_id: u32) -> Option<&Frame> {
        self.scanouts.get(&scanout_id)?.latest.as_ref()
    }
}

// SAFETY: the memory handed out is a slot's `pixels`, a heap `Vec` whose allocation changes only
// in `alloc_frame` for a slot that is not handed out, in `present_frame` for the slot being taken
// back (a swap moves the allocation between owners and leaves its address alone), and in
// `configure_scanout` and `disable_scanout`, after which the header says libkrun has abandoned
// every frame of that scanout. Nothing else touches a handed-out slot.
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
        config.frame_size()?;
        let scanout = self.scanouts.entry(scanout_id).or_insert_with(|| Scanout {
            config,
            ring: Default::default(),
            latest: None,
            next_id: 0,
        });
        scanout.config = config;
        for slot in &mut scanout.ring {
            slot.frame_id = None;
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
        let size = scanout.config.frame_size()?;
        let slot = scanout
            .ring
            .iter_mut()
            .find(|s| s.frame_id.is_none())
            .ok_or(DisplayError::OutOfBuffers)?;
        let frame_id = scanout.next_id;
        scanout.next_id = if frame_id == MAX_FRAME_ID {
            0
        } else {
            frame_id + 1
        };
        slot.frame_id = Some(frame_id);
        slot.pixels.resize(size, 0);
        Ok(FrameAllocation::new(frame_id, &mut slot.pixels))
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
            .ring
            .iter_mut()
            .find(|s| s.frame_id == Some(frame_id))
            .ok_or(DisplayError::InvalidParam)?;
        slot.frame_id = None;
        // The filled buffer becomes the frame, and the previous frame's buffer becomes the free
        // slot: no bytes copied, nothing allocated.
        let pixels = std::mem::take(&mut slot.pixels);
        if let Some(previous) = scanout.latest.take() {
            slot.pixels = previous.pixels;
        }
        let config = scanout.config;
        scanout.latest = Some(Frame {
            frame_id,
            width: config.width,
            height: config.height,
            format: config.format,
            pixels,
            damage,
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
        })
    }
}

/// A context with a root filesystem, being configured toward [`enter`](Self::enter).
#[derive(Debug)]
pub struct Machine {
    ctx: Ctx,
    retained: Vec<CString>,
    retained_display: Option<DisplayHandle>,
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
            "the frame is the buffer, not a copy"
        );

        // Run the ring dry: RING allocations may be outstanding, and the next is refused.
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

        // Warm: the buffer frame 0 was written into has been recycled and comes round again.
        let mut seen = Vec::new();
        for _ in 0..RING + 1 {
            let f = fb.alloc_frame(0).expect("a free slot");
            seen.push(f.buffer.as_ptr());
            let id = f.frame_id;
            fb.present_frame(0, id, None).expect("back");
        }
        assert!(
            seen.contains(&first_addr),
            "the first buffer never came back round"
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
}
