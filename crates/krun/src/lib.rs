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

use std::collections::HashMap;
use std::ffi::{CString, NulError, OsStr};
use std::fmt;
use std::marker::PhantomData;
use std::num::{NonZeroU8, NonZeroU32};
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

/// Errors returned by display backend callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisplayError {
    /// Internal display error (`KRUN_DISPLAY_ERR_INTERNAL`).
    Internal,
    /// Method unsupported error (`KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED`).
    MethodUnsupported,
    /// Invalid scanout ID (`KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID`).
    InvalidScanoutId,
    /// Invalid parameter (`KRUN_DISPLAY_ERR_INVALID_PARAM`).
    InvalidParam,
    /// Out of buffers (`KRUN_DISPLAY_ERR_OUT_OF_BUFFERS`).
    OutOfBuffers,
    /// A custom negative errno return code.
    Custom(i32),
}

impl DisplayError {
    /// Converts this error into libkrun's negative return code.
    pub fn to_raw(self) -> i32 {
        match self {
            Self::Internal => sys::KRUN_DISPLAY_ERR_INTERNAL,
            Self::MethodUnsupported => sys::KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED,
            Self::InvalidScanoutId => sys::KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID,
            Self::InvalidParam => sys::KRUN_DISPLAY_ERR_INVALID_PARAM,
            Self::OutOfBuffers => sys::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS,
            Self::Custom(code) => {
                if code < 0 {
                    code
                } else {
                    -code
                }
            }
        }
    }

    /// Creates a [`DisplayError`] from a raw negative return code.
    pub fn from_raw(code: i32) -> Self {
        match code {
            sys::KRUN_DISPLAY_ERR_INTERNAL => Self::Internal,
            sys::KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED => Self::MethodUnsupported,
            sys::KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID => Self::InvalidScanoutId,
            sys::KRUN_DISPLAY_ERR_INVALID_PARAM => Self::InvalidParam,
            sys::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS => Self::OutOfBuffers,
            other => Self::Custom(other),
        }
    }
}

/// Pixel format returned during scanout configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PixelFormat {
    /// `B8G8R8A8_UNORM` pixel format.
    B8G8R8A8Unorm,
    /// `B8G8R8X8_UNORM` pixel format.
    B8G8R8X8Unorm,
    /// `A8R8G8B8_UNORM` pixel format.
    A8R8G8B8Unorm,
    /// `X8R8G8B8_UNORM` pixel format.
    X8R8G8B8Unorm,
    /// `R8G8B8A8_UNORM` pixel format.
    R8G8B8A8Unorm,
    /// `X8B8G8R8_UNORM` pixel format.
    X8B8G8R8Unorm,
    /// `A8B8G8R8_UNORM` pixel format.
    A8B8G8R8Unorm,
    /// `R8G8B8X8_UNORM` pixel format.
    R8G8B8X8Unorm,
    /// An unknown format ID.
    Unknown(u32),
}

impl PixelFormat {
    /// Creates a [`PixelFormat`] from a raw libkrun format ID.
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

    /// Returns the raw libkrun format ID for this format.
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

    /// Returns the number of bytes per pixel for this format (defaulting to 4).
    pub fn bytes_per_pixel(self) -> usize {
        match self {
            Self::B8G8R8A8Unorm
            | Self::B8G8R8X8Unorm
            | Self::A8R8G8B8Unorm
            | Self::X8R8G8B8Unorm
            | Self::R8G8B8A8Unorm
            | Self::X8B8G8R8Unorm
            | Self::A8B8G8R8Unorm
            | Self::R8G8B8X8Unorm => 4,
            Self::Unknown(_) => 4,
        }
    }
}

/// A rectangle describing a damage region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    /// X coordinate of rectangle origin.
    pub x: u32,
    /// Y coordinate of rectangle origin.
    pub y: u32,
    /// Width of rectangle.
    pub width: u32,
    /// Height of rectangle.
    pub height: u32,
}

/// An allocated frame buffer handed to libkrun to write pixel data into.
#[derive(Debug)]
pub struct FrameAllocation<'a> {
    /// The frame identifier assigned to this buffer.
    pub frame_id: u32,
    /// The mutable byte slice where pixel data will be written.
    pub buffer: &'a mut [u8],
}

/// Trait implemented by display backends to render guest scanouts.
pub trait DisplayBackend: std::fmt::Debug + Send {
    /// Configures or reconfigures a scanout display.
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> Result<(), DisplayError>;

    /// Disables a display scanout.
    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayError>;

    /// Allocates a new frame buffer for `scanout_id`.
    fn alloc_frame(&mut self, scanout_id: u32) -> Result<FrameAllocation<'_>, DisplayError>;

    /// Presents a previously allocated frame to the display.
    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        damage: Option<Rect>,
    ) -> Result<(), DisplayError>;
}

/// Shared wrapper for display backend callback trampolines.
type SharedDisplayBackend = Arc<Mutex<Option<Box<dyn DisplayBackend>>>>;

unsafe extern "C" fn c_create(
    instance: *mut *mut c_void,
    userdata: *const c_void,
    _reserved: *const c_void,
) -> i32 {
    let res = std::panic::catch_unwind(move || {
        if instance.is_null() || userdata.is_null() {
            return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
        }
        unsafe {
            Arc::increment_strong_count(userdata as *const Mutex<Option<Box<dyn DisplayBackend>>>);
            *instance = userdata as *mut c_void;
        }
        0
    });
    res.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

unsafe extern "C" fn c_destroy(instance: *mut c_void) -> i32 {
    let res = std::panic::catch_unwind(move || {
        if !instance.is_null() {
            let _ =
                unsafe { Arc::from_raw(instance as *const Mutex<Option<Box<dyn DisplayBackend>>>) };
        }
        0
    });
    res.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

unsafe extern "C" fn c_configure_scanout(
    instance: *mut c_void,
    scanout_id: u32,
    display_width: u32,
    display_height: u32,
    width: u32,
    height: u32,
    format: u32,
) -> i32 {
    let res = std::panic::catch_unwind(move || {
        if instance.is_null() {
            return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
        }
        let arc = std::mem::ManuallyDrop::new(unsafe {
            Arc::from_raw(instance as *const Mutex<Option<Box<dyn DisplayBackend>>>)
        });
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(backend) = guard.as_mut() else {
            return sys::KRUN_DISPLAY_ERR_INTERNAL;
        };
        let fmt = PixelFormat::from_raw(format);
        match backend.configure_scanout(
            scanout_id,
            display_width,
            display_height,
            width,
            height,
            fmt,
        ) {
            Ok(()) => 0,
            Err(err) => err.to_raw(),
        }
    });
    res.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

unsafe extern "C" fn c_disable_scanout(instance: *mut c_void, scanout_id: u32) -> i32 {
    let res = std::panic::catch_unwind(move || {
        if instance.is_null() {
            return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
        }
        let arc = std::mem::ManuallyDrop::new(unsafe {
            Arc::from_raw(instance as *const Mutex<Option<Box<dyn DisplayBackend>>>)
        });
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(backend) = guard.as_mut() else {
            return sys::KRUN_DISPLAY_ERR_INTERNAL;
        };
        match backend.disable_scanout(scanout_id) {
            Ok(()) => 0,
            Err(err) => err.to_raw(),
        }
    });
    res.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

unsafe extern "C" fn c_alloc_frame(
    instance: *mut c_void,
    scanout_id: u32,
    buffer: *mut *mut u8,
    buffer_size: *mut usize,
) -> i32 {
    let res = std::panic::catch_unwind(move || {
        if instance.is_null() || buffer.is_null() || buffer_size.is_null() {
            return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
        }
        let arc = std::mem::ManuallyDrop::new(unsafe {
            Arc::from_raw(instance as *const Mutex<Option<Box<dyn DisplayBackend>>>)
        });
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(backend) = guard.as_mut() else {
            return sys::KRUN_DISPLAY_ERR_INTERNAL;
        };
        match backend.alloc_frame(scanout_id) {
            Ok(alloc) => unsafe {
                *buffer = alloc.buffer.as_mut_ptr();
                *buffer_size = alloc.buffer.len();
                alloc.frame_id as i32
            },
            Err(err) => err.to_raw(),
        }
    });
    res.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

unsafe extern "C" fn c_present_frame(
    instance: *mut c_void,
    scanout_id: u32,
    frame_id: u32,
    damage_area: *const sys::krun_rect,
) -> i32 {
    let res = std::panic::catch_unwind(move || {
        if instance.is_null() {
            return sys::KRUN_DISPLAY_ERR_INVALID_PARAM;
        }
        let arc = std::mem::ManuallyDrop::new(unsafe {
            Arc::from_raw(instance as *const Mutex<Option<Box<dyn DisplayBackend>>>)
        });
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let Some(backend) = guard.as_mut() else {
            return sys::KRUN_DISPLAY_ERR_INTERNAL;
        };
        let damage = if damage_area.is_null() {
            None
        } else {
            let r = unsafe { &*damage_area };
            Some(Rect {
                x: r.x,
                y: r.y,
                width: r.width,
                height: r.height,
            })
        };
        match backend.present_frame(scanout_id, frame_id, damage) {
            Ok(()) => 0,
            Err(err) => err.to_raw(),
        }
    });
    res.unwrap_or(sys::KRUN_DISPLAY_ERR_INTERNAL)
}

/// A frame presented by a display scanout.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Scanout identifier.
    pub scanout_id: u32,
    /// Frame identifier.
    pub frame_id: u32,
    /// Width of the frame in pixels.
    pub width: u32,
    /// Height of the frame in pixels.
    pub height: u32,
    /// Pixel format of the frame.
    pub format: PixelFormat,
    /// Raw pixel bytes of the frame.
    pub pixels: Vec<u8>,
    /// Optional damage rectangle hint.
    pub damage: Option<Rect>,
}

/// Scanout configuration state.
#[derive(Debug, Clone, Copy)]
pub struct ScanoutConfig {
    /// Original width of the display in pixels.
    pub display_width: u32,
    /// Original height of the display in pixels.
    pub display_height: u32,
    /// Width of the configured scanout in pixels.
    pub width: u32,
    /// Height of the configured scanout in pixels.
    pub height: u32,
    /// Pixel format.
    pub format: PixelFormat,
}

/// A memory-backed display backend storing presented frames in RAM.
#[derive(Debug, Default)]
pub struct MemoryFramebuffer {
    scanouts: HashMap<u32, ScanoutConfig>,
    buffers: HashMap<(u32, u32), Vec<u8>>,
    next_frame_id: HashMap<u32, u32>,
    presented: Vec<Frame>,
}

impl MemoryFramebuffer {
    /// Creates a new empty [`MemoryFramebuffer`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the scanout configuration for `scanout_id` if configured.
    pub fn scanout_config(&self, scanout_id: u32) -> Option<&ScanoutConfig> {
        self.scanouts.get(&scanout_id)
    }

    /// Returns all presented frames.
    pub fn presented_frames(&self) -> &[Frame] {
        &self.presented
    }

    /// Returns the latest presented frame for `scanout_id` if any.
    pub fn latest_frame(&self, scanout_id: u32) -> Option<&Frame> {
        self.presented
            .iter()
            .rev()
            .find(|f| f.scanout_id == scanout_id)
    }

    /// Clears the presented frame history.
    pub fn clear_presented(&mut self) {
        self.presented.clear();
    }
}

impl DisplayBackend for MemoryFramebuffer {
    fn configure_scanout(
        &mut self,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> Result<(), DisplayError> {
        self.scanouts.insert(
            scanout_id,
            ScanoutConfig {
                display_width,
                display_height,
                width,
                height,
                format,
            },
        );
        Ok(())
    }

    fn disable_scanout(&mut self, scanout_id: u32) -> Result<(), DisplayError> {
        self.scanouts.remove(&scanout_id);
        self.next_frame_id.remove(&scanout_id);
        self.buffers.retain(|(s, _), _| *s != scanout_id);
        Ok(())
    }

    fn alloc_frame(&mut self, scanout_id: u32) -> Result<FrameAllocation<'_>, DisplayError> {
        let cfg = self
            .scanouts
            .get(&scanout_id)
            .ok_or(DisplayError::InvalidScanoutId)?;
        let size = (cfg.width as usize)
            .checked_mul(cfg.height as usize)
            .and_then(|pixels| pixels.checked_mul(cfg.format.bytes_per_pixel()))
            .ok_or(DisplayError::OutOfBuffers)?;
        let fid = self.next_frame_id.entry(scanout_id).or_insert(0);
        let frame_id = *fid;
        *fid = fid.wrapping_add(1);

        let buf = self.buffers.entry((scanout_id, frame_id)).or_default();
        if buf.len() != size {
            buf.resize(size, 0);
        }

        Ok(FrameAllocation {
            frame_id,
            buffer: buf.as_mut_slice(),
        })
    }

    fn present_frame(
        &mut self,
        scanout_id: u32,
        frame_id: u32,
        damage: Option<Rect>,
    ) -> Result<(), DisplayError> {
        let cfg = self
            .scanouts
            .get(&scanout_id)
            .ok_or(DisplayError::InvalidScanoutId)?;
        let buf = self
            .buffers
            .remove(&(scanout_id, frame_id))
            .ok_or(DisplayError::OutOfBuffers)?;
        let frame = Frame {
            scanout_id,
            frame_id,
            width: cfg.width,
            height: cfg.height,
            format: cfg.format,
            pixels: buf,
            damage,
        };
        self.presented.push(frame);
        Ok(())
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
    retained_display: Option<SharedDisplayBackend>,
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

    /// Configures a display backend implementation for rendering VM scanouts.
    pub fn display_backend<B: DisplayBackend + 'static>(
        mut self,
        backend: B,
    ) -> Result<Self, Error> {
        let shared: SharedDisplayBackend = Arc::new(Mutex::new(Some(Box::new(backend))));
        let raw_user_data = Arc::into_raw(shared.clone()) as *const c_void;

        let sys_backend = sys::krun_display_backend {
            features: sys::KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER,
            create_userdata: raw_user_data,
            create: Some(c_create),
            vtable: sys::krun_display_vtable {
                basic_framebuffer: sys::krun_display_basic_framebuffer_vtable {
                    destroy: Some(c_destroy),
                    disable_scanout: Some(c_disable_scanout),
                    configure_scanout: Some(c_configure_scanout),
                    alloc_frame: Some(c_alloc_frame),
                    present_frame: Some(c_present_frame),
                },
            },
        };

        check("krun_set_display_backend", unsafe {
            sys::krun_set_display_backend(
                self.ctx.id,
                &sys_backend as *const _ as *const c_void,
                std::mem::size_of_val(&sys_backend),
            )
        })?;

        self.retained_display = Some(shared);
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

    #[test]
    fn display_error_conversion_round_trips() {
        let errors = [
            (DisplayError::Internal, sys::KRUN_DISPLAY_ERR_INTERNAL),
            (
                DisplayError::MethodUnsupported,
                sys::KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED,
            ),
            (
                DisplayError::InvalidScanoutId,
                sys::KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID,
            ),
            (
                DisplayError::InvalidParam,
                sys::KRUN_DISPLAY_ERR_INVALID_PARAM,
            ),
            (
                DisplayError::OutOfBuffers,
                sys::KRUN_DISPLAY_ERR_OUT_OF_BUFFERS,
            ),
            (DisplayError::Custom(-22), -22),
        ];
        for (err, raw) in errors {
            assert_eq!(err.to_raw(), raw);
            assert_eq!(DisplayError::from_raw(raw), err);
        }
    }

    #[test]
    fn pixel_format_conversion_round_trips() {
        let formats = [
            (
                PixelFormat::B8G8R8A8Unorm,
                sys::KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM,
            ),
            (
                PixelFormat::B8G8R8X8Unorm,
                sys::KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM,
            ),
            (
                PixelFormat::A8R8G8B8Unorm,
                sys::KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM,
            ),
            (
                PixelFormat::X8R8G8B8Unorm,
                sys::KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM,
            ),
            (
                PixelFormat::R8G8B8A8Unorm,
                sys::KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM,
            ),
            (
                PixelFormat::X8B8G8R8Unorm,
                sys::KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM,
            ),
            (
                PixelFormat::A8B8G8R8Unorm,
                sys::KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM,
            ),
            (
                PixelFormat::R8G8B8X8Unorm,
                sys::KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM,
            ),
            (PixelFormat::Unknown(999), 999),
        ];
        for (fmt, raw) in formats {
            assert_eq!(fmt.to_raw(), raw);
            assert_eq!(PixelFormat::from_raw(raw), fmt);
            assert_eq!(fmt.bytes_per_pixel(), 4);
        }
    }

    #[test]
    fn memory_framebuffer_lifecycle() {
        let mut mfb = MemoryFramebuffer::new();
        assert!(mfb.scanout_config(0).is_none());

        mfb.configure_scanout(0, 640, 480, 640, 480, PixelFormat::B8G8R8A8Unorm)
            .expect("configure succeeds");
        let cfg = mfb.scanout_config(0).expect("scanout 0 configured");
        assert_eq!(cfg.width, 640);
        assert_eq!(cfg.height, 480);
        assert_eq!(cfg.format, PixelFormat::B8G8R8A8Unorm);

        let alloc = mfb.alloc_frame(0).expect("alloc frame succeeds");
        assert_eq!(alloc.frame_id, 0);
        assert_eq!(alloc.buffer.len(), 640 * 480 * 4);
        alloc.buffer[0..4].copy_from_slice(&[10, 20, 30, 40]);

        let damage = Some(Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        });
        mfb.present_frame(0, 0, damage)
            .expect("present frame succeeds");

        let presented = mfb.presented_frames();
        assert_eq!(presented.len(), 1);
        let frame = mfb.latest_frame(0).expect("latest frame exists");
        assert_eq!(frame.scanout_id, 0);
        assert_eq!(frame.frame_id, 0);
        assert_eq!(frame.pixels[0..4], [10, 20, 30, 40]);
        assert_eq!(frame.damage, damage);

        mfb.disable_scanout(0).expect("disable scanout succeeds");
        assert!(mfb.scanout_config(0).is_none());
    }

    #[test]
    fn display_vtable_ffi_trampolines_work() {
        let backend = MemoryFramebuffer::new();
        let shared: SharedDisplayBackend = Arc::new(Mutex::new(Some(Box::new(backend))));
        let raw_userdata = Arc::into_raw(shared.clone()) as *const c_void;

        let mut instance: *mut c_void = std::ptr::null_mut();
        let rc = unsafe { c_create(&mut instance, raw_userdata, std::ptr::null()) };
        assert_eq!(rc, 0);
        assert_eq!(instance, raw_userdata as *mut c_void);

        let rc = unsafe { c_configure_scanout(instance, 0, 320, 240, 320, 240, 1) };
        assert_eq!(rc, 0);

        let mut buf_ptr: *mut u8 = std::ptr::null_mut();
        let mut buf_size: usize = 0;
        let frame_id = unsafe { c_alloc_frame(instance, 0, &mut buf_ptr, &mut buf_size) };
        assert_eq!(frame_id, 0);
        assert!(!buf_ptr.is_null());
        assert_eq!(buf_size, 320 * 240 * 4);

        unsafe {
            let slice = std::slice::from_raw_parts_mut(buf_ptr, 4);
            slice.copy_from_slice(&[99, 88, 77, 66]);
        }

        let damage = sys::krun_rect {
            x: 0,
            y: 0,
            width: 5,
            height: 5,
        };
        let rc = unsafe { c_present_frame(instance, 0, frame_id as u32, &damage) };
        assert_eq!(rc, 0);

        {
            let guard = shared.lock().expect("lock shared display");
            let trait_obj = guard.as_ref().expect("backend present");
            // Cast or inspect the underlying MemoryFramebuffer via raw ptr safely since we created it above
            let mfb_ptr = &**trait_obj as *const dyn DisplayBackend as *const MemoryFramebuffer;
            let mfb = unsafe { &*mfb_ptr };
            let frame = mfb.latest_frame(0).expect("frame presented");
            assert_eq!(frame.pixels[0..4], [99, 88, 77, 66]);
            assert_eq!(
                frame.damage,
                Some(Rect {
                    x: 0,
                    y: 0,
                    width: 5,
                    height: 5
                })
            );
        }

        let rc = unsafe { c_disable_scanout(instance, 0) };
        assert_eq!(rc, 0);

        let rc = unsafe { c_destroy(instance) };
        assert_eq!(rc, 0);

        // Reclaim the original Arc created by Arc::into_raw.
        unsafe {
            let _ = Arc::from_raw(raw_userdata as *const Mutex<Option<Box<dyn DisplayBackend>>>);
        }
    }
}
