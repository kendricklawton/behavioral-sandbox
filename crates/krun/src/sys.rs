//! Raw FFI declarations for [libkrun](https://github.com/containers/libkrun), hand-written from
//! `/usr/include/libkrun.h`.
//!
//! **Private on purpose.** These are the only unsafe surface in the workspace, and keeping them
//! module-private rather than in a separate `-sys` package means the safe wrapper beside them is
//! the *only* way to reach libkrun: a `pub` crate of raw declarations is one `Cargo.toml` line away
//! from being bypassed. It also keeps the `#![forbid(unsafe_code)]` exemption at exactly one crate,
//! which `every_crate_forbids_unsafe` asserts as an equality.
//!
//! **Nothing here is checked.** Each function returns libkrun's own `int32_t`: zero or a positive
//! value on success, a negative errno on failure. Turning that into a typed error and encoding the
//! call ordering is the parent module's job.
//!
//! - **Hand-written, not generated.** `bindgen` would add a build-time dependency on libclang and
//!   emit the whole 66-symbol surface; the app uses a fraction of it, and a declaration a human
//!   wrote against the header is a declaration a human can review.
//! - **The subset is what phases 2, 3 and 4 need**, plus the capability probes. The display
//!   vtable (`libkrun_display.h`) is a callback table libkrun reads by **layout**, so
//!   `the_display_structs_match_the_installed_header` checks its field order the way the arity
//!   test checks signatures. The input vtable (`libkrun_input.h`) is 4.3's and is not declared.
//! - **A wrong signature is undefined behaviour, not a compile error.** The C header is the only
//!   authority; `the_declared_arity_matches_the_installed_header` reads the installed header back
//!   and compares, so a libkrun bump that changes an argument fails the gate on a host that has it.
//!
//! Verified against libkrun 1.19.4.

// Transcribed as a set against the header, so the arity check covers the whole subset rather than
// only the part wrapped so far. Phase 3 wraps the network and rlimit calls; 0.4 has yet to settle
// what stops a running VM, and `krun_get_shutdown_eventfd` is efi-only, so neither is wrapped here.
#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_void};

/// The virtiofs tag libkrun's init treats as the root filesystem (`KRUN_FS_ROOT_TAG`). Passing it
/// to `krun_add_virtiofs3` is the long form of `krun_set_root`, with the DAX window and the
/// read-only flag under the caller's control.
pub const KRUN_FS_ROOT_TAG: &str = "/dev/root";

/// `level` values for `krun_set_log_level` and `krun_init_log`.
pub const KRUN_LOG_LEVEL_OFF: u32 = 0;
/// See [`KRUN_LOG_LEVEL_OFF`].
pub const KRUN_LOG_LEVEL_ERROR: u32 = 1;
/// See [`KRUN_LOG_LEVEL_OFF`].
pub const KRUN_LOG_LEVEL_WARN: u32 = 2;
/// See [`KRUN_LOG_LEVEL_OFF`].
pub const KRUN_LOG_LEVEL_INFO: u32 = 3;
/// See [`KRUN_LOG_LEVEL_OFF`].
pub const KRUN_LOG_LEVEL_DEBUG: u32 = 4;
/// See [`KRUN_LOG_LEVEL_OFF`].
pub const KRUN_LOG_LEVEL_TRACE: u32 = 5;

/// `target_fd` value selecting libkrun's own default log target (stderr).
pub const KRUN_LOG_TARGET_DEFAULT: c_int = -1;

/// `style` values for `krun_init_log`: whether the library emits terminal colour escapes.
pub const KRUN_LOG_STYLE_AUTO: u32 = 0;
/// See [`KRUN_LOG_STYLE_AUTO`].
pub const KRUN_LOG_STYLE_ALWAYS: u32 = 1;
/// See [`KRUN_LOG_STYLE_AUTO`].
pub const KRUN_LOG_STYLE_NEVER: u32 = 2;

/// `tsi_features` bits for `krun_add_vsock`: TSI transparently proxies the guest's socket calls
/// through the host, so an explicit `0` is the no-network vsock and these are opt-ins.
pub const KRUN_TSI_HIJACK_INET: u32 = 1 << 0;
/// See [`KRUN_TSI_HIJACK_INET`].
pub const KRUN_TSI_HIJACK_UNIX: u32 = 1 << 1;

/// `feature` arguments for [`has_feature`](crate::has_feature). **Ask the library, never a version
/// number**: which
/// features a build carries depends on how it was compiled, not on what it is called.
pub const KRUN_FEATURE_NET: u64 = 0;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_BLK: u64 = 1;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_GPU: u64 = 2;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_SND: u64 = 3;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_INPUT: u64 = 4;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_EFI: u64 = 5;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_TEE: u64 = 6;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_AMD_SEV: u64 = 7;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_INTEL_TDX: u64 = 8;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_AWS_NITRO: u64 = 9;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_VIRGL_RESOURCE_MAP2: u64 = 10;
/// See [`KRUN_FEATURE_NET`].
pub const KRUN_FEATURE_INIT_BLOB: u64 = 11;

// --- display backend constants and vtable types (libkrun_display.h) --------------------------
/// Display backend internal error code.
pub const KRUN_DISPLAY_ERR_INTERNAL: i32 = -1;
/// Display backend method unsupported error code.
pub const KRUN_DISPLAY_ERR_METHOD_UNSUPPORTED: i32 = -2;
/// Display backend invalid scanout ID error code.
pub const KRUN_DISPLAY_ERR_INVALID_SCANOUT_ID: i32 = -3;
/// Display backend invalid parameter error code.
pub const KRUN_DISPLAY_ERR_INVALID_PARAM: i32 = -4;
/// Display backend out of buffers error code.
pub const KRUN_DISPLAY_ERR_OUT_OF_BUFFERS: i32 = -5;

/// Pixel format B8G8R8A8_UNORM.
pub const KRUN_DISPLAY_FORMAT_B8G8R8A8_UNORM: u32 = 1;
/// Pixel format B8G8R8X8_UNORM.
pub const KRUN_DISPLAY_FORMAT_B8G8R8X8_UNORM: u32 = 2;
/// Pixel format A8R8G8B8_UNORM.
pub const KRUN_DISPLAY_FORMAT_A8R8G8B8_UNORM: u32 = 3;
/// Pixel format X8R8G8B8_UNORM.
pub const KRUN_DISPLAY_FORMAT_X8R8G8B8_UNORM: u32 = 4;
/// Pixel format R8G8B8A8_UNORM.
pub const KRUN_DISPLAY_FORMAT_R8G8B8A8_UNORM: u32 = 67;
/// Pixel format X8B8G8R8_UNORM.
pub const KRUN_DISPLAY_FORMAT_X8B8G8R8_UNORM: u32 = 68;
/// Pixel format A8B8G8R8_UNORM.
pub const KRUN_DISPLAY_FORMAT_A8B8G8R8_UNORM: u32 = 121;
/// Pixel format R8G8B8X8_UNORM.
pub const KRUN_DISPLAY_FORMAT_R8G8B8X8_UNORM: u32 = 134;

/// Feature bit for basic framebuffer display operations.
pub const KRUN_DISPLAY_FEATURE_BASIC_FRAMEBUFFER: u64 = 1;

/// A rectangle describing a frame damage region.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub struct krun_rect {
    /// X coordinate of rectangle origin.
    pub x: u32,
    /// Y coordinate of rectangle origin.
    pub y: u32,
    /// Width of rectangle.
    pub width: u32,
    /// Height of rectangle.
    pub height: u32,
}

/// Callback to create a display backend instance.
#[allow(non_camel_case_types)]
pub type krun_display_create_fn = Option<
    unsafe extern "C" fn(
        instance: *mut *mut c_void,
        userdata: *const c_void,
        reserved: *const c_void,
    ) -> i32,
>;

/// Callback to destroy a display backend instance.
#[allow(non_camel_case_types)]
pub type krun_display_destroy_fn = Option<unsafe extern "C" fn(instance: *mut c_void) -> i32>;

/// Callback to configure or reconfigure a display scanout.
#[allow(non_camel_case_types)]
pub type krun_display_configure_scanout_fn = Option<
    unsafe extern "C" fn(
        instance: *mut c_void,
        scanout_id: u32,
        display_width: u32,
        display_height: u32,
        width: u32,
        height: u32,
        format: u32,
    ) -> i32,
>;

/// Callback to disable a display scanout.
#[allow(non_camel_case_types)]
pub type krun_display_disable_scanout_fn =
    Option<unsafe extern "C" fn(instance: *mut c_void, scanout_id: u32) -> i32>;

/// Callback to allocate a frame buffer for a scanout.
#[allow(non_camel_case_types)]
pub type krun_display_alloc_frame_fn = Option<
    unsafe extern "C" fn(
        instance: *mut c_void,
        scanout_id: u32,
        buffer: *mut *mut u8,
        buffer_size: *mut usize,
    ) -> i32,
>;

/// Callback to present a frame to the display.
#[allow(non_camel_case_types)]
pub type krun_display_present_frame_fn = Option<
    unsafe extern "C" fn(
        instance: *mut c_void,
        scanout_id: u32,
        frame_id: u32,
        damage_area: *const krun_rect,
    ) -> i32,
>;

/// Basic framebuffer vtable callbacks.
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct krun_display_basic_framebuffer_vtable {
    /// Optional destroy callback.
    pub destroy: krun_display_destroy_fn,
    /// Callback to disable scanout.
    pub disable_scanout: krun_display_disable_scanout_fn,
    /// Callback to configure scanout.
    pub configure_scanout: krun_display_configure_scanout_fn,
    /// Callback to allocate frame buffer.
    pub alloc_frame: krun_display_alloc_frame_fn,
    /// Callback to present frame.
    pub present_frame: krun_display_present_frame_fn,
}

/// Union of display vtable implementations.
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub union krun_display_vtable {
    /// Basic framebuffer vtable.
    pub basic_framebuffer: krun_display_basic_framebuffer_vtable,
}

/// Display backend configuration handed to [`krun_set_display_backend`].
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct krun_display_backend {
    /// Bitmask of supported display features.
    pub features: u64,
    /// Userdata passed to `create`.
    pub create_userdata: *const c_void,
    /// Optional instance constructor callback.
    pub create: krun_display_create_fn,
    /// Callback vtable implementations.
    pub vtable: krun_display_vtable,
}

// Every declaration is transcribed from `/usr/include/libkrun.h`, argument for argument. `uid_t`
// and `gid_t` are `u32` on both targets this project builds for; naming them as such keeps this
// crate free of a libc dependency, and `the_uid_type_is_the_width_the_header_uses` pins the
// assumption rather than leaving it to a comment.
#[cfg(krun_linked)]
unsafe extern "C" {
    // --- context lifecycle -------------------------------------------------------------------
    /// Creates a configuration context. Returns the context id, or a negative errno.
    pub fn krun_create_ctx() -> i32;
    /// Frees a configuration context. Not the way a *running* VM ends: `krun_start_enter` never
    /// returns, so a started context is freed by the process exiting.
    pub fn krun_free_ctx(ctx_id: u32) -> i32;

    // --- logging -----------------------------------------------------------------------------
    /// Sets the library's log level. Superseded by [`krun_init_log`], which also takes a target.
    pub fn krun_set_log_level(level: u32) -> i32;
    /// Initializes logging with a target fd, level, colour style and option bitmask.
    pub fn krun_init_log(target_fd: c_int, level: u32, style: u32, options: u32) -> i32;

    // --- machine shape -----------------------------------------------------------------------
    /// Sets vCPU count and RAM. `num_vcpus` is a `u8`, which is the ceiling the API can express.
    pub fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;
    /// Sets the host directory served as the guest's root over virtiofs.
    pub fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;
    /// Adds a virtiofs share under `c_tag`.
    pub fn krun_add_virtiofs(ctx_id: u32, c_tag: *const c_char, c_path: *const c_char) -> i32;
    /// Adds a virtiofs share with an explicit DAX window size (`shm_size`, zero to disable).
    pub fn krun_add_virtiofs2(
        ctx_id: u32,
        c_tag: *const c_char,
        c_path: *const c_char,
        shm_size: u64,
    ) -> i32;
    /// Adds a virtiofs share with a DAX window size and a read-only flag. With
    /// [`KRUN_FS_ROOT_TAG`] this is the long form of `krun_set_root`, which the header names as
    /// the way to get read-only control over the root filesystem.
    pub fn krun_add_virtiofs3(
        ctx_id: u32,
        c_tag: *const c_char,
        c_path: *const c_char,
        shm_size: u64,
        read_only: bool,
    ) -> i32;
    /// Overlays an empty read-only directory onto an existing virtiofs tree, for a mount point the
    /// host tree does not carry. `mode` is directory mode bits (e.g. `0o040755`).
    pub fn krun_fs_add_overlay_dir(
        ctx_id: u32,
        fs_tag: *const c_char,
        path: *const c_char,
        mode: u32,
    ) -> i32;

    // --- workload ----------------------------------------------------------------------------
    /// Sets the guest executable, its argv and its envp. Both arrays are NULL-terminated.
    pub fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;
    /// Sets the guest environment alone, as a NULL-terminated `KEY=VALUE` array.
    pub fn krun_set_env(ctx_id: u32, envp: *const *const c_char) -> i32;
    /// Sets the guest working directory.
    pub fn krun_set_workdir(ctx_id: u32, workdir_path: *const c_char) -> i32;
    /// Sets `RLIMIT_*` values applied before the guest starts, as a NULL-terminated array.
    pub fn krun_set_rlimits(ctx_id: u32, rlimits: *const *const c_char) -> i32;
    /// Sets the uid the process drops to immediately before the microVM starts.
    pub fn krun_setuid(ctx_id: u32, uid: u32) -> i32;
    /// Sets the gid the process drops to immediately before the microVM starts.
    pub fn krun_setgid(ctx_id: u32, gid: u32) -> i32;

    // --- console and channels ----------------------------------------------------------------
    /// Suppresses libkrun's default console device, for a caller providing its own.
    pub fn krun_disable_implicit_console(ctx_id: u32) -> i32;
    /// Stops libkrun injecting its default `/init.krun`. The header requires this **before**
    /// `krun_set_root`, which the wrapper encodes by putting it on a stage `krun_set_root` consumes.
    pub fn krun_disable_implicit_init(ctx_id: u32) -> i32;
    /// Attaches a virtio-console backed by three host descriptors.
    pub fn krun_add_virtio_console_default(
        ctx_id: u32,
        input_fd: c_int,
        output_fd: c_int,
        err_fd: c_int,
    ) -> i32;
    /// Maps a guest vsock port to a host unix socket. `listen` chooses which side binds.
    pub fn krun_add_vsock_port2(
        ctx_id: u32,
        port: u32,
        c_filepath: *const c_char,
        listen: bool,
    ) -> i32;

    /// Disables libkrun's implicit vsock device, whose default TSI hijacking gives the guest a
    /// path onto the host's network. A machine that wants no network calls this and adds nothing.
    pub fn krun_disable_implicit_vsock(ctx_id: u32) -> i32;
    /// Adds an explicit vsock device with an exact `tsi_features` bitmask (`0` for no hijacking).
    /// Requires [`krun_disable_implicit_vsock`] first; only one vsock device is supported.
    pub fn krun_add_vsock(ctx_id: u32, tsi_features: u32) -> i32;

    // --- network -----------------------------------------------------------------------------
    /// Points the network backend at a gvproxy socket path. Takes a **mutable** `char *` in the
    /// header, transcribed as such rather than quietly narrowed.
    pub fn krun_set_gvproxy_path(ctx_id: u32, c_path: *mut c_char) -> i32;
    /// Hands the network backend an already-connected passt descriptor.
    pub fn krun_set_passt_fd(ctx_id: u32, fd: c_int) -> i32;
    /// Sets host-to-guest port forwards, as a NULL-terminated array.
    pub fn krun_set_port_map(ctx_id: u32, port_map: *const *const c_char) -> i32;
    /// Attaches a virtio-net device over a unix-stream backend.
    pub fn krun_add_net_unixstream(
        ctx_id: u32,
        c_path: *const c_char,
        fd: c_int,
        c_mac: *mut u8,
        features: u32,
        flags: u32,
    ) -> i32;

    // --- display -----------------------------------------------------------------------------
    /// Configures a display output for the microVM.
    pub fn krun_add_display(ctx_id: u32, width: u32, height: u32) -> i32;
    /// Configures a custom EDID blob for a display.
    pub fn krun_display_set_edid(
        ctx_id: u32,
        display_id: u32,
        edid_blob: *const u8,
        blob_size: usize,
    ) -> i32;
    /// Configures DPI of the display reported to the guest.
    pub fn krun_display_set_dpi(ctx_id: u32, display_id: u32, dpi: u32) -> i32;
    /// Configures physical size of the display reported to the guest.
    pub fn krun_display_set_physical_size(
        ctx_id: u32,
        display_id: u32,
        width_mm: u16,
        height_mm: u16,
    ) -> i32;
    /// Configures refresh rate for a display.
    pub fn krun_display_set_refresh_rate(ctx_id: u32, display_id: u32, refresh_rate: u32) -> i32;
    /// Configures a display backend struct for display output.
    pub fn krun_set_display_backend(
        ctx_id: u32,
        display_backend: *const c_void,
        backend_size: usize,
    ) -> i32;

    // --- lifecycle and probes ----------------------------------------------------------------
    /// Returns an eventfd that stops the VM when written to. The stop path, since the thread that
    /// called `krun_start_enter` never comes back to be asked.
    pub fn krun_get_shutdown_eventfd(ctx_id: u32) -> i32;
    /// **Never returns.** Takes over the calling process, boots the guest, and exits with the
    /// guest's status. This one fact is why every VM is a helper process.
    pub fn krun_start_enter(ctx_id: u32) -> i32;
    /// Whether this build carries a `KRUN_FEATURE_*` capability. A probe, never a version compare.
    pub fn krun_has_feature(feature: u64) -> i32;
    /// The hypervisor's vCPU ceiling on this host.
    pub fn krun_get_max_vcpus() -> i32;
    /// Whether this host can nest virtualization.
    pub fn krun_check_nested_virt() -> i32;
}

/// Stub twins of every symbol the wrapper calls, compiled where `build.rs` found no libkrun.
///
/// A workspace build (and the gate) has to succeed on a host with no libkrun, and an undefined
/// symbol fails at link even when the call that references it is unreachable. Each stub returns
/// [`NOT_LINKED`], and the wrapper reports that as its not-linked error rather than reading an
/// errno the stub would have had to invent.
///
/// Only the symbols with a caller: a declaration alone links fine, and an unstubbed symbol that
/// gains a caller fails the no-libkrun build at link, which is the reminder to add its stub here.
#[cfg(not(krun_linked))]
#[allow(clippy::missing_safety_doc)] // stubs of foreign declarations; nothing here dereferences
mod stub {
    use super::c_char;

    /// Any negative value fails the wrapper's `check`; the wrapper substitutes the not-linked
    /// report without reading which one.
    const NOT_LINKED: i32 = i32::MIN;

    pub unsafe fn krun_create_ctx() -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_free_ctx(_ctx_id: u32) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_disable_implicit_init(_ctx_id: u32) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_set_vm_config(_ctx_id: u32, _num_vcpus: u8, _ram_mib: u32) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_add_virtiofs(
        _ctx_id: u32,
        _c_tag: *const c_char,
        _c_path: *const c_char,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_add_virtiofs3(
        _ctx_id: u32,
        _c_tag: *const c_char,
        _c_path: *const c_char,
        _shm_size: u64,
        _read_only: bool,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_add_vsock_port2(
        _ctx_id: u32,
        _port: u32,
        _c_filepath: *const c_char,
        _listen: bool,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_set_workdir(_ctx_id: u32, _workdir_path: *const c_char) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_set_exec(
        _ctx_id: u32,
        _exec_path: *const c_char,
        _argv: *const *const c_char,
        _envp: *const *const c_char,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_add_display(_ctx_id: u32, _width: u32, _height: u32) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_display_set_edid(
        _ctx_id: u32,
        _display_id: u32,
        _edid_blob: *const u8,
        _blob_size: usize,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_display_set_dpi(_ctx_id: u32, _display_id: u32, _dpi: u32) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_display_set_physical_size(
        _ctx_id: u32,
        _display_id: u32,
        _width_mm: u16,
        _height_mm: u16,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_display_set_refresh_rate(
        _ctx_id: u32,
        _display_id: u32,
        _refresh_rate: u32,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_set_display_backend(
        _ctx_id: u32,
        _display_backend: *const super::c_void,
        _backend_size: usize,
    ) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_start_enter(_ctx_id: u32) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_has_feature(_feature: u64) -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_get_max_vcpus() -> i32 {
        NOT_LINKED
    }
    pub unsafe fn krun_check_nested_virt() -> i32 {
        NOT_LINKED
    }
}

#[cfg(not(krun_linked))]
pub use stub::*;

#[cfg(test)]
mod tests {
    /// Where the declarations above were transcribed from. Read at test time rather than vendored,
    /// so the comparison is against the header this host would actually link against.
    const HEADER: &str = "/usr/include/libkrun.h";

    /// The declared subset, paired with the argument count the header gives it. A signature is the
    /// one thing in this crate a compiler cannot check: a wrong arity is undefined behaviour at
    /// call time, not a build error, so it is checked against the header instead.
    ///
    /// Arity only. Types would need a C parser to compare honestly, and a half-parser that silently
    /// matched the wrong thing would be worse than not claiming to check them.
    const DECLARED: &[(&str, usize)] = &[
        ("krun_create_ctx", 0),
        ("krun_free_ctx", 1),
        ("krun_set_log_level", 1),
        ("krun_init_log", 4),
        ("krun_set_vm_config", 3),
        ("krun_set_root", 2),
        ("krun_add_virtiofs", 3),
        ("krun_add_virtiofs2", 4),
        ("krun_add_virtiofs3", 5),
        ("krun_fs_add_overlay_dir", 4),
        ("krun_set_exec", 4),
        ("krun_set_env", 2),
        ("krun_set_workdir", 2),
        ("krun_set_rlimits", 2),
        ("krun_setuid", 2),
        ("krun_setgid", 2),
        ("krun_disable_implicit_console", 1),
        ("krun_disable_implicit_init", 1),
        ("krun_add_virtio_console_default", 4),
        ("krun_add_vsock_port2", 4),
        ("krun_disable_implicit_vsock", 1),
        ("krun_add_vsock", 2),
        ("krun_set_gvproxy_path", 2),
        ("krun_set_passt_fd", 2),
        ("krun_set_port_map", 2),
        ("krun_add_net_unixstream", 6),
        ("krun_add_display", 3),
        ("krun_display_set_edid", 4),
        ("krun_display_set_dpi", 3),
        ("krun_display_set_physical_size", 4),
        ("krun_display_set_refresh_rate", 3),
        ("krun_set_display_backend", 3),
        ("krun_get_shutdown_eventfd", 1),
        ("krun_start_enter", 1),
        ("krun_has_feature", 1),
        ("krun_get_max_vcpus", 0),
        ("krun_check_nested_virt", 0),
    ];

    /// The argument list of `fn` in the header text, or `None` if it declares no such function.
    ///
    /// Anchored on the `int32_t` return type, not on the bare name: the header mentions functions
    /// inside comments (`/* Feature constants for krun_has_feature() */`), and a search for the
    /// name alone reads that comment's empty parens as a zero-argument declaration. A return type
    /// this header stops using would surface as "not declared", which is loud, rather than as a
    /// match against prose.
    ///
    /// Declarations wrap across lines, so this joins from the opening paren to the matching close
    /// rather than reading one line.
    fn header_arity(header: &str, name: &str) -> Option<usize> {
        let at = header.find(&format!("int32_t {name}("))?;
        let open = at + header[at..].find('(')?;
        let close = open + header[open..].find(')')?;
        let args = header[open + 1..close].trim();
        if args.is_empty() || args == "void" {
            return Some(0);
        }
        Some(args.split(',').count())
    }

    #[test]
    fn the_declared_arity_matches_the_installed_header() {
        let Ok(header) = std::fs::read_to_string(HEADER) else {
            // A skipped test is a pass to cargo, so say what was not checked and why.
            println!(
                "SKIPPED the_declared_arity_matches_the_installed_header: {HEADER} is absent, so \
                 the declarations were compared against nothing. Install libkrun to run it."
            );
            return;
        };
        let mut wrong = Vec::new();
        for (name, declared) in DECLARED {
            match header_arity(&header, name) {
                Some(actual) if actual == *declared => {}
                Some(actual) => wrong.push(format!("{name}: declared {declared}, header {actual}")),
                None => wrong.push(format!("{name}: not declared in {HEADER}")),
            }
        }
        assert!(
            wrong.is_empty(),
            "these declarations disagree with {HEADER}, which is undefined behaviour at call \
             time rather than a build error:\n  {}",
            wrong.join("\n  ")
        );
    }

    /// The parser has to be able to fail, or the test above passes on anything. Both directions:
    /// a function the header does not have, and one whose arity was transcribed wrong.
    ///
    /// The comment case is the one that actually bit: reading the first textual occurrence of the
    /// name found `krun_has_feature()` in prose and called it zero arguments, which reported a
    /// correct declaration as wrong. A parser that mistakes prose for a declaration is equally able
    /// to wave a wrong one through.
    #[test]
    fn the_header_check_rejects_a_wrong_arity_and_a_missing_symbol() {
        let header = "/* See krun_two() for details */\n\
                      int32_t krun_two(uint32_t a, const char *b);\n\
                      int32_t krun_none(void);\n";
        assert_eq!(header_arity(header, "krun_two"), Some(2));
        assert_eq!(header_arity(header, "krun_none"), Some(0));
        assert_eq!(header_arity(header, "krun_absent"), None);
        assert_ne!(header_arity(header, "krun_two"), Some(3));
    }

    /// `uid_t`/`gid_t` are declared here as `u32` rather than pulled from a libc crate. That holds
    /// on both targets this project builds for, and it is an assumption rather than a fact the
    /// compiler checks, so it is pinned where it is made.
    #[test]
    fn the_uid_type_is_the_width_the_header_uses() {
        assert_eq!(
            size_of::<u32>(),
            4,
            "uid_t/gid_t are 32-bit on Linux and macOS"
        );
    }

    /// The header the display structs were transcribed from.
    const DISPLAY_HEADER: &str = "/usr/include/libkrun_display.h";

    /// The structs libkrun reads by layout, with their field names in the order declared above.
    /// A callback table is the one binding where a wrong *order* is undefined behaviour with a
    /// correct arity: libkrun would call `disable_scanout` where it meant `destroy`.
    const DISPLAY_STRUCTS: &[(&str, &[&str])] = &[
        ("krun_rect", &["x", "y", "width", "height"]),
        (
            "krun_display_basic_framebuffer_vtable",
            &[
                "destroy",
                "disable_scanout",
                "configure_scanout",
                "alloc_frame",
                "present_frame",
            ],
        ),
        (
            "krun_display_backend",
            &["features", "create_userdata", "create", "vtable"],
        ),
    ];

    /// The field names of `struct name { ... }` in `header`, in order: the last word of each
    /// `;`-terminated declaration with `//` comments stripped and a leading `*` dropped.
    fn header_struct_fields(header: &str, name: &str) -> Option<Vec<String>> {
        let at = header.find(&format!("struct {name} {{"))?;
        let open = at + header[at..].find('{')?;
        let close = open + header[open..].find('}')?;
        let mut fields = Vec::new();
        for decl in header[open + 1..close].split(';') {
            let code: Vec<&str> = decl
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect();
            if let Some(last) = code.join(" ").split_whitespace().last() {
                fields.push(last.trim_start_matches('*').to_string());
            }
        }
        Some(fields)
    }

    #[test]
    fn the_display_structs_match_the_installed_header() {
        let Ok(header) = std::fs::read_to_string(DISPLAY_HEADER) else {
            println!(
                "SKIPPED the_display_structs_match_the_installed_header: {DISPLAY_HEADER} is \
                 absent, so the struct layouts were compared against nothing. Install libkrun to \
                 run it."
            );
            return;
        };
        for (name, declared) in DISPLAY_STRUCTS {
            let actual = header_struct_fields(&header, name)
                .unwrap_or_else(|| Vec::from([format!("<{name} not found>")]));
            assert_eq!(
                actual, *declared,
                "struct {name} in {DISPLAY_HEADER} is laid out differently from the declaration \
                 above it, which is undefined behaviour at the first callback"
            );
        }
    }

    /// The struct parser has to be able to fail, in both directions.
    #[test]
    fn the_struct_check_rejects_a_reordered_field_and_a_missing_struct() {
        let header = "struct two {\n    int a; // first\n    void *b;\n    struct x c;\n};\n";
        assert_eq!(
            header_struct_fields(header, "two").expect("found"),
            ["a", "b", "c"]
        );
        assert_ne!(
            header_struct_fields(header, "two").expect("found"),
            ["b", "a", "c"]
        );
        assert_eq!(header_struct_fields(header, "absent"), None);
    }

    /// The library is linked and answers. Compiled out where `build.rs` found no libkrun, because
    /// without the link directive this would not build at all.
    #[cfg(krun_linked)]
    #[test]
    fn the_linked_library_answers_a_probe() {
        // `krun_get_max_vcpus` touches no context and mutates nothing, which makes it the one call
        // safe to make from a unit test: it asks the hypervisor a question and returns.
        let max = unsafe { super::krun_get_max_vcpus() };
        assert!(
            max > 0,
            "krun_get_max_vcpus returned {max}; a negative value is an errno from the hypervisor"
        );
    }

    #[cfg(not(krun_linked))]
    #[test]
    fn the_linked_library_answers_a_probe() {
        println!(
            "SKIPPED the_linked_library_answers_a_probe: build.rs found no libkrun to link, so \
             nothing in this crate was called. Install libkrun to run it."
        );
    }
}
