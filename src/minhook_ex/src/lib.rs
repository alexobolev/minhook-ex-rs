#![allow(dead_code)]
#![allow(unsafe_code)]

//! # MinHook EX
//!
//! A safe-ish wrapper around [`minhook_ex_sys`].

use std::ffi::{c_void, c_ulonglong};

use minhook_ex_sys::{self, *};


/// Return [`std::result::Result`] specialized for MinHook [`Error`]s.
pub type Result<T> = std::result::Result<T, Error>;

/// Possible errors returned by the underlying implementation.
/// Directly map to error enumerations in [`minhook_ex_sys::MH_STATUS`].
#[derive(Clone, Copy, Debug)]
pub enum Error {
    /// MinHook has already been initialized.
    AlreadyInitialized,
    /// MinHook has not been initialized yet,
    /// or has already been uninitialized.
    NotInitialized,
    /// Hook for a target function has already been created.
    AlreadyCreated,
    /// Hook for a target function has not been created yet.
    NotCreated,
    /// Hook for a target function has already been enabled.
    HookEnabled,
    /// Hook for a target function has not enabled yet,
    /// or has already been disabled.
    HookDisabled,
    /// Specified target pointer was invalid as it points to
    /// a non-allocated and/or non-executable memory region.
    PointerNotExecutable,
    /// Specified target function could not be hooked.
    UnsupportedFunction,
    /// Internal memory allocation failed.
    AllocationFailure,
    /// Internal memory protection change failed.
    ProtectionFailure,
    /// Specified target module could not be found.
    ModuleNotFound,
    /// Specified target function could not be found.
    FunctionNotFound,
    /// Internal mutex creation/wait failed.
    MutexFailure,
}

impl TryFrom<MH_STATUS> for Error {
    type Error = &'static str;
    fn try_from(value: MH_STATUS) -> std::result::Result<Self, Self::Error> {
        use Error::*;
        use MH_STATUS::*;
        match value {
            MH_ERROR_ALREADY_INITIALIZED => Ok(AlreadyInitialized),
            MH_ERROR_NOT_INITIALIZED => Ok(NotInitialized),
            MH_ERROR_ALREADY_CREATED => Ok(AlreadyCreated),
            MH_ERROR_NOT_CREATED => Ok(NotCreated),
            MH_ERROR_ENABLED => Ok(HookEnabled),
            MH_ERROR_DISABLED => Ok(HookDisabled),
            MH_ERROR_NOT_EXECUTABLE => Ok(PointerNotExecutable),
            MH_ERROR_UNSUPPORTED_FUNCTION => Ok(UnsupportedFunction),
            MH_ERROR_MEMORY_ALLOC => Ok(AllocationFailure),
            MH_ERROR_MEMORY_PROTECT => Ok(ProtectionFailure),
            MH_ERROR_MODULE_NOT_FOUND => Ok(ModuleNotFound),
            MH_ERROR_FUNCTION_NOT_FOUND => Ok(FunctionNotFound),
            MH_ERROR_MUTEX_FAILURE => Ok(MutexFailure),
            _ => Err("minhook status did not represent an error"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        f.write_str(match self {
            AlreadyInitialized => "minhook already initialized",
            NotInitialized => "minhook not initialized",
            AlreadyCreated => "hook for a target function already created",
            NotCreated => "hook for a target function not yet created",
            HookEnabled => "hook for a target function already enabled",
            HookDisabled => "hook for a target function not yet created",
            PointerNotExecutable => "target function pointer not executable",
            UnsupportedFunction => "target function not hookable",
            AllocationFailure => "internal allocation failed",
            ProtectionFailure => "internal protection change failed",
            ModuleNotFound => "target module not found",
            FunctionNotFound => "target function not found",
            MutexFailure => "internal mutex creation or wait failed",
        })
    }
}

/// Method to use for suspending/resuming threads.
#[derive(Clone, Copy, Debug)]
pub enum ThreadFreezeMethod {
    /// Original method using `CreateToolhelp32Snapshot`, supported
    /// across Windows versions but is slow and a little unreliable.
    OriginalSnapshot,
    /// Newer method using undocumented `NtGetNextThread`, supported
    /// starting from Windows Vista but is faster and more reliable.
    KernelNextThread,
}

impl From<ThreadFreezeMethod> for MH_THREAD_FREEZE_METHOD {
    fn from(method: ThreadFreezeMethod) -> Self {
        match method {
            ThreadFreezeMethod::OriginalSnapshot => MH_THREAD_FREEZE_METHOD::MH_FREEZE_METHOD_ORIGINAL,
            ThreadFreezeMethod::KernelNextThread => MH_THREAD_FREEZE_METHOD::MH_FREEZE_METHOD_FAST_UNDOCUMENTED,
        }
    }
}

/// Internal trait to simplify [`MH_STATUS`] into [`Result`] conversion.
///
/// Can't use the idiomatic [`From`]/[`Into`] because both types
/// are defined out of crate.
trait StatusExt {
    fn into_result(self) -> Result<()>;
}

impl StatusExt for MH_STATUS {
    fn into_result(self) -> Result<()> {
        match self.try_into() {
            Ok(err) => Err(err),
            Err(_) => Ok(()),
        }
    }
}

/// Initialize the MinHook library and select an
/// internal method of suspending/resuming threads.
pub fn initialize(freeze: ThreadFreezeMethod) -> Result<()> {
    unsafe { MH_Initialize() }.into_result()?;
    unsafe { MH_SetThreadFreezeMethod(freeze.into()) }.into_result()
}

/// Uninitialize the MinHook library.
pub fn uninitialize() -> Result<()> {
    unsafe { MH_Uninitialize() }.into_result()
}

/// Create a disabled hook for a `target` function.
/// Returns a pointer to the trampoline function.
///
/// # Arguments
///
/// * `target` - pointer to the hooked function.
/// * `detour` - pointer to the overwriting function.
/// * `ident` - optional hook identifier, provide to set multiple
///     hooks for the same target function.
pub unsafe fn create_hook(target: *const c_void, detour: *const c_void,
    ident: Option<c_ulonglong>) -> Result<*const c_void>
{
    let mut trampoline: *mut c_void = std::ptr::null_mut();
    match ident {
        Some(ident) => MH_CreateHookEx(ident, target, detour, &mut trampoline),
        None => MH_CreateHook(target, detour, &mut trampoline),
    }.into_result()?;
    Ok(trampoline)
}

/// Remove a previously created hook.
///
/// # Arguments
///
/// * `target` - pointer to the hooked function.
/// * `ident` - optional hook identifier, required to remove a hook
///     which was created with one.
pub unsafe fn remove_hook(target: *const c_void, ident: Option<c_ulonglong>) -> Result<()> {
    match ident {
        Some(ident) => MH_RemoveHookEx(ident, target),
        None => MH_RemoveHook(target),
    }.into_result()
}

/// Enable a previously created hook.
///
/// # Arguments
///
/// * `target` - pointer to the hooked function.
/// * `ident` - optional hook identifier, required to enable a hook
///     which was created with one.
pub unsafe fn enable_hook(target: *const c_void, ident: Option<c_ulonglong>) -> Result<()> {
    match ident {
        Some(ident) => MH_EnableHookEx(ident, target),
        None => MH_EnableHook(target),
    }.into_result()
}

/// Disable a previously created and enabled hook.
///
/// # Arguments
///
/// * `target` - pointer to the hooked function.
/// * `ident` - optional hook identifier, required to enable a hook
///     which was created and enabled with one.
pub unsafe fn disable_hook(target: *const c_void, ident: Option<c_ulonglong>) -> Result<()> {
    match ident {
        Some(ident) => MH_DisableHookEx(ident, target),
        None => MH_DisableHook(target),
    }.into_result()
}
