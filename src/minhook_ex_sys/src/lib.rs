#![allow(dead_code)]
#![allow(unsafe_code)]
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_short, c_ulonglong, c_void};

/// MinHook error codes.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum MH_STATUS {
    /// Unknown error. Should not be returned.
    MH_UNKNOWN = -1,
    /// Successful.
    MH_OK = 0,
    /// MinHook is already initialized.
    MH_ERROR_ALREADY_INITIALIZED,
    /// MinHook is not initialized yet, or already uninitialized.
    MH_ERROR_NOT_INITIALIZED,
    /// The hook for the specified target function is already created.
    MH_ERROR_ALREADY_CREATED,
    /// The hook for the specified target function is not created yet.
    MH_ERROR_NOT_CREATED,
    /// The hook for the specified target function is already enabled.
    MH_ERROR_ENABLED,
    /// The hook for the specified target function is not enabled yet,
    /// or already disabled.
    MH_ERROR_DISABLED,
    /// The specified pointer is invalid. It points the address of
    /// non-allocated and/or non-executable region.
    MH_ERROR_NOT_EXECUTABLE,
    /// The specified target function cannot be hooked.
    MH_ERROR_UNSUPPORTED_FUNCTION,
    /// Failed to allocate memory.
    MH_ERROR_MEMORY_ALLOC,
    /// Failed to change the memory protection.
    MH_ERROR_MEMORY_PROTECT,
    /// The specified module is not loaded.
    MH_ERROR_MODULE_NOT_FOUND,
    /// The specified function is not found.
    MH_ERROR_FUNCTION_NOT_FOUND,
    /// Failed to create, or to wait for the main mutex.
    MH_ERROR_MUTEX_FAILURE,
}

/// The method of suspending and resuming threads.
#[repr(C)]
pub enum MH_THREAD_FREEZE_METHOD {
    /// The original MinHook method, using CreateToolhelp32Snapshot. Documented
    /// and supported on all Windows versions, but very slow and less reliable.
    MH_FREEZE_METHOD_ORIGINAL = 0,
    /// A much faster and more reliable, but undocumented method, using
    /// NtGetNextThread. Supported since Windows Vista, on older versions falls
    /// back to MH_ORIGINAL.
    MH_FREEZE_METHOD_FAST_UNDOCUMENTED,
    /// Threads are not suspended and instruction pointer registers are not
    /// adjusted. Don't use this method unless you understand the implications
    /// and know that it's safe.
    MH_FREEZE_METHOD_NONE_UNSAFE
}

/// Can be passed as a parameter to [`MH_EnableHook`], [`MH_DisableHook`],
/// [`MH_QueueEnableHook`] or [`MH_QueueDisableHook`].
pub const MH_ALL_HOOKS: *const c_void = std::ptr::null::<c_void>();

pub const MH_ALL_IDENTS: c_ulonglong = 0;
pub const MH_DEFAULT_IDENT: c_ulonglong = 1;

#[link(name = "minhook", kind = "static")]
extern "C" {

    /// Initialize the MinHook library. You must call this function **exactly
    /// once** at the beginning of your program.
    pub fn MH_Initialize() -> MH_STATUS;

    /// Uninitialize the MinHook library. You must call this function **exactly
    /// once** at the end of your program.
    pub fn MH_Uninitialize() -> MH_STATUS;

    /// Set the method of suspending and resuming threads.
    pub fn MH_SetThreadFreezeMethod(method: MH_THREAD_FREEZE_METHOD) -> MH_STATUS;

    /// Creates a hook for the specified target function, in disabled state.
    ///
    /// # Arguments
    ///
    /// * `pTarget` - a pointer to the target function, which will be
    ///     overridden by the detour function.
    /// * `pDetour` - a pointer to the detour function, which will override
    ///     the target function.
    /// * `ppOriginal` - a pointer to the trampoline function, which will be
    ///     used to call the original target function. Can be null.
    pub fn MH_CreateHook(pTarget: *const c_void, pDetour: *const c_void,
        ppOriginal: *mut *mut c_void) -> MH_STATUS;
    /// Creates a hook for the specified target function, in disabled state.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    /// * `pTarget` - a pointer to the target function, which will be
    ///     overridden by the detour function.
    /// * `pDetour` - a pointer to the detour function, which will override
    ///     the target function.
    /// * `ppOriginal` - a pointer to the trampoline function, which will be
    ///     used to call the original target function. Can be null.
    pub fn MH_CreateHookEx(hookIdent: c_ulonglong, pTarget: *const c_void,
        pDetour: *const c_void, ppOriginal: *mut *mut c_void) -> MH_STATUS;

    /// Creates a hook for the specified API function, in disabled state.
    ///
    /// # Arguments
    ///
    /// * `pszModule` - a pointer to the loaded module name which contains
    ///     the target function.
    /// * `pszProcName` - a pointer to the target function name, which will be
    ///     overridden by the detour function.
    /// * `pDetour` - a pointer to the detour function, which will override
    ///     the target function.
    /// * `ppOriginal` - a pointer to the trampoline function, which will be
    ///     used to call the original target function. Can be null.
    pub fn MH_CreateHookApi(pszModule: *const c_short, pszProcName: *const c_char,
        pDetour: *const c_void, ppOriginal: *mut *mut c_void) -> MH_STATUS;
    /// Creates a hook for the specified API function, in disabled state.
    ///
    /// # Arguments
    ///
    /// * `pszModule` - a pointer to the loaded module name which contains
    ///     the target function.
    /// * `pszProcName` - a pointer to the target function name, which will be
    ///     overridden by the detour function.
    /// * `pDetour` - a pointer to the detour function, which will override
    ///     the target function.
    /// * `ppOriginal` - a pointer to the trampoline function, which will be
    ///     used to call the original target function. Can be null.
    /// * `ppTarget` - a pointer to the target function, which will be used
    ///     with other functions. Can be null.
    pub fn MH_CreateHookApiEx(pszModule: *const c_short, pszProcName: *const c_char,
        pDetour: *const c_void, ppOriginal: *mut *mut c_void,
        ppTarget: *mut *mut c_void) -> MH_STATUS;

    /// Removes an already created hook.
    ///
    /// # Arguments
    ///
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are removed in one go.
    pub fn MH_RemoveHook(pTarget: *const c_void) -> MH_STATUS;
    /// Removes an already created hook.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are removed in one go.
    pub fn MH_RemoveHookEx(hookIdent: c_ulonglong, pTarget: *const c_void) -> MH_STATUS;

    /// Removes all disabled hooks.
    pub fn MH_RemoveDisabledHooks() -> MH_STATUS;
    /// Removes all disabled hooks.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    pub fn MH_RemoveDisabledHooksEx(hookIdent: c_ulonglong) -> MH_STATUS;

    /// Enables an already created hook.
    ///
    /// # Arguments
    ///
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are enabled in one go.
    pub fn MH_EnableHook(pTarget: *const c_void) -> MH_STATUS;
    /// Enables an already created hook.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are enabled in one go.
    pub fn MH_EnableHookEx(hookIdent: c_ulonglong, pTarget: *const c_void) -> MH_STATUS;

    /// Disables an already created hook.
    ///
    /// # Arguments
    ///
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are disabled in one go.
    pub fn MH_DisableHook(pTarget: *const c_void) -> MH_STATUS;
    /// Disables an already created hook.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are disabled in one go.
    pub fn MH_DisableHookEx(hookIdent: c_ulonglong, pTarget: *const c_void) -> MH_STATUS;

    /// Queues to enable an already created hook.
    ///
    /// # Arguments
    ///
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are queued to be enabled.
    pub fn MH_QueueEnableHook(pTarget: *const c_void) -> MH_STATUS;
    /// Queues to enable an already created hook.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are queued to be enabled.
    pub fn MH_QueueEnableHookEx(hookIdent: c_ulonglong, pTarget: *const c_void) -> MH_STATUS;

    /// Queues to disable an already created hook.
    ///
    /// # Arguments
    ///
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are queued to be disabled.
    pub fn MH_QueueDisableHook(pTarget: *const c_void) -> MH_STATUS;
    /// Queues to disable an already created hook.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    /// * `pTarget` - a pointer to the target function. If this parameter is
    ///     [`MH_ALL_HOOKS`], all created hooks are queued to be disabled.
    pub fn MH_QueueDisableHookEx(hookIdent: c_ulonglong, pTarget: *const c_void) -> MH_STATUS;

    /// Applies all queued changes in one go.
    pub fn MH_ApplyQueued() -> MH_STATUS;

    /// Applies all queued changes in one go.
    ///
    /// # Arguments
    ///
    /// * `hookIdent` - a hook identifier, can be set to different values for
    ///     different hooks to hook the same function more than once.
    ///     Default value: [`MH_DEFAULT_IDENT`].
    pub fn MH_ApplyQueuedEx(hookIdent: c_ulonglong) -> MH_STATUS;

    /// Translates an [`MH_STATUS`] to its name as a string.
    pub fn MH_StatusToString(status: MH_STATUS) -> *const c_char;
}
