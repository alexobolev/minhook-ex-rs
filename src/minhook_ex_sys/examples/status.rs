use std::ffi::CStr;
use minhook_ex_sys::*;

#[inline]
fn get_status_name(status: MH_STATUS) -> &'static str {
    let cstr = unsafe {
        let raw = MH_StatusToString(status);
        CStr::from_ptr(raw)
    };
    cstr.to_str().expect("failed to convert returned bytes to a utf-8 slice")
}

fn main() {
    let statuses = [
        MH_STATUS::MH_UNKNOWN,
        MH_STATUS::MH_OK,
        MH_STATUS::MH_ERROR_ALREADY_INITIALIZED,
        MH_STATUS::MH_ERROR_NOT_INITIALIZED,
        MH_STATUS::MH_ERROR_ALREADY_CREATED,
        MH_STATUS::MH_ERROR_NOT_CREATED,
        MH_STATUS::MH_ERROR_ENABLED,
        MH_STATUS::MH_ERROR_DISABLED,
        MH_STATUS::MH_ERROR_NOT_EXECUTABLE,
        MH_STATUS::MH_ERROR_UNSUPPORTED_FUNCTION,
        MH_STATUS::MH_ERROR_MEMORY_ALLOC,
        MH_STATUS::MH_ERROR_MEMORY_PROTECT,
        MH_STATUS::MH_ERROR_MODULE_NOT_FOUND,
        MH_STATUS::MH_ERROR_MUTEX_FAILURE,
    ];

    for status in statuses {
        println!("Func 'MH_StatusToString' for enumerator '{:?}' => {}.",
            status, get_status_name(status));
    }
}
