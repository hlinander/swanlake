//! Session-bound access to the external_kernel telemetry ABI. Flight forwards
//! these snapshots directly; it never reads another session's extension handle.
use crate::error::ServerError;
use duckdb::{Connection, InterruptHandle};
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::Mutex;

type SetContext = unsafe extern "C" fn(*mut c_void, u64, *const c_char) -> u64;
type Read = unsafe extern "C" fn(u64, *const c_char) -> *mut c_char;
type Free = unsafe extern "C" fn(*mut c_char);

pub struct KernelTelemetry {
    _library: libloading::Library,
    set_context: SetContext,
    read: Read,
    free: Free,
    scope: u64,
}

// Same pinned duckdb-rs layout already used by engine::progress.
#[repr(C)]
struct Handle {
    conn: Mutex<libduckdb_sys::duckdb_connection>,
}
fn raw(conn: &Connection) -> Result<*mut c_void, ServerError> {
    let handle = conn.interrupt_handle();
    let inner = unsafe { &*((&*handle as *const InterruptHandle).cast::<Handle>()) };
    let ptr = *inner
        .conn
        .lock()
        .map_err(|_| ServerError::Internal("interrupt handle poisoned".into()))?;
    Ok(ptr.cast())
}

impl KernelTelemetry {
    pub fn load(conn: &Connection, path: &str) -> Result<Self, ServerError> {
        conn.execute_batch(&format!("LOAD '{}'", path.replace('\'', "''")))?;
        // Keep this handle alive until after all callers finish using its exports.
        let library = unsafe { libloading::Library::new(path) }
            .map_err(|e| ServerError::Internal(format!("load kernel telemetry: {e}")))?;
        let (set_context, read, free) = unsafe {
            (
                *library
                    .get::<SetContext>(b"external_kernel_set_context\0")
                    .map_err(abi_error)?,
                *library
                    .get::<Read>(b"external_kernel_read_updates\0")
                    .map_err(abi_error)?,
                *library
                    .get::<Free>(b"external_kernel_free_string\0")
                    .map_err(abi_error)?,
            )
        };
        let scope = unsafe { set_context(raw(conn)?, 0, std::ptr::null()) };
        if scope == 0 {
            return Err(ServerError::Internal(
                "kernel telemetry scope unavailable".into(),
            ));
        }
        Ok(Self {
            _library: library,
            set_context,
            read,
            free,
            scope,
        })
    }

    pub fn set(&self, conn: &Connection, context: Option<&str>) -> Result<(), ServerError> {
        let text = CString::new(context.unwrap_or(""))
            .map_err(|_| ServerError::Internal("invalid execution context".into()))?;
        let scope = unsafe { (self.set_context)(raw(conn)?, 0, text.as_ptr()) };
        if scope != self.scope {
            return Err(ServerError::Internal(
                "kernel telemetry scope changed".into(),
            ));
        }
        Ok(())
    }

    pub fn read(&self, request: &str) -> Result<Vec<u8>, ServerError> {
        let request = CString::new(request)
            .map_err(|_| ServerError::Internal("invalid telemetry request".into()))?;
        let ptr = unsafe { (self.read)(self.scope, request.as_ptr()) };
        if ptr.is_null() {
            return Err(ServerError::Internal("kernel telemetry unavailable".into()));
        }
        let result = unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() };
        unsafe { (self.free)(ptr) };
        Ok(result)
    }
}
fn abi_error(e: libloading::Error) -> ServerError {
    ServerError::Internal(format!("external_kernel lacks telemetry ABI v1: {e}"))
}
