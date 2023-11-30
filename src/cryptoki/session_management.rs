use crate::state::StateAccessor;

use super::bindings::{
    CKR_ARGUMENTS_BAD, CKR_OK, CK_FLAGS, CK_NOTIFY, CK_RV, CK_SESSION_HANDLE,
    CK_SESSION_HANDLE_PTR, CK_SLOT_ID, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VOID_PTR,
};

/// Opens a session between an application and a token in a particular slot
///
/// # Arguments
///
/// * `slotID` - the slot’s ID
/// * `flags` - indicates the type of session
/// * `pApplication` - an application-defined pointer to be passed to the notification callback
/// * `Notify` - the address of the notification callback function
/// * `phSession` - points to the location that receives the handle for the new session
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_OpenSession(
    slotID: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _pApplication: CK_VOID_PTR,
    _Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    // TODO: finish implementation
    if phSession.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let session_handle = match state_accessor.create_session(&slotID) {
        Ok(handle) => handle,
        Err(err) => return err.into_ck_rv(),
    };
    unsafe {
        *phSession = session_handle;
    }
    CKR_OK as CK_RV
}

/// Closes a session between an application and a token
///
/// # Arguments
///
/// * `hSession` - the session’s handle
#[cryptoki_macros::cryptoki_function]
pub fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let state_accessor = StateAccessor::new();
    if let Err(err) = state_accessor.close_session(&hSession) {
        return err.into_ck_rv();
    }

    CKR_OK as CK_RV
}

/// Logs a user into a token
///
/// # Arguments
///
/// `hSession` - a session handle
/// `userType` - the user type
/// `pPin` - points to the user’s PIN
/// `ulPinLen` - the length of the PIN
#[cryptoki_macros::cryptoki_function]
pub fn C_Login(
    _hSession: CK_SESSION_HANDLE,
    _userType: CK_USER_TYPE,
    _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    // TODO: do we need this kind of auth?
    // for now just allow all logins
    CKR_OK as CK_RV
}

/// Logs a user out from a token
///
/// # Arguments
///
/// * `hSession` - the session’s handle
#[cryptoki_macros::cryptoki_function]
pub fn C_Logout(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    // for now do nothing
    CKR_OK as CK_RV
}
