use std::mem;

use super::{
    bindings::{
        CKR_ARGUMENTS_BAD, CKR_HOST_MEMORY, CKR_OK, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR_PTR,
        CK_INFO, CK_INFO_PTR, CK_RV, CK_VERSION, CK_VOID_PTR,
    },
    decryption::{C_Decrypt, C_DecryptInit},
    encryption::{C_Encrypt, C_EncryptInit},
    key_management::{C_GenerateKey, C_GenerateKeyPair, C_UnwrapKey, C_WrapKey},
    message_digesting::{C_Digest, C_DigestInit},
    object_management::{
        C_CreateObject, C_DestroyObject, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit,
        C_GetAttributeValue,
    },
    session_management::{C_CloseSession, C_Login, C_Logout, C_OpenSession},
    signing::{C_Sign, C_SignInit},
    slot_token::{C_GetSlotInfo, C_GetSlotList, C_GetTokenInfo},
    unsupported,
};
use crate::package_info::{
    IMPLEMENTATION_MAJOR_VERSION, IMPLEMENTATION_MINOR_VERSION, STANDARD_MAJOR_VERSION,
    STANDARD_MINOR_VERSION,
};
use crate::state::StateAccessor;

/// Initializes the Cryptoki library
///
/// # Arguments
///
/// * `pInitArgs` - either has the value NULL_PTR or points to a CK_C_INITIALIZE_ARGS structure containing information on how the library should deal with multi-threaded access
#[cryptoki_macros::cryptoki_function]
pub fn C_Initialize(_pInitArgs: CK_VOID_PTR) -> CK_RV {
    let state_accessor = StateAccessor::new();
    if let Err(err) = state_accessor.initialize_state() {
        return err.into_ck_rv();
    }
    CKR_OK as CK_RV
}

/// The function is called to indicate that an application is finished with the Cryptoki library.
/// It should be the last Cryptoki call made by an application
///
/// # Arguments
///
/// * `pReserved` - reserved for future versions; for this version, it should be set to NULL_PTR
#[cryptoki_macros::cryptoki_function]
pub fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    if !pReserved.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    if let Err(err) = state_accessor.finalize() {
        return err.into_ck_rv();
    }

    CKR_OK as CK_RV
}

/// Returns general information about Cryptoki
///
/// # Arguments
///
/// * `pInfo` - points to the location that receives the information
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let info = CK_INFO {
        cryptokiVersion: CK_VERSION {
            major: STANDARD_MAJOR_VERSION,
            minor: STANDARD_MINOR_VERSION,
        },
        manufacturerID: [0; 32],
        flags: 0,
        libraryDescription: [0; 32],
        libraryVersion: CK_VERSION {
            major: IMPLEMENTATION_MAJOR_VERSION,
            minor: IMPLEMENTATION_MINOR_VERSION,
        },
    };
    unsafe {
        *pInfo = info;
    }
    CKR_OK as CK_RV
}

/// Obtains a pointer to the Cryptoki library’s list of function pointers
///
/// # Arguments
///
/// * `ppFunctionList` - points to a value which will receive a pointer to the library’s CK_FUNCTION_LIST structure
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let version = CK_VERSION {
        major: STANDARD_MAJOR_VERSION,
        minor: STANDARD_MINOR_VERSION,
    };
    let function_list = CK_FUNCTION_LIST {
        version,
        C_Initialize: Some(C_Initialize),
        C_Finalize: Some(C_Finalize),
        C_GetInfo: Some(C_GetInfo),
        C_GetFunctionList: Some(C_GetFunctionList),
        C_GetSlotList: Some(C_GetSlotList),
        C_GetSlotInfo: Some(C_GetSlotInfo),
        C_GetTokenInfo: Some(C_GetTokenInfo),
        C_GetMechanismList: Some(unsupported::C_GetMechanismList),
        C_GetMechanismInfo: Some(unsupported::C_GetMechanismInfo),
        C_InitToken: Some(unsupported::C_InitToken),
        C_InitPIN: Some(unsupported::C_InitPIN),
        C_SetPIN: Some(unsupported::C_SetPIN),
        C_OpenSession: Some(C_OpenSession),
        C_CloseSession: Some(C_CloseSession),
        C_CloseAllSessions: Some(unsupported::C_CloseAllSessions),
        C_GetSessionInfo: Some(unsupported::C_GetSessionInfo),
        C_GetOperationState: Some(unsupported::C_GetOperationState),
        C_SetOperationState: Some(unsupported::C_SetOperationState),
        C_Login: Some(C_Login),
        C_Logout: Some(C_Logout),
        C_CreateObject: Some(C_CreateObject),
        C_CopyObject: Some(unsupported::C_CopyObject),
        C_DestroyObject: Some(C_DestroyObject),
        C_GetObjectSize: Some(unsupported::C_GetObjectSize),
        C_GetAttributeValue: Some(C_GetAttributeValue),
        C_SetAttributeValue: Some(unsupported::C_SetAttributeValue),
        C_FindObjectsInit: Some(C_FindObjectsInit),
        C_FindObjects: Some(C_FindObjects),
        C_FindObjectsFinal: Some(C_FindObjectsFinal),
        C_EncryptInit: Some(C_EncryptInit),
        C_Encrypt: Some(C_Encrypt),
        C_EncryptUpdate: Some(unsupported::C_EncryptUpdate),
        C_EncryptFinal: Some(unsupported::C_EncryptFinal),
        C_DecryptInit: Some(C_DecryptInit),
        C_Decrypt: Some(C_Decrypt),
        C_DecryptUpdate: Some(unsupported::C_DecryptUpdate),
        C_DecryptFinal: Some(unsupported::C_DecryptFinal),
        C_DigestInit: Some(C_DigestInit),
        C_Digest: Some(C_Digest),
        C_DigestUpdate: Some(unsupported::C_DigestUpdate),
        C_DigestKey: Some(unsupported::C_DigestKey),
        C_DigestFinal: Some(unsupported::C_DigestFinal),
        C_SignInit: Some(C_SignInit),
        C_Sign: Some(C_Sign),
        C_SignUpdate: Some(unsupported::C_SignUpdate),
        C_SignFinal: Some(unsupported::C_SignFinal),
        C_SignRecoverInit: Some(unsupported::C_SignRecoverInit),
        C_SignRecover: Some(unsupported::C_SignRecover),
        C_VerifyInit: Some(unsupported::C_VerifyInit),
        C_Verify: Some(unsupported::C_Verify),
        C_VerifyUpdate: Some(unsupported::C_VerifyUpdate),
        C_VerifyFinal: Some(unsupported::C_VerifyFinal),
        C_VerifyRecoverInit: Some(unsupported::C_VerifyRecoverInit),
        C_VerifyRecover: Some(unsupported::C_VerifyRecover),
        C_DigestEncryptUpdate: Some(unsupported::C_DigestEncryptUpdate),
        C_DecryptDigestUpdate: Some(unsupported::C_DecryptDigestUpdate),
        C_SignEncryptUpdate: Some(unsupported::C_SignEncryptUpdate),
        C_DecryptVerifyUpdate: Some(unsupported::C_DecryptVerifyUpdate),
        C_GenerateKey: Some(C_GenerateKey),
        C_GenerateKeyPair: Some(C_GenerateKeyPair),
        C_WrapKey: Some(C_WrapKey),
        C_UnwrapKey: Some(C_UnwrapKey),
        C_DeriveKey: Some(unsupported::C_DeriveKey),
        C_SeedRandom: Some(unsupported::C_SeedRandom),
        C_GenerateRandom: Some(unsupported::C_GenerateRandom),
        C_GetFunctionStatus: Some(unsupported::C_GetFunctionStatus),
        C_CancelFunction: Some(unsupported::C_CancelFunction),
        C_WaitForSlotEvent: Some(unsupported::C_WaitForSlotEvent),
    };

    unsafe {
        *ppFunctionList = libc::malloc(mem::size_of::<CK_FUNCTION_LIST>() as libc::size_t)
            as *mut CK_FUNCTION_LIST;
        if (*ppFunctionList).is_null() {
            return CKR_HOST_MEMORY as CK_RV;
        }
        **ppFunctionList = function_list;
    }
    CKR_OK as CK_RV
}

#[cfg(test)]
mod test {
    use crate::cryptoki::{
        bindings::{
            CKR_ARGUMENTS_BAD, CKR_OK, CK_FUNCTION_LIST_PTR, CK_FUNCTION_LIST_PTR_PTR, CK_RV,
        },
        general_purpose::C_GetFunctionList,
    };

    #[test]
    fn c_get_function_list_returns_ckr_ok() {
        let mut funct_list_ptr: CK_FUNCTION_LIST_PTR = 0 as CK_FUNCTION_LIST_PTR;
        let return_value = unsafe { C_GetFunctionList(&mut funct_list_ptr) };
        assert_eq!(
            return_value, CKR_OK as CK_RV,
            "C_GetFunctionList didn't return CKR_OK",
        );
        assert!(
            !funct_list_ptr.is_null(),
            "C_GetFunctionList set null pointer"
        );
        unsafe { libc::free(funct_list_ptr as *mut libc::c_void) }
    }

    #[test]
    fn given_nullptr_c_get_function_list_returns_ckr_arguments_bad() {
        let return_value = unsafe { C_GetFunctionList(0 as CK_FUNCTION_LIST_PTR_PTR) };
        assert_eq!(
            return_value, CKR_ARGUMENTS_BAD as CK_RV,
            "C_GetFunctionList didn't return CKR_ARGUMENTS_BAD",
        );
    }
}
