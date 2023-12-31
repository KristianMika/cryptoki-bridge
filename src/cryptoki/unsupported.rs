//
// Warning: Please, don't modify by hand, the file is generated by a script
//
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_variables)]

use super::bindings::*;

/// Generates two functions conditionally compiled for Win and Linux
/// that return CKR_FUNCTION_NOT_SUPPORTED as specified
/// by PKCS#11 spec for unimplemented functions
///
/// # Arguments
///
/// * function name with arguments
///
/// # Example
///
/// ```no_run
/// unsupported!(C_CloseAllSessions(slotID: CK_SLOT_ID));
/// ```
///
/// evaluates to
///
/// ```no_run
/// #[no_mangle]
/// #[cfg(target_os = "linux")]
/// pub extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
///     CKR_FUNCTION_NOT_SUPPORTED as CK_RV
/// }
/// #[no_mangle]
/// #[cfg(target_os = "windows")]
/// pub extern "system" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
///     CKR_FUNCTION_NOT_SUPPORTED as CK_RV
/// }
/// ```
macro_rules! unsupported{
    ($function_name:ident($($argument:tt)*))=>{
        #[no_mangle]
        #[cfg(target_os = "linux")]
        pub extern "C" fn $function_name($($argument)*) -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV
        }

        #[no_mangle]
        #[cfg(target_os = "windows")]
        pub extern "system" fn $function_name($($argument)*) -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED as CK_RV
        }
    }
}

unsupported!(
    C_GetMechanismList(
        slotID: CK_SLOT_ID,
        pMechanismList: CK_MECHANISM_TYPE_PTR,
        pulCount: CK_ULONG_PTR,
    )
);

unsupported!(
    C_GetMechanismInfo(
        slotID: CK_SLOT_ID,
        type_: CK_MECHANISM_TYPE,
        pInfo: CK_MECHANISM_INFO_PTR,
    )
);

unsupported!(
    C_InitToken(
        slotID: CK_SLOT_ID,
        pPin: CK_UTF8CHAR_PTR,
        ulPinLen: CK_ULONG,
        pLabel: CK_UTF8CHAR_PTR,
    )
);

unsupported!(
    C_InitPIN(
        hSession: CK_SESSION_HANDLE,
        pPin: CK_UTF8CHAR_PTR,
        ulPinLen: CK_ULONG,
    )
);

unsupported!(
    C_SetPIN(
        hSession: CK_SESSION_HANDLE,
        pOldPin: CK_UTF8CHAR_PTR,
        ulOldLen: CK_ULONG,
        pNewPin: CK_UTF8CHAR_PTR,
        ulNewLen: CK_ULONG,
    )
);

unsupported!(
    C_CloseAllSessions(slotID: CK_SLOT_ID)
);

unsupported!(
    C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR)
);

unsupported!(
    C_GetOperationState(
        hSession: CK_SESSION_HANDLE,
        pOperationState: CK_BYTE_PTR,
        pulOperationStateLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_SetOperationState(
        hSession: CK_SESSION_HANDLE,
        pOperationState: CK_BYTE_PTR,
        ulOperationStateLen: CK_ULONG,
        hEncryptionKey: CK_OBJECT_HANDLE,
        hAuthenticationKey: CK_OBJECT_HANDLE,
    )
);

unsupported!(
    C_CopyObject(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
        phNewObject: CK_OBJECT_HANDLE_PTR,
    )
);

unsupported!(
    C_GetObjectSize(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pulSize: CK_ULONG_PTR,
    )
);

unsupported!(
    C_SetAttributeValue(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
    )
);

unsupported!(C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
));

unsupported!(C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
));

unsupported!(
    C_DecryptUpdate(
        hSession: CK_SESSION_HANDLE,
        pEncryptedPart: CK_BYTE_PTR,
        ulEncryptedPartLen: CK_ULONG,
        pPart: CK_BYTE_PTR,
        pulPartLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_DecryptFinal(
        hSession: CK_SESSION_HANDLE,
        pLastPart: CK_BYTE_PTR,
        pulLastPartLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_DigestUpdate(
        hSession: CK_SESSION_HANDLE,
        pPart: CK_BYTE_PTR,
        ulPartLen: CK_ULONG,
    )
);

unsupported!(
    C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE)
);

unsupported!(
    C_DigestFinal(
        hSession: CK_SESSION_HANDLE,
        pDigest: CK_BYTE_PTR,
        pulDigestLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_SignUpdate(
        hSession: CK_SESSION_HANDLE,
        pPart: CK_BYTE_PTR,
        ulPartLen: CK_ULONG,
    )
);

unsupported!(
    C_SignFinal(
        hSession: CK_SESSION_HANDLE,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_SignRecover(
        hSession: CK_SESSION_HANDLE,
        pData: CK_BYTE_PTR,
        ulDataLen: CK_ULONG,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_SignRecoverInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    )
);

unsupported!(
    C_Verify(
        hSession: CK_SESSION_HANDLE,
        pData: CK_BYTE_PTR,
        ulDataLen: CK_ULONG,
        pSignature: CK_BYTE_PTR,
        ulSignatureLen: CK_ULONG,
    )
);

unsupported!(
    C_VerifyInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    )
);

unsupported!(
    C_VerifyUpdate(
        hSession: CK_SESSION_HANDLE,
        pPart: CK_BYTE_PTR,
        ulPartLen: CK_ULONG,
    )
);

unsupported!(
    C_VerifyFinal(
        hSession: CK_SESSION_HANDLE,
        pSignature: CK_BYTE_PTR,
        ulSignatureLen: CK_ULONG,
    )
);

unsupported!(
    C_VerifyRecover(
        hSession: CK_SESSION_HANDLE,
        pSignature: CK_BYTE_PTR,
        ulSignatureLen: CK_ULONG,
        pData: CK_BYTE_PTR,
        pulDataLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_VerifyRecoverInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    )
);

unsupported!(
    C_DigestEncryptUpdate(
        hSession: CK_SESSION_HANDLE,
        pPart: CK_BYTE_PTR,
        ulPartLen: CK_ULONG,
        pEncryptedPart: CK_BYTE_PTR,
        pulEncryptedPartLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_DecryptDigestUpdate(
        hSession: CK_SESSION_HANDLE,
        pEncryptedPart: CK_BYTE_PTR,
        ulEncryptedPartLen: CK_ULONG,
        pPart: CK_BYTE_PTR,
        pulPartLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_SignEncryptUpdate(
        hSession: CK_SESSION_HANDLE,
        pPart: CK_BYTE_PTR,
        ulPartLen: CK_ULONG,
        pEncryptedPart: CK_BYTE_PTR,
        pulEncryptedPartLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_DecryptVerifyUpdate(
        hSession: CK_SESSION_HANDLE,
        pEncryptedPart: CK_BYTE_PTR,
        ulEncryptedPartLen: CK_ULONG,
        pPart: CK_BYTE_PTR,
        pulPartLen: CK_ULONG_PTR,
    )
);

unsupported!(
    C_DeriveKey(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hBaseKey: CK_OBJECT_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulAttributeCount: CK_ULONG,
        phKey: CK_OBJECT_HANDLE_PTR,
    )
);

unsupported!(
    C_SeedRandom(
        hSession: CK_SESSION_HANDLE,
        pSeed: CK_BYTE_PTR,
        ulSeedLen: CK_ULONG,
    )
);

unsupported!(
    C_GenerateRandom(
        hSession: CK_SESSION_HANDLE,
        RandomData: CK_BYTE_PTR,
        ulRandomLen: CK_ULONG,
    )
);

unsupported!(
    C_GetFunctionStatus(hSession: CK_SESSION_HANDLE)
);

unsupported!(
    C_CancelFunction(hSession: CK_SESSION_HANDLE)
);

unsupported!(
    C_WaitForSlotEvent(
        flags: CK_FLAGS,
        pSlot: CK_SLOT_ID_PTR,
        pRserved: CK_VOID_PTR,
    )
);
