use std::ptr;

use crate::state::{object::template::Template, session::single_session::Signer, StateAccessor};
const CKA_REQUEST_ORIGINATOR: CK_ATTRIBUTE_TYPE =
    (CKA_VENDOR_DEFINED as CK_ATTRIBUTE_TYPE) | 0x000000000000abcd;

use super::{
    bindings::{
        CKA_VENDOR_DEFINED, CKR_ARGUMENTS_BAD, CKR_OK, CK_ATTRIBUTE_PTR, CK_ATTRIBUTE_TYPE,
        CK_BYTE_PTR, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG,
        CK_ULONG_PTR,
    },
    utils::FromPointer,
};

/// Initializes a signature operation, where the signature is an appendix to the data
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the signature mechanism
/// * `hKey` - handle of the signature key
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    let state_accessor = StateAccessor::new();
    let signing_key = match state_accessor.get_object(&hSession, &hKey) {
        Ok(key) => key,
        Err(err) => return err.into_ck_rv(),
    };

    let mechanism = unsafe { *pMechanism };
    let attributes = unsafe {
        Vec::from_pointer(
            mechanism.pParameter as CK_ATTRIBUTE_PTR,
            mechanism.ulParameterLen as usize,
        )
    };
    let template = Template::from(attributes);
    let request_originator = template
        .get_value(&(CKA_REQUEST_ORIGINATOR as CK_ATTRIBUTE_TYPE))
        .map(|originator| String::from_utf8(originator).ok())
        .and_then(|x| x);

    if let Err(err) =
        state_accessor.set_signer(&hSession, Signer::new(signing_key, request_originator))
    {
        return err.into_ck_rv();
    }

    CKR_OK as CK_RV
}

/// Signs data in a single part, where the signature is an appendix to the data
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pData` - points to the data
/// * `ulDataLen` - the length of the data
/// * `pSignature` - points to the location that receives the signature
/// * `pulSignatureLen` - points to the location that holds the length of the signature
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulSignatureLen.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();

    let signer = match state_accessor.get_signer(&hSession) {
        Ok(val) => val,
        Err(err) => return err.into_ck_rv(),
    };
    let mut cached_response = signer.response.clone();
    if cached_response.is_none() {
        // response not stored from the previous call, send the request
        let pubkey = signer.key.get_value().unwrap();

        let auth_data = unsafe { Vec::from_pointer(pData, ulDataLen as usize) };

        let response = match state_accessor.send_signing_request_wait_for_response(
            pubkey,
            auth_data,
            signer.auth_request_originator,
        ) {
            Ok(response) => response,
            Err(err) => {
                println!("Authentication request failed.");
                return err.into_ck_rv();
            }
        };
        if let Err(err) = state_accessor.store_signing_response(&hSession, response.clone()) {
            return err.into_ck_rv();
        }
        cached_response = Some(response);
    }

    let response = cached_response.unwrap();
    unsafe {
        *pulSignatureLen = response.len() as CK_ULONG;
    }

    if !pSignature.is_null() {
        unsafe {
            ptr::copy(response.as_ptr(), pSignature, response.len());
        }
    }

    CKR_OK as CK_RV
}
