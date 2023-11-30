use std::ptr;

use crate::state::StateAccessor;

use super::{
    bindings::{
        CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA_1, CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED,
        CKR_OK, CK_BYTE_PTR, CK_MECHANISM_PTR, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
    },
    utils::FromPointer,
};
use openssl::hash::{Hasher, MessageDigest};

/// Initializes a message-digesting operation
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the digesting mechanism
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV {
    if pMechanism.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let digest = match unsafe { (*pMechanism).mechanism as u32 } {
        CKM_SHA_1 => MessageDigest::sha1(),
        CKM_SHA256 => MessageDigest::sha256(),
        CKM_SHA384 => MessageDigest::sha384(),
        CKM_SHA512 => MessageDigest::sha512(),
        _ => {
            return CKR_ARGUMENTS_BAD as CK_RV;
        }
    };
    let Ok(hasher) = Hasher::new(digest) else {
        return CKR_FUNCTION_FAILED as CK_RV;
    };

    let state_accessor = StateAccessor::new();
    if let Err(err) = state_accessor.set_hasher(&hSession, hasher) {
        return err.into_ck_rv();
    }

    CKR_OK as CK_RV
}

/// Digests data in a single part
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pData` - points to the data
/// * `ulDataLen` - the length of the data
/// * `pDigest` - points to the location that receives the message digest
/// * `pulDigestLen` - points to the location that holds the length of the message digest
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    // TODO: cache hasher output
    let state_accessor = StateAccessor::new();
    let mut hasher = match state_accessor.get_hasher(&hSession) {
        Ok(hasher) => hasher,
        Err(err) => return err.into_ck_rv(),
    };

    let data_buffer = unsafe { Vec::from_pointer(pData, ulDataLen as usize) };

    if hasher.update(&data_buffer).is_err() {
        // TODO: reset hasher state
        return CKR_FUNCTION_FAILED as CK_RV;
    }

    let Ok(digest) = hasher.finish() else {
        return CKR_FUNCTION_FAILED as CK_RV;
    };

    let digest = digest.to_vec();
    unsafe {
        *pulDigestLen = digest.len() as CK_ULONG;
    }
    // todo: check convention from 5.2

    if !pDigest.is_null() {
        unsafe {
            ptr::copy(digest.as_ptr(), pDigest, digest.len());
        }
    }
    CKR_OK as CK_RV
}

#[cfg(test)]
mod test {
    use openssl::{
        error::ErrorStack,
        hash::{Hasher, MessageDigest},
    };

    use crate::cryptoki::{
        bindings::{
            CKM_SHA256, CKR_OK, CK_BYTE_PTR, CK_MECHANISM, CK_MECHANISM_PTR, CK_MECHANISM_TYPE,
            CK_RV, CK_SESSION_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR, CK_VOID_PTR, NULL_PTR,
        },
        general_purpose::C_Initialize,
        message_digesting::{C_Digest, C_DigestInit},
        session_management::{C_CloseSession, C_OpenSession},
    };

    #[test]
    #[ignore]
    fn given_valid_data_c_digest_produces_valid_hash() -> Result<(), ErrorStack> {
        assert_eq!(CKR_OK as CK_RV, C_Initialize(NULL_PTR as CK_VOID_PTR));
        let mut session_handle = 0;
        assert_eq!(CKR_OK as CK_RV, unsafe {
            C_OpenSession(
                0,
                0,
                NULL_PTR as CK_VOID_PTR,
                None,
                &mut session_handle as CK_SESSION_HANDLE_PTR,
            )
        });
        let mut digest_mechanism = CK_MECHANISM {
            mechanism: CKM_SHA256 as CK_MECHANISM_TYPE,
            pParameter: NULL_PTR as CK_VOID_PTR,
            ulParameterLen: 0,
        };

        assert_eq!(
            unsafe { C_DigestInit(session_handle, &mut digest_mechanism as CK_MECHANISM_PTR) },
            CKR_OK as CK_RV
        );

        let mut data: Vec<u8> = vec![1, 2, 3, 4, 5];
        let mut digest: Vec<u8> = vec![0; MessageDigest::sha256().size() + 1];
        let mut digest_len: CK_ULONG = 0;
        assert_eq!(
            unsafe {
                C_Digest(
                    session_handle,
                    data.as_mut_ptr() as CK_BYTE_PTR,
                    data.len() as CK_ULONG,
                    digest.as_mut_ptr() as CK_BYTE_PTR,
                    &mut digest_len as CK_ULONG_PTR,
                )
            },
            CKR_OK as CK_RV
        );
        let digest: Vec<u8> = digest.iter().cloned().take(digest_len as usize).collect();
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        hasher.update(&data)?;
        let target_digest = hasher.finish()?.to_vec();

        assert_eq!(target_digest, digest);

        assert_eq!(CKR_OK as CK_RV, C_CloseSession(session_handle));
        Ok(())
    }
}
