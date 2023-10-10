use std::ptr;

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
};

use crate::state::StateAccessor;

use super::{
    bindings::{
        CKM_AES_ECB, CKR_ARGUMENTS_BAD, CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OK,
        CK_BYTE_PTR, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG,
        CK_ULONG_PTR,
    },
    utils::FromPointer,
};

/// Initializes an encryption operation
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the encryption mechanism
/// * `hKey` - the handle of the encryption key
#[allow(non_snake_case)]
pub(crate) fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let state_accessor = StateAccessor::new();
    let mechanism = unsafe { *pMechanism };
    // todo: support other algos
    match mechanism.mechanism as u32 {
        CKM_AES_ECB => {}
        _ => return CKR_MECHANISM_INVALID as CK_RV,
    };
    let key = match state_accessor.get_object(&hSession, &hKey) {
        Ok(key) => key,
        Err(err) => return err.into_ck_rv(),
    };
    let key = key.get_value().unwrap();
    let key = GenericArray::clone_from_slice(&key[0..16]);
    let encryptor = Aes128::new(&key);
    if let Err(err) = state_accessor.set_encryptor(&hSession, encryptor) {
        return err.into_ck_rv();
    }

    CKR_OK as CK_RV
}

/// Encrypts single-part data
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pData` - points to the data
/// * `ulDataLen` - the length in bytes of the data
/// * `pEncryptedData` - points to the location that receives the encrypted data
/// * `pulEncryptedDataLen` - points to the location that holds the length in bytes of the encrypted data
#[allow(non_snake_case)]
pub(crate) fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    if pData.is_null() || pulEncryptedDataLen.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let encryptor = match state_accessor.get_encryptor(&hSession) {
        Ok(encryptor) => encryptor,
        Err(err) => return err.into_ck_rv(),
    };
    let data = unsafe { Vec::from_pointer(pData, ulDataLen as usize) };
    let mut cipher_length = 0;
    // TODO: check block length
    for block_i in 0..(data.len() / 16) {
        let mut block =
            GenericArray::from_slice(&data[(16 * block_i)..(16 * (block_i + 1))]).to_owned();
        encryptor.encrypt_block(&mut block);
        if !pEncryptedData.is_null() {
            unsafe {
                ptr::copy(
                    block.as_ptr(),
                    pEncryptedData.offset((block_i * 16) as isize),
                    block.len(),
                );
            }
        }
        cipher_length += block.len();
    }

    unsafe {
        *pulEncryptedDataLen = cipher_length as CK_ULONG;
    }

    CKR_OK as CK_RV
}

/// Continues a multiple-part encryption operation, processing another data part
///
/// # Arguments
///
/// * `hSession` - is the session’s handle
/// * `pPart` - points to the data part
/// * `ulPartLen` - the length of the data part
/// * `pEncryptedPart` - points to the location that receives the encrypted data part
/// * `pulEncryptedPartLen` - points to the location that holds the length in bytes of the encrypted data part
#[allow(non_snake_case)]
pub(crate) fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    // TODO
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}

/// Finishes a multiple-part encryption operation
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pLastEncryptedPart` - points to the location that receives the last encrypted data part, if any
/// * `pulLastEncryptedPartLen` - points to the location that holds the length of the last encrypted data part
#[allow(non_snake_case)]
pub(super) fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    // TODO
    CKR_FUNCTION_NOT_SUPPORTED as CK_RV
}
