use std::ptr;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt};

use crate::state::StateAccessor;

use super::{
    bindings::{
        CKR_ARGUMENTS_BAD, CKR_OK, CK_BYTE_PTR, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_RV,
        CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
    },
    encryption::C_EncryptInit,
    utils::FromPointer,
};

/// Initializes a decryption operation
///
/// # Arguments
///
/// `hSession` - the session’s handle
/// `pMechanism` - points to the decryption mechanism
/// `hKey` - the handle of the decryption key
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    unsafe { C_EncryptInit(hSession, pMechanism, hKey) }
}

/// Decrypts encrypted data in a single part
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pEncryptedData` - points to the encrypted data
/// * `ulEncryptedDataLen` - the length of the encrypted data
/// * `pData` - points to the location that receives the recovered data
/// * `pulDataLen` - points to the location that holds the length of the recovered data
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    // TODO: refactor, and properly implement, right now the implementation is very unsafe!

    if pEncryptedData.is_null() || pulDataLen.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let accessor = StateAccessor::new();
    let encryptor = match accessor.get_encryptor(&hSession) {
        Ok(encryptor) => encryptor,
        Err(err) => return err.into_ck_rv(),
    };

    let data = unsafe { Vec::from_pointer(pEncryptedData, ulEncryptedDataLen as usize) };
    let mut cipher_length = 0;
    // TODO: check block length
    for block_i in 0..(data.len() / 16) {
        let mut block =
            GenericArray::from_slice(&data[(16 * block_i)..(16 * (block_i + 1))]).to_owned();
        encryptor.decrypt_block(&mut block);
        if !pData.is_null() {
            unsafe {
                ptr::copy(block.as_ptr(), pData.add(block_i * 16), block.len());
            }
        }
        cipher_length += block.len();
    }

    unsafe {
        *pulDataLen = cipher_length as CK_ULONG;
    }

    CKR_OK as CK_RV
}
