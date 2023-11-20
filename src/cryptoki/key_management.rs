use std::{ptr, sync::Arc};

use rand::{rngs::OsRng, Rng};

use super::{
    bindings::{
        CKA_CLASS, CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD, CKM_ECDSA_KEY_PAIR_GEN,
        CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CKO_PUBLIC_KEY, CKR_ARGUMENTS_BAD,
        CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID, CKR_OK, CKR_VENDOR_DEFINED,
        CK_ATTRIBUTE_PTR, CK_ATTRIBUTE_TYPE, CK_BYTE_PTR, CK_MECHANISM_PTR, CK_MECHANISM_TYPE,
        CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
    },
    internals::encryption::{
        compute_pkcs7_padded_ciphertext_size, decrypt, destructure_iv_ciphertext, encrypt_pad,
    },
    utils::FromPointer,
};
use crate::{
    state::{
        object::{
            cryptoki_object::CryptokiObject, private_key_object::PrivateKeyObject,
            secret_key_object::SecretKeyObject, template::Template,
        },
        StateAccessor,
    },
    SESSIONS,
};

pub(crate) type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
pub(crate) type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
pub(crate) const AES_BLOCK_SIZE: usize = 16;
pub(crate) const AES_IV_SIZE: usize = AES_BLOCK_SIZE;

/// Generates a secret key or set of domain parameters, creating a new object
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the generation mechanism
/// * `pTemplate` - points to the template for the new key or set of domain parameters
/// * `ulCount` - the number of attributes in the template
/// * `phKey` - points to the location that receives the handle of the new key or set of domain parameters
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if pMechanism.is_null() || pTemplate.is_null() || phKey.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let mechanism = unsafe { *pMechanism };

    if mechanism.mechanism as u32 != CKM_AES_KEY_GEN {
        return CKR_FUNCTION_NOT_SUPPORTED as CK_RV;
    }
    let template = unsafe { Vec::from_pointer(pTemplate, ulCount as usize) };
    let template = Template::from(template);
    let mut object = SecretKeyObject::from_template(template);

    let key: [u8; 16] = OsRng.gen();
    object.store_value(key.into());

    let state_accessor = StateAccessor::new();
    let object_handle = match state_accessor.create_object(&hSession, Arc::new(object)) {
        Ok(handle) => handle,
        Err(err) => err.into_ck_rv(),
    };
    unsafe { *phKey = object_handle };

    CKR_OK as CK_RV
}

/// Generates a public/private key pair, creating new key objects
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the key generation mechanism
/// * `pPublicKeyTemplate` - points to the template for the public key
/// * `ulPublicKeyAttributeCount` - the number of attributes in the public-key template
/// * `pPrivateKeyTemplate` - points to the template for the private key
/// * `ulPrivateKeyAttributeCount` - the number of attributes in the private-key template
/// * `phPublicKey` - points to the location that receives the handle of the new public key
/// * `phPrivateKey` - points to the location that receives the handle of the new private key
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    _pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    _ulPublicKeyAttributeCount: CK_ULONG,
    _pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    _ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let mechanism = unsafe { *pMechanism };
    let pub_key_template = {
        let template =
            unsafe { Vec::from_pointer(_pPublicKeyTemplate, _ulPublicKeyAttributeCount as usize) };
        Template::from(template)
    };
    let priv_key_template = {
        let template = unsafe {
            Vec::from_pointer(_pPrivateKeyTemplate, _ulPrivateKeyAttributeCount as usize)
        };
        Template::from(template)
    };

    if mechanism.mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE {
        let state_accessor = StateAccessor::new();
        let mut sessions = SESSIONS.write().unwrap();
        let session = sessions
            .as_mut()
            .unwrap()
            .get_session_mut(&hSession)
            .unwrap();

        let meesign_pubkey = session
            .ephemeral_objects
            .values()
            .find(|obj| {
                obj.get_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE).unwrap()
                    == (CKO_PUBLIC_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
            })
            .expect("No public key found");

        let (private_key_handle, pubkey_handle) = match state_accessor.get_communicator_keypair(
            &hSession,
            &pub_key_template,
            &priv_key_template,
        ) {
            Ok(val) => val,
            Err(err) => return err.into_ck_rv(),
        };

        unsafe {
            *phPublicKey = pubkey_handle;
            *phPrivateKey = private_key_handle;
        };

        return CKR_OK as CK_RV;
    }
    return CKR_MECHANISM_INVALID as CK_RV;

    // if mechanism.mechanism != CKM_ECDSA_KEY_PAIR_GEN as CK_MECHANISM_TYPE
    //     || mechanism.mechanism != CKM_RSA_PKCS as CK_MECHANISM_TYPE
    // {
    //     // we are supporting only ECDSA keys that are already generated externally
    //     return CKR_MECHANISM_INVALID as CK_RV;
    // }

    //     let state_accessor = StateAccessor::new();
    //     let (private_key_handle, pubkey_handle) = match state_accessor.get_keypair(&hSession) {
    //         Ok(val) => val,
    //         Err(err) => return err.into_ck_rv(),
    //     };

    //     unsafe {
    //         *phPublicKey = pubkey_handle;
    //         *phPrivateKey = private_key_handle;
    //     };

    //     CKR_OK as CK_RV
}

/// Wraps (i.e., encrypts) a private or secret key
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the wrapping mechanism
/// * `hWrappingKey` - the handle of the wrapping key
/// * `hKey` - the handle of the key to be wrapped
/// * `pWrappedKey` - points to the location that receives the wrapped key
/// * `pulWrappedKeyLen` - points to the location that receives the length of the wrapped key
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    if pulWrappedKeyLen.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let mechanism = unsafe { *pMechanism };
    if mechanism.mechanism != CKM_AES_KEY_WRAP_PAD as CK_MECHANISM_TYPE {
        return CKR_MECHANISM_INVALID as CK_RV;
    }

    let state_accessor = StateAccessor::new();
    let wrapping_key = match state_accessor.get_object(&hSession, &hWrappingKey) {
        Ok(val) => val,
        Err(err) => return err.into_ck_rv(),
    };
    let private_key = match state_accessor.get_object(&hSession, &hKey) {
        Ok(val) => val,
        Err(err) => return err.into_ck_rv(),
    };
    let private_key = private_key.get_value().unwrap();
    let key = &wrapping_key.get_value().unwrap();

    if pWrappedKey.is_null() {
        // the application is asking for the size of the wrapped key
        let ciphertext_with_iv_len =
            AES_IV_SIZE + compute_pkcs7_padded_ciphertext_size(private_key.len());
        unsafe {
            *pulWrappedKeyLen = ciphertext_with_iv_len as CK_ULONG;
        }
        return CKR_OK as CK_RV;
    }

    let encryption_output = encrypt_pad(key, private_key);

    let ciphertext_with_iv = encryption_output.into_combined();
    unsafe {
        *pulWrappedKeyLen = ciphertext_with_iv.len() as CK_ULONG;
    }

    unsafe {
        ptr::copy(
            ciphertext_with_iv.as_ptr(),
            pWrappedKey,
            ciphertext_with_iv.len(),
        );
    }

    CKR_OK as CK_RV
}

/// Unwraps (i.e. decrypts) a wrapped key, creating a new private key or secret key object
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pMechanism` - points to the unwrapping mechanism
/// * `hUnwrappingKey` - the handle of the unwrapping key
/// * `pWrappedKey` - points to the wrapped key
/// * `ulWrappedKeyLen` - the length of the wrapped key
/// * `pTemplate` - points to the template for the new key
/// * `ulAttributeCount` - the number of attributes in the template
/// * `phKey` - points to the location that receives the handle of the recovered key
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if pWrappedKey.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let mechanism = unsafe { *pMechanism };
    match mechanism.mechanism as u32 {
        CKM_AES_KEY_WRAP_PAD => {}
        CKM_AES_KEY_WRAP => {}
        _ => return CKR_MECHANISM_INVALID as CK_RV,
    };

    let state_accessor = StateAccessor::new();
    let unwrapping_key = match state_accessor.get_object(&hSession, &hUnwrappingKey) {
        Ok(val) => val,
        Err(err) => return err.into_ck_rv(),
    };

    let key = unwrapping_key.get_value().unwrap();
    let encryption_output =
        unsafe { destructure_iv_ciphertext(pWrappedKey, ulWrappedKeyLen as usize) };

    let plaintext = decrypt(&key, encryption_output.ciphertext, encryption_output.iv);

    let attributes = unsafe { Vec::from_pointer(pTemplate, ulAttributeCount as usize) };
    let template = Template::from(attributes);
    let mut private_key_object = PrivateKeyObject::from_template(template);
    private_key_object.store_value(plaintext);

    let handle =
        match state_accessor.create_ephemeral_object(&hSession, Arc::new(private_key_object)) {
            Ok(val) => val,
            Err(err) => return err.into_ck_rv(),
        };
    unsafe {
        *phKey = handle;
    }
    CKR_OK as CK_RV
}
