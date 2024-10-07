use aes::cipher::{
    block_padding::Pkcs7, generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use derive_new::new;
use rand::{rngs::OsRng, Rng};

use crate::cryptoki::{
    bindings::CK_BYTE_PTR,
    key_management::{Aes128CbcDec, Aes128CbcEnc, AES_BLOCK_SIZE, AES_IV_SIZE},
    utils::FromPointer,
};

pub(crate) fn encrypt_pad(key: &[u8], plaintext: Vec<u8>) -> EncryptionOutput {
    let key = GenericArray::from_slice(key).to_owned();
    let iv: [u8; AES_BLOCK_SIZE] = OsRng.gen();
    let mut plaintext_buffer: Vec<u8> = vec![0; plaintext.len() + AES_BLOCK_SIZE];
    let plaintext_length = plaintext.len();
    plaintext_buffer[..plaintext_length].copy_from_slice(&plaintext);

    let ciphertext = Aes128CbcEnc::new(&key, &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut plaintext_buffer, plaintext_length)
        .unwrap()
        .to_vec();
    EncryptionOutput::new(ciphertext, iv.to_vec())
}

pub(crate) fn compute_pkcs7_padded_ciphertext_size(plaintext_length: usize) -> usize {
    plaintext_length + (AES_BLOCK_SIZE - (plaintext_length % AES_BLOCK_SIZE))
}

pub(crate) fn decrypt(key: &[u8], mut ciphertext: Vec<u8>, iv: Vec<u8>) -> Vec<u8> {
    let key = GenericArray::from_slice(key).to_owned();
    let iv: [u8; AES_BLOCK_SIZE] = iv[..AES_BLOCK_SIZE].try_into().unwrap();

    let plaintext: Vec<u8> = Aes128CbcDec::new(&key, &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
        .unwrap()
        .to_vec();

    plaintext
}

pub(crate) unsafe fn destructure_iv_ciphertext(
    ciphertext_with_iv: CK_BYTE_PTR,
    length: usize,
) -> EncryptionOutput {
    let iv_pointer = ciphertext_with_iv;
    let iv = Vec::from_pointer(iv_pointer, AES_IV_SIZE);

    let ciphertext_pointer = ciphertext_with_iv.add(AES_IV_SIZE);
    let ciphertext_length = length - AES_IV_SIZE;
    let ciphertext = Vec::from_pointer(ciphertext_pointer, ciphertext_length);

    EncryptionOutput::new(ciphertext, iv)
}

#[derive(new)]
pub struct EncryptionOutput {
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
}

impl EncryptionOutput {
    pub fn into_combined(self) -> Vec<u8> {
        let mut ciphertext_with_iv = self.iv;
        ciphertext_with_iv.extend(self.ciphertext);
        ciphertext_with_iv
    }
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::*;
    #[test]
    fn given_plaintext_encrypt_decrypt_return_plaintext() {
        let key = vec![1; 16];
        let plaintext = vec![2; 32];
        let ciphertext = encrypt_pad(&key, plaintext.clone());
        let decrypted_plaintext = decrypt(&key, ciphertext.ciphertext, ciphertext.iv);
        assert_eq!(plaintext, decrypted_plaintext);
    }

    #[test]
    fn given_large_enough_buffer_destructure_iv_ciphertext_correctly_splits_the_two() {
        let iv = vec![1; AES_IV_SIZE];
        let ciphertext = vec![2; 2 * AES_BLOCK_SIZE];
        let mut ciphertext_with_iv = iv.clone();
        ciphertext_with_iv.extend(ciphertext.clone());
        let destructured = unsafe {
            destructure_iv_ciphertext(ciphertext_with_iv.as_mut_ptr(), ciphertext_with_iv.len())
        };
        assert_eq!(iv, destructured.iv);
        assert_eq!(ciphertext, destructured.ciphertext);
    }

    #[rstest]
    #[case(5, 16)]
    #[case(15, 16)]
    #[case(16, 32)]
    fn given_plaintext_length_compute_pkcs7_padded_ciphertext_size_gives_valid_ciphertext_length(
        #[case] plaintext_length: usize,
        #[case] expected_ciphertext_length: usize,
    ) {
        let actual_ciphertext_length = compute_pkcs7_padded_ciphertext_size(plaintext_length);
        assert_eq!(actual_ciphertext_length, expected_ciphertext_length);
    }
}
