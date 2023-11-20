use std::{collections::HashMap, iter::Chain, sync::Arc, vec::IntoIter};

use aes::Aes128;
use openssl::hash::Hasher;
use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts, RsaPublicKey};
use uuid::Uuid;

use crate::{
    communicator::{AuthResponse, GroupId},
    cryptoki::bindings::{
        CKA_ALWAYS_AUTHENTICATE, CKA_CLASS, CKA_DECRYPT, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT,
        CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_MODULUS_BITS, CKA_PRIVATE,
        CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VALUE, CKA_VERIFY,
        CKA_WRAP, CKK_ECDSA, CKK_RSA, CKM_RSA_PKCS, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
        CK_ATTRIBUTE_TYPE, CK_FALSE, CK_OBJECT_HANDLE, CK_TRUE,
    },
    cryptoki_error::CryptokiError,
    persistence::{persistence_error::PersistenceError, CryptokiRepo},
    state::{
        object::{
            attribute::Attribute,
            cryptoki_object::{AttributeValue, CryptokiObject},
            object_search::ObjectSearch,
            private_key_object::PrivateKeyObject,
            public_key_object::PublicKeyObject,
            template::Template,
        },
        slots::TokenStore,
    },
    utils::as_der_octet_string,
};

use super::handle_resolver::HandleResolver;

const NIST_P256_EC_PARAMS_DER_HEX: &str = "06082a8648ce3d030107";
static KEYPAIR_IDENTIFIER_FROM_PUBLIC_PREFIX_LENGTH: usize = 8;

type ObjectSearchIterator = Chain<IntoIter<CK_OBJECT_HANDLE>, IntoIter<CK_OBJECT_HANDLE>>;

/// Holds the current state of PKCS#11 lib
pub(crate) struct Session {
    /// Holds the object managed by functions C_Digest*
    hasher: Option<Hasher>,

    object_search: Option<ObjectSearch>,

    object_search_iterator: Option<ObjectSearchIterator>,

    // TODO: objects should be held by the token struct
    // TODO: also store token ID
    // TODO: RwLock
    handle_resolver: HandleResolver,

    // TODO: utilize token attribute
    #[allow(dead_code)]
    pub(crate) token: TokenStore,

    encryptor: Option<Aes128>,

    signer: Option<Signer>,

    key_pair: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,

    cryptoki_repo: Arc<dyn CryptokiRepo>,
    pub ephemeral_objects: HashMap<Uuid, Arc<dyn CryptokiObject>>,
}

#[derive(Clone)]
pub(crate) struct Signer {
    pub key: Arc<dyn CryptokiObject>,
    pub response: Option<AuthResponse>,
    pub auth_request_originator: Option<String>,
}
impl Signer {
    pub(crate) fn new(
        key: Arc<dyn CryptokiObject>,
        auth_request_originator: Option<String>,
    ) -> Self {
        Self {
            key,
            response: None,
            auth_request_originator,
        }
    }
}
impl Session {
    pub(crate) fn new(token: TokenStore, cryptoki_repo: Arc<dyn CryptokiRepo>) -> Self {
        // TODO: refactor
        let pubkey: GroupId = token.read().unwrap().get_public_key().into();
        let token_label: String = token.read().unwrap().get_label().into();
        let mut session = Self {
            hasher: None,
            object_search: None,
            token,
            encryptor: None,
            signer: None,
            object_search_iterator: None,
            key_pair: None,
            cryptoki_repo,
            handle_resolver: HandleResolver::new(),
            ephemeral_objects: HashMap::new(),
        };

        session.key_pair = Some(session.create_communicator_keypair(
            pubkey,
            token_label,
            &Template::new(),
            &Template::new(),
        ));
        session
    }
    pub fn get_keypair(&self) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        self.key_pair.unwrap()
    }
    // pub fn get_keypair_rsa(
    //     &self,
    //     pubt: &Template,
    //     privt: &Template,
    // ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    //     let pubkey: GroupId = self.token.read().unwrap().get_public_key().into();
    //     let token_label: String = self.token.read().unwrap().get_label().into();

    //     let mut session = Self {
    //         hasher: None,
    //         object_search: None,
    //         token,
    //         encryptor: None,
    //         signer: None,
    //         object_search_iterator: None,
    //         key_pair: None,
    //         cryptoki_repo,
    //         handle_resolver: HandleResolver::new(),
    //         ephemeral_objects: HashMap::new(),
    //     };

    //     pubkey, privkey = Some(session.create_communicator_keypair(
    //         pubkey,
    //         token_label,
    //         &Template::new(),
    //         &Template::new(),
    //     ));
    //     (pubkey, privkey)
    //     // self.key_pair.unwrap()
    // }
    pub fn get_hasher(&self) -> Option<Hasher> {
        self.hasher.clone()
    }

    pub fn set_hasher(&mut self, hasher: Hasher) {
        self.hasher = Some(hasher)
    }

    pub fn init_object_search(&mut self, object_search: ObjectSearch) {
        self.object_search_iterator = None;
        self.object_search = Some(object_search);
    }

    pub fn reset_object_search(&mut self) {
        self.object_search_iterator = None;
        self.object_search = None;
    }

    pub fn create_object(
        &mut self,
        object: Arc<dyn CryptokiObject>,
    ) -> Result<CK_OBJECT_HANDLE, PersistenceError> {
        let object_id = self.cryptoki_repo.store_object(object)?;
        Ok(self.handle_resolver.get_or_insert_object_handle(object_id))
    }

    pub fn create_ephemeral_object(&mut self, object: Arc<dyn CryptokiObject>) -> CK_OBJECT_HANDLE {
        let id = *object.get_id();
        self.ephemeral_objects.insert(id, object);
        self.handle_resolver.get_or_insert_object_handle(id)
    }

    pub fn destroy_object(
        &mut self,
        object_handle: &CK_OBJECT_HANDLE,
    ) -> Result<Option<Arc<dyn CryptokiObject>>, PersistenceError> {
        let Some(object_id) = self.handle_resolver.destroy_object_mapping(*object_handle) else {
            return Ok(None);
        };
        let destroyed_object = self.ephemeral_objects.remove(&object_id);
        if destroyed_object.is_some() {
            return Ok(destroyed_object);
        }
        self.cryptoki_repo.destroy_object(object_id)
    }

    pub(crate) fn get_object(
        &self,
        object_handle: CK_OBJECT_HANDLE,
    ) -> Result<Option<Arc<dyn CryptokiObject>>, PersistenceError> {
        let Some(object_id) = self.handle_resolver.get_object_id(object_handle) else {
            return Ok(None);
        };
        let object = self.ephemeral_objects.get(&object_id);
        if object.is_some() {
            return Ok(object.cloned());
        }
        self.cryptoki_repo.get_object(object_id)
    }

    pub fn get_filtered_handles(
        &mut self,
        object_count: usize,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, CryptokiError> {
        let Some(object_search) = self.object_search.as_ref() else {
            return Err(CryptokiError::OperationNotInitialized);
        };
        if self.object_search_iterator.is_none() {
            let ephemeral_objects = self
                .ephemeral_objects
                .iter()
                .filter(|(_, object)| object.does_template_match(object_search.get_template()))
                .map(|(id, _)| self.handle_resolver.get_or_insert_object_handle(*id))
                .collect::<Vec<CK_OBJECT_HANDLE>>()
                .into_iter();
            self.object_search_iterator = Some(
                self.cryptoki_repo
                    .get_objects(self.object_search.as_ref().unwrap())
                    .unwrap()
                    .iter()
                    .map(|object| {
                        self.handle_resolver
                            .get_or_insert_object_handle(*object.get_id())
                    })
                    .collect::<Vec<CK_OBJECT_HANDLE>>()
                    .into_iter()
                    .chain(ephemeral_objects),
            )
        }
        let handles = self
            .object_search_iterator
            .as_mut()
            .unwrap()
            .take(object_count)
            .collect();
        Ok(handles)
    }

    pub fn set_encryptor(&mut self, encryptor: Aes128) {
        self.encryptor = Some(encryptor);
    }

    pub fn get_encryptor(&self) -> Option<Aes128> {
        self.encryptor.clone()
    }

    pub fn set_signer(&mut self, signer: Signer) {
        self.signer = Some(signer)
    }

    pub fn get_signer(&self) -> Option<Signer> {
        self.signer.clone()
    }

    pub fn store_signing_response(&mut self, response: AuthResponse) {
        let Some(ref mut signer) = self.signer else {
            return;
        };

        signer.response = Some(response);
    }

    pub fn create_communicator_keypair(
        &mut self,
        pubkey: GroupId,
        token_label: String,
        pub_key_template: &Template,
        priv_key_template: &Template,
    ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let pubkey_template =
            get_communicator_public_key_template(&token_label, pubkey.clone(), pub_key_template);
        let pubkey_object = PublicKeyObject::from_template(pubkey_template);
        let pubkey_handle = self.create_ephemeral_object(Arc::new(pubkey_object));

        let private_key_template =
            get_communicator_private_key_template(&token_label, pubkey, priv_key_template);
        let private_key = PrivateKeyObject::from_template(private_key_template);
        let private_key_handle = self.create_ephemeral_object(Arc::new(private_key));

        (private_key_handle, pubkey_handle)
    }
}

fn get_communicator_common_key_attributes(
    token_label: &str,
    public_key: Vec<u8>,
    template: &Template,
) -> Vec<Attribute> {
    let key_identifier: Vec<u8> = public_key
        .iter()
        .cloned()
        .take(KEYPAIR_IDENTIFIER_FROM_PUBLIC_PREFIX_LENGTH)
        .collect();
    vec![
        // FIXME fixed values
        Attribute::from_parts(
            CKA_LABEL,
            match template.get_value(&(CKA_LABEL as CK_ATTRIBUTE_TYPE)) {
                Some(label) => label,
                None => token_label.into(),
                // Attribute::from_parts(CKA_LABEL, token_label),
                // Attribute::from_parts(CKA_LABEL, vec![0x6D, 0x73]),
            },
        ),
        Attribute::from_parts(CKA_VALUE, public_key),
        // Attribute::from_parts(CKA_ID, key_identifier),
        Attribute::from_parts(
            CKA_ID,
            match template.get_value(&(CKA_ID as CK_ATTRIBUTE_TYPE)) {
                Some(label) => label,
                None => key_identifier,
                // Attribute::from_parts(CKA_LABEL, token_label),
                // Attribute::from_parts(CKA_LABEL, vec![0x6D, 0x73]),
            },
        ),
    ]
}

fn get_communicator_public_key_template(
    token_label: &str,
    public_key: AttributeValue,
    pub_key_template: &Template,
) -> Template {
    let mut common_attributes =
        get_communicator_common_key_attributes(token_label, public_key.clone(), pub_key_template);
    // FIXME add a test
    let key = RsaPublicKey::from_pkcs1_der(&public_key).unwrap();
    let key_size = (key.size() * 8) as u32;

    //  Attribute: 266 (CKA_VERIFY)
    //  Attribute: 262 (CKA_WRAP)
    //  Attribute: 260 (CKA_ENCRYPT)
    //  Attribute: 3 (CKA_LABEL)
    //  Attribute: 290 (CKA_PUBLIC_EXPONENT)
    //  Attribute: 258 (CKA_ID)
    //  Attribute: 289 (CKA_MODULUS_BITS)
    //  Attribute: 1 (CKA_TOKEN)
    //  Attribute: 1073743360 (CKA_ALLOWED_MECHANISMS)
    //  Attribute: 256 (CKA_KEY_TYPE)
    //  Attribute: 0 (CKA_CLASS)
    //

    // CKA_VERIFY,
    // CKA_WRAP,
    // CKA_ENCRYPT,
    // CKA_LABEL,
    // CKA_PUBLIC_EXPONENT,
    // CKA_ID,
    // CKA_MODULUS_BITS,
    // CKA_TOKEN,
    // CKA_ALLOWED_MECHANISMS,
    // CKA_KEY_TYPE,
    // CKA_CLASS,
    let mut template = pub_key_template.clone();
    template.set_value(Attribute::from_parts(CKA_MODULUS, key.n().to_bytes_be()));
    // template.set_value(Attribute::from_parts(CKA_CLASS, CKO_PUBLIC_KEY));
    template
    // let mut attributes = pub_key_template.get_attributes().to_vec();
    // attributes.append(vec![
    //     Attribute::from_parts(CKA_MODULUS, key.n().to_bytes_be()),
    //     Attribute::from_parts(CKA_PUBLIC_EXPONENT, key.e().to_bytes_be()),
    // ]);
    // let mut attributes = vec![
    //     Attribute::from_parts(CKA_CLASS, CKO_PUBLIC_KEY),
    //     Attribute::from_parts(CKA_KEY_TYPE, CKK_RSA),
    //     Attribute::from_parts(CKA_TOKEN, CK_TRUE),
    //     Attribute::from_parts(CKA_WRAP, CK_FALSE),
    //     Attribute::from_parts(CKA_VERIFY, CK_TRUE),
    //     Attribute::from_parts(CKA_ENCRYPT, CK_FALSE),
    //     Attribute::from_parts(CKA_MODULUS, key.n().to_bytes_be()),
    //     Attribute::from_parts(CKA_MODULUS_BITS, key_size),
    //     Attribute::from_parts(CKA_PUBLIC_EXPONENT, key.e().to_bytes_be()),
    // ];
    // attributes.append(&mut common_attributes);

    // Template::from_vec(attributes)
}

fn get_communicator_private_key_template(
    token_label: &str,
    public_key: AttributeValue,
    priv_key_template: &Template,
) -> Template {
    let mut template = priv_key_template.clone();
    // template.set_value(Attribute::from_parts(CKA_CLASS, CKO_PRIVATE_KEY));
    template

    // let mut common_attributes =
    //     get_communicator_common_key_attributes(token_label, public_key, priv_key_template);
    // let mut attributes = vec![
    //     Attribute::from_parts(CKA_ALWAYS_AUTHENTICATE, CK_FALSE),
    //     Attribute::from_parts(CKA_CLASS, CKO_PRIVATE_KEY),
    //     Attribute::from_parts(CKA_TOKEN, CK_TRUE),
    //     Attribute::from_parts(CKA_PRIVATE, CK_TRUE),
    //     Attribute::from_parts(CKA_SENSITIVE, CK_TRUE),
    //     Attribute::from_parts(CKA_SIGN, CK_TRUE),
    //     Attribute::from_parts(CKA_UNWRAP, CK_FALSE),
    //     Attribute::from_parts(CKA_DECRYPT, CK_FALSE),
    //     // {CKA_SUBJECT, subject, sizeof(subject)},
    //     // {CKA_ID, id, sizeof(id)},
    //     // {CKA_SENSITIVE, &true, sizeof(true)},
    //     // {CKA_DECRYPT, &true, sizeof(true)},
    //     // {CKA_SIGN, &true, sizeof(true)},
    //     // {CKA_UNWRAP, &true, sizeof(true)}
    // ];
    // attributes.append(&mut common_attributes);

    // Template::from_vec(attributes)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_parsing_rsa_key() {}
}
