use std::{collections::HashMap, iter::Chain, sync::Arc, vec::IntoIter};

use aes::Aes128;
use openssl::hash::Hasher;
use uuid::Uuid;

use crate::{
    communicator::{AuthResponse, GroupId},
    cryptoki::bindings::{
        CKA_ALWAYS_AUTHENTICATE, CKA_CLASS, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ID, CKA_KEY_TYPE,
        CKA_LABEL, CKA_VALUE, CKK_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CK_FALSE,
        CK_OBJECT_HANDLE,
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
    handle_resolver: HandleResolver,

    // TODO: utilize token attribute
    #[allow(dead_code)]
    token: TokenStore,

    encryptor: Option<Aes128>,

    signer: Option<Signer>,

    key_pair: Option<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)>,

    cryptoki_repo: Arc<dyn CryptokiRepo>,
    ephemeral_objects: HashMap<Uuid, Arc<dyn CryptokiObject>>,
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

        session.key_pair = Some(session.create_communicator_keypair(pubkey, token_label));
        session
    }
    pub fn get_keypair(&self) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        self.key_pair.unwrap()
    }
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
    ) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
        let pubkey_template = get_communicator_public_key_template(&token_label, pubkey.clone());
        let pubkey_object = PublicKeyObject::from_template(pubkey_template);
        let pubkey_handle = self.create_ephemeral_object(Arc::new(pubkey_object));

        let private_key_template = get_communicator_private_key_template(&token_label, pubkey);
        let private_key = PrivateKeyObject::from_template(private_key_template);
        let private_key_handle = self.create_ephemeral_object(Arc::new(private_key));

        (private_key_handle, pubkey_handle)
    }
}

fn get_communicator_common_key_attributes(
    token_label: &str,
    public_key: Vec<u8>,
) -> Vec<Attribute> {
    let key_identifier: Vec<u8> = public_key
        .iter()
        .cloned()
        .take(KEYPAIR_IDENTIFIER_FROM_PUBLIC_PREFIX_LENGTH)
        .collect();
    vec![
        Attribute::from_parts(CKA_LABEL, token_label),
        Attribute::from_parts(CKA_VALUE, public_key),
        Attribute::from_parts(CKA_ID, key_identifier),
    ]
}

fn get_communicator_public_key_template(token_label: &str, public_key: AttributeValue) -> Template {
    let mut common_attributes =
        get_communicator_common_key_attributes(token_label, public_key.clone());
    let ec_params = hex::decode(NIST_P256_EC_PARAMS_DER_HEX).unwrap();
    let mut attributes = vec![
        Attribute::from_parts(CKA_KEY_TYPE, CKK_ECDSA),
        Attribute::from_parts(CKA_EC_PARAMS, ec_params),
        Attribute::from_parts(CKA_EC_POINT, as_der_octet_string(&public_key)),
        Attribute::from_parts(CKA_CLASS, CKO_PUBLIC_KEY),
    ];
    attributes.append(&mut common_attributes);

    Template::from_vec(attributes)
}

fn get_communicator_private_key_template(
    token_label: &str,
    public_key: AttributeValue,
) -> Template {
    let mut common_attributes = get_communicator_common_key_attributes(token_label, public_key);
    let mut attributes = vec![
        Attribute::from_parts(CKA_ALWAYS_AUTHENTICATE, CK_FALSE),
        Attribute::from_parts(CKA_CLASS, CKO_PRIVATE_KEY),
    ];
    attributes.append(&mut common_attributes);

    Template::from_vec(attributes)
}
