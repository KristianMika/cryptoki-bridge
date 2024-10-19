use std::sync::Arc;

use uuid::Uuid;

use crate::state::object::{cryptoki_object::CryptokiObject, object_search::ObjectSearch};

use super::persistence_error::PersistenceError;

/// Repository for storing and retrieving Cryptoki objects into and from a persistent storage
pub(crate) trait CryptokiRepo: Send + Sync {
    fn store_object(&self, object: Arc<CryptokiObject>) -> Result<Uuid, PersistenceError>;
    fn destroy_object(
        &self,
        object_id: Uuid,
    ) -> Result<Option<Arc<CryptokiObject>>, PersistenceError>;
    fn get_object(&self, object_id: Uuid) -> Result<Option<Arc<CryptokiObject>>, PersistenceError>;

    fn get_objects(
        &self,
        object_search: &ObjectSearch,
    ) -> Result<Vec<Arc<CryptokiObject>>, PersistenceError>;
}
