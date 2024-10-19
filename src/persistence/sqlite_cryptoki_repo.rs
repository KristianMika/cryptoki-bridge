use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rusqlite::{named_params, Connection, OpenFlags};
use uuid::Uuid;

use crate::{
    cryptoki::bindings::{CKA_LABEL, CK_ATTRIBUTE_TYPE},
    state::object::{AttributeValue, CryptokiObject, ObjectClass, ObjectSearch},
};

use super::{
    cryptoki_repo::CryptokiRepo,
    models::{try_object_model_from_cryptoki_object, ObjectModel},
    persistence_error::PersistenceError,
};

/// SQLite implementation of the Cryptoki repository trait
pub(crate) struct SqliteCryptokiRepo {
    /// A single connection to the SQLite database
    connection: Arc<Mutex<Connection>>,
}

impl SqliteCryptokiRepo {
    pub fn new(cryptoki_directory: PathBuf) -> Result<Self, PersistenceError> {
        static CRYPTOKI_BRIDGE_DB_FILE: &str = "cryptoki-bridge.db";
        let cryptoki_sqlite_db = cryptoki_directory.join(CRYPTOKI_BRIDGE_DB_FILE);
        let cryptoki_sqlite_db = cryptoki_sqlite_db.to_str().unwrap();
        let flags = OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE;
        let connection = Connection::open_with_flags(cryptoki_sqlite_db, flags)?;
        let connection = Arc::new(Mutex::new(connection));
        Ok(Self { connection })
    }

    /// Initializes the database schema
    pub(crate) fn create_tables(&self) -> Result<(), PersistenceError> {
        let connection = self.connection.lock()?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS objects (
                `id` BLOB PRIMARY KEY,
                `class` INTEGER NOT NULL CHECK (class IN (1, 2, 3, 4)),
                `label` BLOB,
                `serialized_attributes` BLOB NOT NULL
            );",
            (),
        )?;
        Ok(())
    }

    /// Fetches objects from the DB that match the supplied label or class.
    /// If any of the values is not supplied, the filter is ignored.
    fn filter_objects_in_db(
        &self,
        label: Option<AttributeValue>,
        class: Option<ObjectClass>,
    ) -> Result<Vec<Arc<CryptokiObject>>, PersistenceError> {
        let connection = &self.connection.lock()?;
        let mut statement = connection
            .prepare("SELECT id, class, label, serialized_attributes FROM objects WHERE (:label IS NULL OR label = :label) AND (:class IS NULL or class = :class)")?;
        let rows = statement.query_map(
            named_params! {":label":label, ":class":class.map(|x| x as i32)},
            |row| -> Result<Arc<CryptokiObject>, rusqlite::Error> {
                let object_model = ObjectModel::from_row(row)?;
                Ok(object_model.into())
            },
        )?;
        rows.into_iter()
            .map(|x| x.map_err(PersistenceError::from))
            .collect()
    }
}

impl CryptokiRepo for SqliteCryptokiRepo {
    fn store_object(&self, object: Arc<CryptokiObject>) -> Result<Uuid, PersistenceError> {
        let connection = &self.connection.lock()?;
        let mut statement = connection.prepare(
            "INSERT INTO objects (id, class, label, serialized_attributes) VALUES (?1, ?2, ?3, ?4)",
        )?;
        let object_model = try_object_model_from_cryptoki_object(object)?;

        statement.execute((
            object_model.id.as_bytes(),
            object_model.class as i32,
            object_model.label,
            object_model.serialized_attributes,
        ))?;
        Ok(object_model.id)
    }

    fn destroy_object(
        &self,
        object_id: Uuid,
    ) -> Result<Option<Arc<CryptokiObject>>, PersistenceError> {
        let connection = self.connection.lock()?;
        let mut statement = connection.prepare(
            "DELETE FROM objects WHERE id = ?1 RETURNING id, class, label, serialized_attributes;",
        )?;

        let object_model = statement.query_row((object_id.as_bytes(),), ObjectModel::from_row)?;

        Ok(Some(object_model.into()))
    }

    fn get_object(&self, object_id: Uuid) -> Result<Option<Arc<CryptokiObject>>, PersistenceError> {
        let connection = self.connection.lock()?;
        let mut statement = connection.prepare("SELECT * FROM objects WHERE id = ?1;")?;

        let object_model = statement.query_row((object_id.as_bytes(),), ObjectModel::from_row)?;

        Ok(Some(object_model.into()))
    }

    /// Fetches objects conforming to the given search template.
    /// First, it filters objects in the database by label and class. Then,
    /// it filters objects in memory using deserialized attributes
    ///
    /// # Arguments
    ///
    /// * `object_search` - The search template to be used for filtering objects
    fn get_objects(
        &self,
        object_search: &ObjectSearch,
    ) -> Result<Vec<Arc<CryptokiObject>>, PersistenceError> {
        let filter_label = object_search
            .get_template()
            .get_attributes()
            .get(&(CKA_LABEL as CK_ATTRIBUTE_TYPE))
            .and_then(|x| x.clone());
        let filter_class = object_search.get_template().get_class();
        let objects = self.filter_objects_in_db(filter_label, filter_class)?;
        Ok(objects
            .into_iter()
            .filter(|object| object.does_template_match(object_search.get_template()))
            .collect())
    }
}
