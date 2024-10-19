use std::sync::Arc;

use derive_new::new;
use rusqlite::Row;
use uuid::Uuid;

use crate::cryptoki::bindings::{
    CKA_CLASS, CKA_LABEL, CKO_DATA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
    CK_ATTRIBUTE_TYPE,
};
use crate::state::object::{CryptokiObject, ObjectClass};
use crate::utils;

use super::persistence_error::PersistenceError;

/// Represents a Cryptoki object of any class
#[derive(new)]
pub(crate) struct ObjectModel {
    /// A unique UUID which is used to assign handles
    pub id: Uuid,

    /// value CKA_CLASS, identifying the type of object
    pub class: ObjectClass,

    /// value CKA_LABEL, identifying the object
    pub label: Option<Vec<u8>>,

    /// Other attributes of the object in the form of a serialized vector.
    /// PKCS#11 permits an unlimited number of vendor-defined attributes.
    /// It might not be the most-efficient option to store attributes
    /// as individual collumns, that's why we are storing independently
    /// only the attributes most-commonly used for filtering, i.e., class, and label.
    /// Other attributes are filtered when deserialized.
    /// There is also a JSON extension for SQLite that can be used
    /// for storing json strings and performing queries
    /// using individual attributes
    pub serialized_attributes: Vec<u8>,
}

impl ObjectModel {
    /// Creates an instance of ObjectModel from an SQLite row
    pub(crate) fn from_row(row: &Row<'_>) -> Result<Self, rusqlite::Error> {
        let uuid: [u8; 16] = row.get(0)?;
        Ok(ObjectModel {
            id: Uuid::from_bytes(uuid),
            class: try_object_class_from_i32(row.get(1)?).unwrap(),
            label: row.get(2)?,
            serialized_attributes: row.get(3)?,
        })
    }
}

// While the following functions are really ugly, we can't
// implement `From<T>` for `Option<ObjectModel>` or `Result<ObjectModel, E>`
// because of the orphan rule.

pub(crate) fn try_object_model_from_cryptoki_object(
    value: Arc<CryptokiObject>,
) -> Result<ObjectModel, PersistenceError> {
    let class = try_object_class_from_cryptoki_object(&value)?;
    let label = value.get_attribute(CKA_LABEL as CK_ATTRIBUTE_TYPE);
    let id = *value.get_id();
    let attributes = bincode::serialize(&value.get_attributes().clone()).unwrap();
    Ok(ObjectModel::new(id, class, label, attributes))
}

pub(crate) fn try_object_class_from_cryptoki_object(
    value: &Arc<CryptokiObject>,
) -> Result<ObjectClass, PersistenceError> {
    let class = CK_ATTRIBUTE_TYPE::from_le_bytes(utils::to_fixed_size_array(
        value.get_attribute(CKA_CLASS as CK_ATTRIBUTE_TYPE).ok_or(
            PersistenceError::DataInconsistency(format!(
                "Object {id} does not have a class attribute",
                id = value.get_id()
            )),
        )?,
    ));
    let object = match class as u32 {
        CKO_PRIVATE_KEY => ObjectClass::PrivateKey,
        CKO_PUBLIC_KEY => ObjectClass::PublicKey,
        CKO_SECRET_KEY => ObjectClass::SecretKey,
        CKO_DATA => ObjectClass::Data,
        _ => {
            return Err(PersistenceError::DataInconsistency(format!(
                "Invalid object class {class}"
            )))
        }
    };
    Ok(object)
}

pub(crate) fn try_object_class_from_i32(value: i32) -> Option<ObjectClass> {
    match value {
        1 => Some(ObjectClass::Data),
        2 => Some(ObjectClass::SecretKey),
        3 => Some(ObjectClass::PrivateKey),
        4 => Some(ObjectClass::PublicKey),
        _ => None,
    }
}
