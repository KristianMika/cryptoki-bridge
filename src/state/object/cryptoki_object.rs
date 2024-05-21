use std::{collections::HashMap, sync::Arc};

use uuid::Uuid;

use super::{
    data_object::DataObject, private_key_object::PrivateKeyObject,
    public_key_object::PublicKeyObject, secret_key_object::SecretKeyObject, template::Template,
};
use crate::{
    cryptoki::bindings::{CKA_CLASS, CK_ATTRIBUTE_TYPE},
    persistence::models::ObjectModel,
    state::object::object_class::ObjectClass,
};

pub(crate) type ByteVector = Vec<u8>;
pub(crate) type AttributeValue = ByteVector;
pub(crate) type Attributes = HashMap<CK_ATTRIBUTE_TYPE, Option<AttributeValue>>;
pub(crate) trait CryptokiObject: Sync + Send {
    fn from_parts(id: Uuid, attributes: Attributes) -> Self
    where
        Self: Sized;
    fn does_template_match(&self, template: &Template) -> bool;
    // TODO: implement only for data-like objects
    fn store_value(&mut self, data: AttributeValue) -> Option<AttributeValue>;
    fn get_value(&self) -> Option<AttributeValue>;

    fn from_template(template: Template) -> Self
    where
        Self: Sized;

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<AttributeValue>;
    #[allow(dead_code)]
    fn set_attribute(
        &mut self,
        attribute_type: CK_ATTRIBUTE_TYPE,
        value: AttributeValue,
    ) -> Option<AttributeValue>;

    fn get_id(&self) -> &Uuid;

    fn get_attributes(&self) -> &Attributes;
}

#[derive(Clone)]
pub(crate) struct CryptokiArc {
    pub value: Arc<dyn CryptokiObject>,
}

impl From<Template> for Option<CryptokiArc> {
    fn from(template: Template) -> Self {
        // TODO: refactor!!!!!
        let class = template.get_class()?;
        match class {
            ObjectClass::Data => Some(CryptokiArc {
                value: Arc::new(DataObject::from_template(template)),
            }),
            ObjectClass::SecretKey => Some(CryptokiArc {
                value: (Arc::new(SecretKeyObject::from_template(template))),
            }),
            ObjectClass::PublicKey => Some(CryptokiArc {
                value: Arc::new(PublicKeyObject::from_template(template)),
            }),
            ObjectClass::PrivateKey => Some(CryptokiArc {
                value: Arc::new(PrivateKeyObject::from_template(template)),
            }),
        }
    }
}

impl From<ObjectModel> for Arc<dyn CryptokiObject> {
    fn from(value: ObjectModel) -> Self {
        let attributes: Attributes = bincode::deserialize(&value.serialized_attributes).unwrap();
        let object: Arc<dyn CryptokiObject> = match value.class {
            ObjectClass::Data => Arc::new(DataObject::from_parts(value.id, attributes)),
            ObjectClass::SecretKey => Arc::new(SecretKeyObject::from_parts(value.id, attributes)),
            ObjectClass::PrivateKey => Arc::new(PrivateKeyObject::from_parts(value.id, attributes)),
            ObjectClass::PublicKey => Arc::new(PublicKeyObject::from_parts(value.id, attributes)),
        };
        object
    }
}

pub(crate) trait AttributeMatcher {
    fn do_attributes_match(&self, template: &Template) -> bool;
}

impl AttributeMatcher for Attributes {
    fn do_attributes_match(&self, template: &Template) -> bool {
        let template_attributes = template.get_attributes();
        for (filter_type, filter_value) in template_attributes {
            let Some(my_value) = self.get(filter_type) else {
                return false;
            };
            if my_value != filter_value {
                return false;
            }
        }
        true
    }
}

pub(crate) trait AttributeValidator {
    fn validate_template_class(&self, class_value: &AttributeValue) -> bool;
}

impl AttributeValidator for Attributes {
    fn validate_template_class(&self, class_value: &AttributeValue) -> bool {
        let my_class = self
            .get(&(CKA_CLASS as CK_ATTRIBUTE_TYPE))
            .and_then(|x| x.as_ref());
        my_class == Some(class_value)
    }
}
