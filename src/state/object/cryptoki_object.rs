use std::{collections::HashMap, sync::Arc};

use crate::cryptoki::bindings::{CKA_VALUE, CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE};
use uuid::Uuid;

use crate::persistence::models::ObjectModel;

use super::template::Template;

pub(crate) type ByteVector = Vec<u8>;
pub(crate) type AttributeValue = ByteVector;
pub(crate) type Attributes = HashMap<CK_ATTRIBUTE_TYPE, Option<AttributeValue>>;
pub(crate) struct CryptokiObject {
    id: Uuid,
    attributes: Attributes,
}
impl CryptokiObject {
    fn from_parts(id: Uuid, attributes: Attributes) -> Self {
        Self { id, attributes }
    }

    #[allow(dead_code)]
    fn set_attribute(
        &mut self,
        attribute_type: CK_ATTRIBUTE_TYPE,
        value: AttributeValue,
    ) -> Option<AttributeValue> {
        self.attributes
            .insert(attribute_type, Some(value))
            .and_then(|x| x)
    }

    pub fn store_value(&mut self, value: AttributeValue) -> Option<AttributeValue> {
        self.attributes
            .insert(CKA_VALUE as CK_ATTRIBUTE_TYPE, Some(value))
            .and_then(|x| x)
    }

    pub fn get_value(&self) -> Option<AttributeValue> {
        self.get_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE)
    }

    pub fn does_template_match(&self, template: &Template) -> bool {
        self.attributes.do_attributes_match(template)
    }

    pub fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        let attributes = template.into_attributes();

        Self {
            id: Uuid::new_v4(),
            attributes,
        }
    }

    pub fn get_id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub fn get_attributes(&self) -> &Attributes {
        &self.attributes
    }
    pub fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        self.attributes.get(&attribute_type).and_then(|x| x.clone())
    }
}

impl From<Vec<CK_ATTRIBUTE>> for CryptokiObject {
    fn from(value: Vec<CK_ATTRIBUTE>) -> Self {
        let template = Template::from_vec(value.into_iter().map(|t| t.into()).collect());
        Self::from_template(template)
    }
}

impl From<Template> for CryptokiObject {
    fn from(value: Template) -> Self {
        Self::from_template(value)
    }
}

#[derive(Clone)]
pub(crate) struct CryptokiArc {
    pub value: Arc<CryptokiObject>,
}

impl From<Template> for Option<CryptokiArc> {
    fn from(template: Template) -> Self {
        let cryptoki_object = CryptokiObject::from_template(template);
        Some(CryptokiArc {
            value: Arc::new(cryptoki_object),
        })
    }
}

impl From<ObjectModel> for Arc<CryptokiObject> {
    fn from(value: ObjectModel) -> Self {
        let attributes: Attributes = bincode::deserialize(&value.serialized_attributes).unwrap();
        Arc::new(CryptokiObject::from_parts(value.id, attributes))
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
