use std::collections::HashMap;

use crate::cryptoki::bindings::{CKA_CLASS, CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE};

use super::{cryptoki_object::Attributes, Attribute, ObjectClass};

pub(crate) struct Template {
    attributes: HashMap<CK_ATTRIBUTE_TYPE, Option<Vec<u8>>>,
}

impl Template {
    pub(crate) fn from_vec(attributes: Vec<Attribute>) -> Self {
        let mut attributes_map = HashMap::new();
        attributes.into_iter().for_each(|attribute| {
            attributes_map.insert(
                attribute.get_attribute_type(),
                attribute.get_attribute_value().cloned(),
            );
        });
        Self {
            attributes: attributes_map,
        }
    }

    pub(crate) fn get_value(&self, key: &CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        self.attributes.get(key).cloned().unwrap_or(None)
    }

    pub(crate) fn get_class(&self) -> Option<ObjectClass> {
        let value = self.get_value(&(CKA_CLASS as CK_ATTRIBUTE_TYPE))?;
        ObjectClass::from_vec(&value)
    }

    pub(crate) fn into_attributes(self) -> Attributes {
        self.attributes
    }

    pub(crate) fn get_attributes(&self) -> &Attributes {
        &self.attributes
    }
}

impl From<Vec<CK_ATTRIBUTE>> for Template {
    fn from(value: Vec<CK_ATTRIBUTE>) -> Self {
        Self::from_vec(value.into_iter().map(|t| t.into()).collect())
    }
}
