use uuid::Uuid;

use crate::cryptoki::bindings::{
    CKA_CLASS, CKA_VALUE, CKO_SECRET_KEY, CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE,
};

use super::{
    cryptoki_object::{
        AttributeMatcher, AttributeValidator, AttributeValue, Attributes, CryptokiObject,
    },
    template::Template,
};

#[derive(Clone)]
pub(crate) struct SecretKeyObject {
    id: Uuid,
    attributes: Attributes,
}

impl SecretKeyObject {
    pub(crate) fn new() -> Self {
        let mut object = Self {
            id: Uuid::new_v4(),
            attributes: Attributes::new(),
        };
        object.set_attribute(
            CKA_CLASS as CK_ATTRIBUTE_TYPE,
            (CKO_SECRET_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec(),
        );
        object
    }
}
impl CryptokiObject for SecretKeyObject {
    fn from_parts(id: Uuid, attributes: Attributes) -> Self
    where
        Self: Sized,
    {
        assert!(attributes.validate_template_class(
            &(CKO_SECRET_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
        ));
        Self { id, attributes }
    }
    fn store_value(&mut self, value: AttributeValue) -> Option<AttributeValue> {
        self.attributes
            .insert(CKA_VALUE as CK_ATTRIBUTE_TYPE, Some(value))
            .and_then(|x| x)
    }

    fn get_value(&self) -> Option<AttributeValue> {
        self.get_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE)
    }
    fn set_attribute(
        &mut self,
        attribute_type: CK_ATTRIBUTE_TYPE,
        value: AttributeValue,
    ) -> Option<AttributeValue> {
        self.attributes
            .insert(attribute_type, Some(value))
            .and_then(|x| x)
    }
    fn does_template_match(&self, template: &Template) -> bool {
        self.attributes.do_attributes_match(template)
    }

    fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        let attributes = template.into_attributes();
        assert!(attributes.validate_template_class(
            &(CKO_SECRET_KEY as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
        ));

        Self {
            id: Uuid::new_v4(),
            attributes,
        }
    }

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        self.attributes.get(&attribute_type).and_then(|x| x.clone())
    }

    fn get_id(&self) -> &uuid::Uuid {
        &self.id
    }

    fn into_attributes(self) -> Attributes {
        self.attributes
    }

    fn get_attributes(&self) -> &Attributes {
        &self.attributes
    }
}

impl From<Vec<CK_ATTRIBUTE>> for SecretKeyObject {
    fn from(value: Vec<CK_ATTRIBUTE>) -> Self {
        let template = Template::from_vec(value.into_iter().map(|t| t.into()).collect());
        Self::from_template(template)
    }
}

impl From<Template> for SecretKeyObject {
    fn from(value: Template) -> Self {
        Self::from_template(value)
    }
}
