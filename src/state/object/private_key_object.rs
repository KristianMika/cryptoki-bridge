use uuid::Uuid;

use crate::{
    cryptoki::bindings::{CKA_VALUE, CKO_PRIVATE_KEY, CK_ATTRIBUTE_TYPE},
    state::object::cryptoki_object::AttributeValidator,
};

use super::{
    cryptoki_object::{AttributeMatcher, AttributeValue, Attributes, ByteVector, CryptokiObject},
    template::Template,
};

#[derive(Clone)]
pub(crate) struct PrivateKeyObject {
    id: Uuid,
    attributes: Attributes,
}

impl CryptokiObject for PrivateKeyObject {
    fn from_parts(id: Uuid, attributes: Attributes) -> Self
    where
        Self: Sized,
    {
        assert!(attributes.validate_template_class(
            &(CKO_PRIVATE_KEY as CK_ATTRIBUTE_TYPE)
                .to_le_bytes()
                .to_vec()
        ));

        Self { id, attributes }
    }
    fn set_attribute(
        &mut self,
        attribute_type: CK_ATTRIBUTE_TYPE,
        value: Vec<u8>,
    ) -> Option<ByteVector> {
        self.attributes
            .insert(attribute_type, Some(value))
            .and_then(|x| x)
    }
    fn does_template_match(&self, template: &Template) -> bool {
        self.attributes.do_attributes_match(template)
    }
    fn store_value(&mut self, value: AttributeValue) -> Option<AttributeValue> {
        self.attributes
            .insert(CKA_VALUE as CK_ATTRIBUTE_TYPE, Some(value))
            .and_then(|x| x)
    }

    fn get_value(&self) -> Option<AttributeValue> {
        self.get_attribute(CKA_VALUE as CK_ATTRIBUTE_TYPE)
    }
    fn from_template(template: Template) -> Self
    where
        Self: Sized,
    {
        let attributes = template.into_attributes();
        assert!(attributes.validate_template_class(
            &(CKO_PRIVATE_KEY as CK_ATTRIBUTE_TYPE)
                .to_le_bytes()
                .to_vec()
        ));
        Self {
            id: Uuid::new_v4(),
            attributes,
        }
    }

    fn get_attribute(&self, attribute_type: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        self.attributes.get(&attribute_type).and_then(|x| x.clone())
    }

    fn get_id(&self) -> &Uuid {
        &self.id
    }
    fn into_attributes(self) -> Attributes {
        self.attributes
    }
    fn get_attributes(&self) -> &Attributes {
        &self.attributes
    }
}
