use derive_new::new;

use crate::cryptoki::{
    bindings::{CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE},
    utils::FromPointer,
};
use crate::state::object::cryptoki_object::AttributeValue;

#[derive(new)]
pub(crate) struct Attribute {
    attribute_type: CK_ATTRIBUTE_TYPE,
    value: Option<Vec<u8>>,
}

impl Attribute {
    pub(crate) fn get_attribute_type(&self) -> CK_ATTRIBUTE_TYPE {
        self.attribute_type
    }

    pub(crate) fn get_attribute_value(&self) -> Option<&Vec<u8>> {
        self.value.as_ref()
    }
}

impl From<CK_ATTRIBUTE> for Attribute {
    fn from(template: CK_ATTRIBUTE) -> Self {
        let mut template_value = None;
        if template.ulValueLen > 0 {
            let value = unsafe {
                Vec::from_pointer(template.pValue as *mut u8, template.ulValueLen as usize)
            };
            template_value = Some(value);
        }
        Attribute::new(template.type_, template_value)
    }
}

impl Attribute {
    pub fn from_parts(attribute_type: u32, attribute_value: impl ToAttributeValue) -> Self {
        let attribute_type = attribute_type as CK_ATTRIBUTE_TYPE;
        let value = Some(attribute_value.to_attribute_value());
        Self {
            attribute_type,
            value,
        }
    }
}

pub trait ToAttributeValue {
    fn to_attribute_value(self) -> AttributeValue;
}

impl ToAttributeValue for AttributeValue {
    fn to_attribute_value(self) -> AttributeValue {
        self
    }
}

impl ToAttributeValue for u32 {
    fn to_attribute_value(self) -> AttributeValue {
        (self as CK_ATTRIBUTE_TYPE).to_le_bytes().to_vec()
    }
}

impl ToAttributeValue for &str {
    fn to_attribute_value(self) -> AttributeValue {
        self.as_bytes().to_vec()
    }
}
