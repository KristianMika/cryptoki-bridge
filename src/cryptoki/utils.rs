use std::ptr;

/// Allows easier vector initialization from a pointer.
///
/// # Safety
///
/// The pointer must be valid and point to an array of T with the given count.
pub unsafe trait FromPointer<T> {
    /// Creates a vector from a pointer to an array of T, copying memory from the pointer.
    unsafe fn from_pointer(pointer: *mut T, count: usize) -> Self;
}

unsafe impl<T> FromPointer<T> for Vec<T> {
    unsafe fn from_pointer(pointer: *mut T, count: usize) -> Self {
        if pointer.is_null() {
            return Vec::new();
        }
        let mut vector = Vec::with_capacity(count);
        unsafe {
            ptr::copy(pointer, vector.as_mut_ptr(), count);
            vector.set_len(count);
        }
        vector
    }
}

#[cfg(test)]
mod test {
    use crate::cryptoki::bindings::{
        CKA_CLASS, CKA_LABEL, CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_ULONG, CK_VOID_PTR, NULL_PTR,
    };

    use super::FromPointer;

    #[test]
    fn given_valid_pointer_to_array_from_pointer_returns_vector() {
        let attribute_value = [1, 2, 3];
        let attribute_1 = CK_ATTRIBUTE {
            type_: CKA_LABEL as CK_ATTRIBUTE_TYPE,
            pValue: attribute_value.as_ptr() as CK_VOID_PTR,
            ulValueLen: attribute_value.len() as CK_ULONG,
        };

        let attribute_2 = CK_ATTRIBUTE {
            type_: CKA_CLASS as CK_ATTRIBUTE_TYPE,
            pValue: NULL_PTR as CK_VOID_PTR,
            ulValueLen: 0,
        };
        let array = [attribute_1, attribute_2];
        let array_pointer = array.as_ptr() as *mut CK_ATTRIBUTE;
        let attribute_vector = unsafe { Vec::from_pointer(array_pointer, array.len()) };
        let expected_vector = array.to_vec();
        assert_eq!(expected_vector.len(), attribute_vector.len());
        expected_vector
            .iter()
            .zip(attribute_vector)
            .for_each(|(expected, actual)| {
                assert_eq!(expected.type_, actual.type_);
                assert_eq!(expected.pValue, actual.pValue);
                assert_eq!(expected.ulValueLen, actual.ulValueLen)
            });
    }

    #[test]
    fn given_nullptr_from_pointer_returns_empty_vector() {
        let vector = unsafe { Vec::from_pointer(NULL_PTR as *mut CK_ATTRIBUTE, 0) };
        assert!(vector.is_empty())
    }
}
