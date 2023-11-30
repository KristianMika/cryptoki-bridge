use std::{cmp::min, ptr};

use crate::state::{
    object::{
        attribute::Attribute, cryptoki_object::CryptokiArc, object_search::ObjectSearch,
        template::Template,
    },
    StateAccessor,
};

use super::{
    bindings::{
        CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_OK, CKR_TEMPLATE_INCOMPLETE,
        CK_ATTRIBUTE_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_RV, CK_SESSION_HANDLE,
        CK_ULONG, CK_ULONG_PTR,
    },
    utils::FromPointer,
};

/// Creates an object
///
/// # Arguments
///
/// * `hSession` - session's handle
/// * `pTemplate` - points to the object’s template
/// * `ulCount` - the number of attributes in the template
/// * `phObject` - points to the location that receives the new object’s handle
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    if pTemplate.is_null() || phObject.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let template = unsafe { Vec::from_pointer(pTemplate, ulCount as usize) };
    let template = Template::from(template);
    let Some(object): Option<CryptokiArc> = template.into() else {
        return CKR_TEMPLATE_INCOMPLETE as CK_RV;
    };
    let object = object.value;
    let object_handle = match state_accessor.create_object(&hSession, object) {
        Ok(handle) => handle,
        Err(err) => err.into_ck_rv(),
    };
    unsafe {
        *phObject = object_handle;
    }
    CKR_OK as CK_RV
}

/// Destroys an object
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `hObject` - the object’s handle
#[cryptoki_macros::cryptoki_function]
pub fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV {
    let state_accessor = StateAccessor::new();

    match state_accessor.destroy_object(&hSession, &hObject) {
        Ok(_) => CKR_OK as CK_RV,
        Err(err) => err.into_ck_rv(),
    }
}

/// Obtains the value of one or more attributes of an object
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `hObject` - the object’s handle
/// * `pTemplate` - points to a template that specifies which attribute values are to be obtained, and receives the attribute values
/// * `ulCount` - the number of attributes in the template
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let object = match state_accessor.get_object(&hSession, &hObject) {
        Ok(object) => object,
        Err(err) => return err.into_ck_rv(),
    };

    let template = unsafe { Vec::from_pointer(pTemplate, ulCount as usize) };
    let template: Vec<Attribute> = template
        .into_iter()
        .map(|attribute| attribute.into())
        .collect();

    for i in 0..(ulCount as isize) {
        // todo: implement behaviour by spec (5 options)
        let Some(attribute) = object.get_attribute(template[i as usize].get_attribute_type())
        else {
            return CKR_ATTRIBUTE_TYPE_INVALID as CK_RV;
        };

        if unsafe { (*pTemplate.offset(i)).pValue.is_null() } {
            unsafe { (*pTemplate.offset(i)).ulValueLen = attribute.len() as CK_ULONG }
            continue;
        }
        unsafe {
            ptr::copy(
                attribute.as_ptr(),
                (*pTemplate.offset(i)).pValue as *mut u8,
                attribute.len(),
            );
            (*pTemplate.offset(i)).ulValueLen = attribute.len() as CK_ULONG
        };
    }

    CKR_OK as CK_RV
}

/// Initializes a search for token and session objects that match a template.
/// The matching criterion is an exact byte-for-byte match with all attributes in the template.
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `pTemplate` - points to a search template that specifies the attribute values to match
/// * `ulCount` - the number of attributes in the search template. If 0, find all objects
///
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let template = unsafe { Vec::from_pointer(pTemplate, ulCount as usize) };

    let object_search = ObjectSearch::new(template.into());
    let state_accessor = StateAccessor::new();
    if let Err(err) = state_accessor.init_object_search(&hSession, object_search) {
        return err.into_ck_rv();
    }
    CKR_OK as CK_RV
}

/// Continues a search for token and session objects that match a template, obtaining additional object handles
///
/// # Arguments
///
/// * `hSession` - the session’s handle
/// * `phObject` - points to the location that receives the list (array) of additional object handles
/// * `ulMaxObjectCount` - the maximum number of object handles to be returned
/// * `pulObjectCount` - points to the location that receives the actual number of object handles returned
#[allow(clippy::missing_safety_doc)]
#[cryptoki_macros::cryptoki_function]
pub unsafe fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    if phObject.is_null() || pulObjectCount.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let filtered_handles =
        match state_accessor.get_filtered_handles(&hSession, ulMaxObjectCount as usize) {
            Ok(handles) => handles,
            Err(err) => return err.into_ck_rv(),
        };

    let copy_count = min(ulMaxObjectCount as usize, filtered_handles.len());
    unsafe {
        ptr::copy(filtered_handles.as_ptr(), phObject, copy_count);
        *pulObjectCount = copy_count as CK_ULONG;
    }
    CKR_OK as CK_RV
}

/// Terminates a search for token and session objects
///
/// # Arguments
///
/// * `hSession` - the session’s handle
#[cryptoki_macros::cryptoki_function]
pub fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    let state_accessor = StateAccessor::new();
    if let Err(err) = state_accessor.reset_object_search(&hSession) {
        return err.into_ck_rv();
    }
    CKR_OK as CK_RV
}
