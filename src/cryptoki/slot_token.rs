use std::{
    ptr,
    sync::{Arc, RwLock},
};

use crate::{
    communicator::group::Group,
    cryptoki_error::CryptokiError,
    state::{token::MeesignToken, StateAccessor},
};

use super::bindings::{
    CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_OK, CK_BBOOL, CK_RV, CK_SLOT_ID, CK_SLOT_ID_PTR,
    CK_SLOT_INFO_PTR, CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR,
};

/// Used to obtain a list of slots in the system
///
/// # Arguments
///
/// * `tokenPresent` - indicates whether the list obtained includes only those slots with a token present, or all slots
/// * `pSlotList` - points to the buffer for the slot list
/// * `pulCount` -  points to the location that receives the number of slots
#[cryptoki_macros::cryptoki_function]
pub fn C_GetSlotList(
    _tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let groups = match state_accessor.get_groups_blocking() {
        Ok(groups) => groups,
        Err(err) => return err.into_ck_rv(),
    };

    let slot_length = groups.len();

    if pSlotList.is_null() {
        unsafe {
            *pulCount = slot_length as CK_ULONG;
        }
        return CKR_OK as CK_RV;
    }
    if unsafe { *pulCount } < slot_length as CK_ULONG {
        return CKR_BUFFER_TOO_SMALL as CK_RV;
    }

    let slot_list: Result<Vec<CK_SLOT_ID>, CryptokiError> = groups
        .into_iter()
        .map(|group: Group| group.into())
        .map(|token: MeesignToken| Arc::new(RwLock::new(token)))
        .map(|token| state_accessor.insert_token(token))
        .collect();
    let slot_list = match slot_list {
        Ok(slot_list) => slot_list,
        Err(err) => return err.into_ck_rv(),
    };
    unsafe {
        ptr::copy(slot_list.as_ptr(), pSlotList, slot_length);
    }
    CKR_OK as CK_RV
}

/// Obtains information about a particular token in the system
///
/// # Arguments
///
/// * `slotID` - the ID of the token’s slot
/// * `pInfo` - points to the location that receives the token information
#[cryptoki_macros::cryptoki_function]
pub fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }

    let state_accessor = StateAccessor::new();
    let token_info = match state_accessor.get_token_info(&slotID) {
        Ok(info) => info,
        Err(err) => return err.into_ck_rv(),
    };
    unsafe { *pInfo = token_info };

    CKR_OK as CK_RV
}

#[cryptoki_macros::cryptoki_function]
pub fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD as CK_RV;
    }
    let state_accessor = StateAccessor::new();
    let slot_info = match state_accessor.get_slot_info(&slotID) {
        Ok(info) => info,
        Err(err) => return err.into_ck_rv(),
    };

    unsafe {
        *pInfo = slot_info;
    }

    CKR_OK as CK_RV
}
