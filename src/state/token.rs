use std::iter::repeat;

use crate::{
    communicator::{group::Group, GroupId},
    cryptoki::bindings::{
        CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT, CK_CHAR, CK_FLAGS, CK_SLOT_INFO, CK_TOKEN_INFO,
        CK_VERSION,
    },
};

static LABEL_PREFIX: &str = "Meesign: ";
const LABEL_BUFFER_LENGTH: usize = 32;
const DESCRIPTION_BUFFER_LENGTH: usize = 64;

pub(crate) trait Token: Sync + Send {
    fn get_token_info(&self) -> CK_TOKEN_INFO;

    fn get_public_key(&self) -> &[u8];

    fn get_label(&self) -> &str;

    fn get_slot_info(&self) -> CK_SLOT_INFO;
}

#[derive(Default)]
pub(crate) struct MeesignToken {
    group_id: GroupId,
    name: String,
}

impl Token for MeesignToken {
    fn get_token_info(&self) -> CK_TOKEN_INFO {
        // TODO: fill in
        CK_TOKEN_INFO {
            label: self.create_token_label(),
            manufacturerID: Default::default(),
            model: Default::default(),
            serialNumber: Default::default(),
            flags: self.get_flags(),
            ulMaxSessionCount: 2,
            ulSessionCount: 1, // TODO
            ulMaxRwSessionCount: 2,
            ulRwSessionCount: 1, // TODO
            ulMaxPinLen: 16,
            ulMinPinLen: 4,
            ulTotalPublicMemory: 1 << 20,
            ulFreePublicMemory: 1 << 20,
            ulTotalPrivateMemory: 1 << 20,
            ulFreePrivateMemory: 1 << 20,
            hardwareVersion: CK_VERSION { major: 0, minor: 0 },
            firmwareVersion: CK_VERSION { major: 0, minor: 0 },
            utcTime: Self::get_utc_time(),
        }
    }

    fn get_slot_info(&self) -> CK_SLOT_INFO {
        let version = CK_VERSION { major: 0, minor: 0 };
        CK_SLOT_INFO {
            slotDescription: self.create_slot_description(),
            manufacturerID: Default::default(),
            flags: CKF_TOKEN_PRESENT as CK_FLAGS,
            hardwareVersion: version,
            firmwareVersion: version,
        }
    }

    fn get_public_key(&self) -> &[u8] {
        &self.group_id
    }

    fn get_label(&self) -> &str {
        &self.name
    }
}

impl MeesignToken {
    fn create_token_label(&self) -> [u8; LABEL_BUFFER_LENGTH] {
        let token_label = self.create_token_name(LABEL_BUFFER_LENGTH);
        match token_label.try_into() {
            Ok(val) => val,
            Err(_) => unreachable!(),
        }
    }

    fn create_slot_description(&self) -> [u8; DESCRIPTION_BUFFER_LENGTH] {
        let token_description = self.create_token_name(DESCRIPTION_BUFFER_LENGTH);
        match token_description.try_into() {
            Ok(val) => val,
            Err(_) => unreachable!(),
        }
    }

    fn create_token_name(&self, length: usize) -> Vec<u8> {
        let label: Vec<u8> = (String::from(LABEL_PREFIX) + &self.name)
            .chars()
            .map(|character: char| character as u8)
            .chain(repeat(b' '))
            .take(length)
            .collect();

        label
    }

    // TODO
    fn get_utc_time() -> [CK_CHAR; 16usize] {
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn get_flags(&self) -> CK_FLAGS {
        (CKF_TOKEN_PRESENT | CKF_TOKEN_INITIALIZED) as CK_FLAGS
    }
}

impl From<Group> for MeesignToken {
    fn from(value: Group) -> Self {
        Self {
            name: value.get_name().into(),
            group_id: value.get_group_id().to_owned(),
        }
    }
}
