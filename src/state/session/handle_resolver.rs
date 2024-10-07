use dashmap::DashMap;
use rand::{rngs::OsRng, Rng};
use uuid::Uuid;

use crate::cryptoki::bindings::CK_OBJECT_HANDLE;

/// Holds handles for objects accessed with the session and maps them to their UUIDs.
/// UUIDs are used to identify objects in the database, and persist across sessions.
#[derive(Default)]
pub(crate) struct HandleResolver {
    /// A map of UUID -> object handle
    object_handles: DashMap<Uuid, CK_OBJECT_HANDLE>,

    /// A map of object handle -> UUID
    object_ids: DashMap<CK_OBJECT_HANDLE, Uuid>,
}

impl HandleResolver {
    fn generate_object_handle(&self) -> CK_OBJECT_HANDLE {
        let mut object_handle = OsRng.gen_range(0..CK_OBJECT_HANDLE::MAX);
        while self.object_ids.contains_key(&object_handle) {
            object_handle = OsRng.gen_range(0..CK_OBJECT_HANDLE::MAX);
        }

        object_handle
    }

    pub(crate) fn get_or_insert_object_handle(&self, object_id: Uuid) -> CK_OBJECT_HANDLE {
        let handle = self.object_handles.entry(object_id).or_insert_with(|| {
            let handle = self.generate_object_handle();
            self.object_ids.insert(handle, object_id);
            handle
        });
        *handle.value()
    }

    pub(crate) fn destroy_object_mapping(&self, handle: CK_OBJECT_HANDLE) -> Option<Uuid> {
        let uuid = self.object_ids.remove(&handle).map(|(_, uuid)| uuid)?;
        self.object_handles.remove(&uuid);
        Some(uuid)
    }

    pub(crate) fn get_object_id(&self, handle: CK_OBJECT_HANDLE) -> Option<Uuid> {
        self.object_ids.get(&handle).map(|x| *x.value())
    }
}
