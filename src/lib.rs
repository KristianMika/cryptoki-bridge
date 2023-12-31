extern crate libc;

pub(crate) mod communicator;
mod configuration;
pub mod cryptoki;
mod cryptoki_error;
mod persistence;
pub(crate) mod state;
pub(crate) mod utils;
pub(crate) mod package_info {
    include!(concat!(env!("OUT_DIR"), "/package_info.rs"));
    pub const STANDARD_MAJOR_VERSION: u8 = 2;
    pub const STANDARD_MINOR_VERSION: u8 = 4;
}

use crate::{
    communicator::Communicator,
    configuration::ConfigurationProvider,
    state::{session::sessions::Sessions, slots::Slots},
};
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex, RwLock};
use tokio::runtime::Runtime;

lazy_static! {
    pub(crate) static ref SLOTS: RwLock<Option<Slots>> = RwLock::new(None);
    pub(crate) static ref CONFIGURATION: RwLock<Option<Arc<dyn ConfigurationProvider>>> =
        RwLock::new(None);
    pub(crate) static ref SESSIONS: RwLock<Option<Sessions>> = RwLock::new(None);
    pub(crate) static ref RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);
    pub(crate) static ref COMMUNICATOR: Mutex<Option<Box<dyn Communicator>>> = Mutex::new(None);
}
