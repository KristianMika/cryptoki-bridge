extern crate libc;

use std::sync::{Arc, Mutex, RwLock};

use lazy_static::lazy_static;
use tokio::runtime::Runtime;

use crate::{
    communicator::Communicator,
    configuration::ConfigurationProvider,
    state::{session::Sessions, slots::Slots},
};

pub(crate) use cryptoki_error::CryptokiError;

mod communicator;
mod configuration;
pub mod cryptoki;
mod cryptoki_error;
mod persistence;
mod state;
mod utils;
mod package_info {
    include!(concat!(env!("OUT_DIR"), "/package_info.rs"));
    pub const STANDARD_MAJOR_VERSION: u8 = 2;
    pub const STANDARD_MINOR_VERSION: u8 = 4;
}

lazy_static! {
    pub(crate) static ref SLOTS: RwLock<Option<Slots>> = RwLock::new(None);
    pub(crate) static ref CONFIGURATION: RwLock<Option<Arc<dyn ConfigurationProvider>>> =
        RwLock::new(None);
    pub(crate) static ref SESSIONS: RwLock<Option<Sessions>> = RwLock::new(None);
    pub(crate) static ref RUNTIME: RwLock<Option<Runtime>> = RwLock::new(None);
    pub(crate) static ref COMMUNICATOR: Mutex<Option<Box<dyn Communicator>>> = Mutex::new(None);
}
