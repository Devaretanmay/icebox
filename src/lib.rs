use linkme::distributed_slice;
extern crate self as icebox;

#[distributed_slice]
pub static MODULE_REGISTRY: [crate::core::module::ModuleEntry];

pub mod ai;
pub mod capi;
pub mod core;
pub mod interfaces;
pub mod modules;
