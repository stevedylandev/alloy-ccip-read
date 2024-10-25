//! # Alloy CCIP-Read
//!
//! Provides an [alloy](https://docs.rs/alloy) reader for the [CCIP-Read](https://eips.ethereum.org/EIPS/eip-3675) standard.

pub use ccip::handle_ccip;
pub use domain_id::{namehash, DomainIdProvider, NamehashIdProvider};
pub use errors::*;
pub use protocols::*;
pub use reader::CCIPReader;
pub use types::*;

mod ccip;
pub mod consts;
mod contracts;
mod domain_id;
mod errors;
mod protocols;
mod reader;
mod types;
pub mod utils;
