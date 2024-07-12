use alloy::{
    hex::FromHexError,
    transports::{RpcError, TransportErrorKind},
};
use std::{collections::HashMap, fmt::Display};
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum CCIPRequestError {
    // gateway supplied error
    #[error("Gateway error: {0}")]
    GatewayError(String),

    // when gateway either fails to respond with an expected format
    #[error("Gateway format error: {0}")]
    GatewayFormatError(String),

    #[error("HTTP error: {0}")]
    HTTPError(#[from] reqwest::Error),
}

#[derive(Debug)]
pub struct CCIPFetchError(pub(crate) HashMap<String, Vec<String>>);

/// Handle CCIP-Read middlware specific errors.
#[derive(Error, Debug)]
pub enum CCIPReaderError {
    /// Thrown when the internal middleware errors
    #[error("{0}")]
    Internal(anyhow::Error),

    #[error("contract call error: {0}")]
    ContractCall(#[from] alloy::contract::Error),

    #[error("rpc error: {0}")]
    Rpc(#[from] RpcError<TransportErrorKind>),

    #[error("abi encode or decode error: {0}")]
    AbiEncodeDecode(#[from] alloy::sol_types::Error),

    #[error("Error(s) during CCIP fetch: {0}")]
    Fetch(CCIPFetchError),

    #[error("CCIP Read sender did not match {}", sender)]
    Sender { sender: String },

    #[error("CCIP Read no provided URLs")]
    GatewayNotFound,

    #[error("CCIP Read exceeded maximum redirections")]
    MaxRedirection,

    #[error("error decoding from hex: {0}")]
    HexDecode(#[from] FromHexError),

    #[error("Invalid domain: {0}")]
    InvalidDomain(String),

    /// Invalid reverse ENS name
    #[error("Reversed ens name not pointing to itself: {0}")]
    #[allow(dead_code)]
    EnsNotOwned(String),

    #[error("Error(s) during parsing avatar url: {0}")]
    #[allow(dead_code)]
    URLParse(String),

    #[error("Error(s) during NFT ownership verification: {0}")]
    #[allow(dead_code)]
    NFTOwner(String),
}

impl Display for CCIPFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut errors = f.debug_struct("CCIPFetchError");

        for (url, messages) in self.0.iter() {
            errors.field(url, messages);
        }

        errors.finish()
    }
}
