use alloy::primitives::{Address, Bytes};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub addr: Address,
}

#[derive(Debug, Clone)]
pub struct CCIPRequest {
    pub url: String,
    pub sender: Address,
    pub calldata: Bytes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CCIPResponse {
    pub data: Option<String>,
    pub message: Option<String>,
}
