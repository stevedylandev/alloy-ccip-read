use alloy::primitives::{Address, Bytes};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub addr: CCIPType<Address>,
    pub ccip_read_used: bool,
    pub wildcard_used: bool,
}

#[derive(Debug, Clone)]
pub struct CCIPType<T> {
    pub value: T,
    pub requests: Vec<CCIPRequest>,
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
