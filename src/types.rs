use alloy::primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub addr: CCIPType<Address>,
    pub ccip_read_used: bool,
    pub wildcard_used: bool,
}

pub struct ReverseResolveResult {
    pub name: CCIPType<String>,
    pub ccip_read_used: bool,
}

#[derive(Debug, Clone)]
pub struct CCIPType<T> {
    pub value: T,
    pub requests: Vec<CCIPRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CCIPRequest {
    pub url: String,
    pub sender: Address,
    pub calldata: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CCIPResponse {
    pub data: Option<String>,
    pub message: Option<String>,
}
