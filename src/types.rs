use alloy::primitives::{Address, Bytes};
use derive_new::new;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub addr: CCIPResult<Address>,
    pub ccip_read_used: bool,
    pub wildcard_used: bool,
}

pub struct ReverseResolveResult {
    pub name: CCIPResult<String>,
    pub ccip_read_used: bool,
}

#[derive(Debug, Clone, new)]
pub struct CCIPResult<T> {
    pub value: T,
    pub requests: Vec<CCIPRequest>,
}

impl<T> CCIPResult<T> {
    pub fn into_value(self) -> T {
        self.value
    }

    pub fn ccip_read_used(&self) -> bool {
        !self.requests.is_empty()
    }

    pub fn map<F, U>(self, f: F) -> CCIPResult<U>
    where
        F: FnOnce(T) -> U,
    {
        CCIPResult::new(f(self.value), self.requests)
    }
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
