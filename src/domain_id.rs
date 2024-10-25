/// This module provides a way to generate a domain id from a domain name.
/// The domain id is used to identify a domain in the ENS system.
/// Most commonly the domain id is generated using the namehash algorithm,
/// however this crate provider a way to generate domain ids using other algorithms.
use alloy::primitives::{keccak256, B256};

pub trait DomainIdProvider: Clone + Send + Sync {
    fn generate(&self, name: &str) -> B256;
}

#[derive(Default, Debug, Clone)]
pub struct NamehashIdProvider;

impl DomainIdProvider for NamehashIdProvider {
    fn generate(&self, name: &str) -> B256 {
        namehash(name)
    }
}

/// Returns the ENS namehash as specified in [EIP-137](https://eips.ethereum.org/EIPS/eip-137)
pub fn namehash(name: &str) -> B256 {
    if name.is_empty() {
        return B256::ZERO;
    }

    // Remove the variation selector U+FE0F
    let name = name.replace('\u{fe0f}', "");

    // Generate the node starting from the right
    name.rsplit('.')
        .fold([0u8; 32], |node, label| {
            keccak256([node, keccak256(label.as_bytes()).into()].concat()).into()
        })
        .into()
}

#[cfg(test)]
mod tests {
    use alloy::hex::FromHex;

    use super::*;

    #[test]
    fn namehash_works() {
        for (name, expected) in [
            (
                "eth",
                "93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae",
            ),
            (
                "vitalik.eth",
                "ee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835",
            ),
            (
                "itslev.cb.id",
                "374c33a7695f14806781b113c46fe46030f8448ab0c3bae331ef443e281dfd10",
            ),
        ] {
            let expected = B256::from_hex(expected).unwrap();
            assert_eq!(namehash(name), expected);
        }
    }
}
