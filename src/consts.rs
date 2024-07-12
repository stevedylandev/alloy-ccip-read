use alloy::primitives::{address, Address};

pub const DEFAULT_ETHEREUM_RPC_URL: &str = "https://ethereum-rpc.publicnode.com";
pub const MAINNET_ENS_ADDRESS: Address = address!("00000000000C2E074eC69A0dFb2997BA6C7d2e1e");
// https://www.4byte.directory/signatures/?bytes4_signature=0x9061b923
pub const ENSIP10_RESOLVER_INTERFACE: [u8; 4] = [0x90, 0x61, 0xb9, 0x23];
// https://www.4byte.directory/signatures/?bytes4_signature=0x556f1830
pub const OFFCHAIN_LOOKUP_SELECTOR: [u8; 4] = [0x55, 0x6f, 0x18, 0x30];
