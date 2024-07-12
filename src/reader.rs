use crate::{
    domain_id::DomainIdProvider, errors::CCIPReaderError, types::ResolveResult,
    utils::iter_parent_names,
};
use alloy::{
    eips::BlockId,
    hex::FromHex,
    network::TransactionBuilder,
    primitives::{Address, Bytes},
    rpc::types::TransactionRequest,
    sol_types::{SolCall, SolError, SolValue},
    transports::{BoxTransport, RpcError, TransportErrorKind},
};
use async_recursion::async_recursion;
use serde_json::Value;
use std::time::Duration;

use crate::{
    ccip, consts, contracts,
    utils::{build_reqwest, dns_encode, sanitaze_error_data_from_rpc},
    CCIPRequest, NamehashIdProvider,
};

pub struct CCIPReader<P, D> {
    provider: P,
    ens: contracts::ENS::ENSInstance<BoxTransport, P>,
    reqwest_client: reqwest::Client,
    max_redirect_attempt: u8,
    domain_id_provider: D,
}

pub struct CCIPReaderBuilder<P, D> {
    provider: Option<P>,
    ens_address: Option<Address>,
    timeout: Option<Duration>,
    max_redirect_attempt: Option<u8>,
    domain_id_provider: D,
}

impl<P> Default for CCIPReaderBuilder<P, NamehashIdProvider> {
    fn default() -> Self {
        CCIPReaderBuilder {
            provider: None,
            ens_address: None,
            timeout: None,
            max_redirect_attempt: None,
            domain_id_provider: NamehashIdProvider,
        }
    }
}

impl<P, D> CCIPReaderBuilder<P, D>
where
    P: alloy::providers::Provider + Clone,
    D: DomainIdProvider,
{
    pub fn with_provider(mut self, provider: P) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_max_redirect_attempt(mut self, max_redirect_attempt: u8) -> Self {
        self.max_redirect_attempt = Some(max_redirect_attempt);
        self
    }

    pub fn with_ens_address(mut self, ens_address: Address) -> Self {
        self.ens_address = Some(ens_address);
        self
    }

    pub fn with_domain_id_provider<D2>(self, domain_id_provider: D2) -> CCIPReaderBuilder<P, D2> {
        CCIPReaderBuilder {
            provider: self.provider,
            ens_address: self.ens_address,
            timeout: self.timeout,
            max_redirect_attempt: self.max_redirect_attempt,
            domain_id_provider,
        }
    }

    pub fn build(self) -> Result<CCIPReader<P, D>, String> {
        let ens_address = self.ens_address.unwrap_or(consts::MAINNET_ENS_ADDRESS);
        let provider = self.provider.ok_or("provider is required".to_string())?;
        Ok(CCIPReader {
            ens: contracts::ENS::ENSInstance::new(ens_address, provider.clone()),
            provider,
            reqwest_client: build_reqwest(self.timeout.unwrap_or(Duration::from_secs(10))),
            max_redirect_attempt: self.max_redirect_attempt.unwrap_or(10),
            domain_id_provider: self.domain_id_provider,
        })
    }
}

impl<P> CCIPReader<P, NamehashIdProvider>
where
    P: alloy::providers::Provider + Clone,
{
    pub fn builder() -> CCIPReaderBuilder<P, NamehashIdProvider> {
        CCIPReaderBuilder::default()
    }

    /// Creates an instance of CCIPReader
    /// `ìnner` the inner Provider
    pub fn new(inner: P) -> Self {
        Self::builder().with_provider(inner).build().unwrap()
    }
}

impl<P, D> CCIPReader<P, D>
where
    P: alloy::providers::Provider + Clone,
    D: DomainIdProvider + Send + Sync,
{
    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub async fn call(&self, tx: &TransactionRequest) -> Result<Bytes, CCIPReaderError> {
        self.call_ccip(tx).await.map(|(result, _)| result)
    }

    /// Perform eth_call with tx, and handle CCIP requests if needed
    /// returning both the result of the call and the CCIP requests made during the call
    pub async fn call_ccip(
        &self,
        tx: &TransactionRequest,
    ) -> Result<(Bytes, Vec<CCIPRequest>), CCIPReaderError> {
        let mut requests = Vec::new();
        let mut tx = tx.clone();
        self._call(&mut tx, 0, &mut requests).await
    }

    /// The supports_wildcard checks if a given resolver supports the wildcard resolution by calling
    /// its `supportsInterface` function with the `resolve(bytes,bytes)` selector.
    ///
    /// # Arguments
    ///
    /// * `resolver_address`: The resolver's address.
    ///
    /// # Returns
    ///
    /// A `Result` with either a `bool` value indicating if the resolver supports wildcard
    /// resolution or a `ProviderError`.
    pub async fn supports_wildcard(
        &self,
        resolver_address: Address,
    ) -> Result<bool, CCIPReaderError> {
        let contract = contracts::IERC165::new(resolver_address, self.provider.clone());
        // sending `supportsInterface` call, with selector of the "resolve(bytes,bytes)" function
        let supported = contract
            .supportsInterface(consts::ENSIP10_RESOLVER_INTERFACE.into())
            .call()
            .await?
            ._0;
        Ok(supported)
    }

    pub async fn get_resolver(&self, name: &str) -> Result<Address, CCIPReaderError> {
        for parent_name in iter_parent_names(name) {
            if parent_name.is_empty() || parent_name.eq(".") {
                return Ok(Address::ZERO);
            }

            if !name.eq("eth") && parent_name.eq("eth") {
                return Ok(Address::ZERO);
            }

            let name_id = self.domain_id_provider.generate(parent_name);
            let data = self.ens.resolver(name_id).call().await?;
            let resolver_address = data._0;

            if resolver_address != Address::ZERO {
                if parent_name != name && !self.supports_wildcard(resolver_address).await? {
                    return Ok(Address::ZERO);
                }
                return Ok(resolver_address);
            }
        }

        Ok(Address::ZERO)
    }

    pub async fn resolve_name(&self, name: &str) -> Result<ResolveResult, CCIPReaderError> {
        let resolver_address = self.get_resolver(name).await?;
        self.resolve_name_with_resolver(name, resolver_address)
            .await
    }

    pub async fn resolve_name_with_resolver(
        &self,
        name: &str,
        resolver_address: Address,
    ) -> Result<ResolveResult, CCIPReaderError> {
        let node = self.domain_id_provider.generate(name);
        let addr_call = contracts::IAddrResolver::addrCall { node };
        let response: contracts::IAddrResolver::addrReturn = self
            .query_resolver_parameters(name, resolver_address, addr_call)
            .await?;

        Ok(ResolveResult { addr: response._0 })
    }

    async fn query_resolver_parameters<C: SolCall>(
        &self,
        name: &str,
        resolver_address: Address,
        call: C,
    ) -> Result<<C as SolCall>::Return, CCIPReaderError> {
        let (tx, parse_resp_as_bytes) = if self.supports_wildcard(resolver_address).await? {
            let dns_encode_name =
                dns_encode(name).map_err(|e| CCIPReaderError::InvalidDomain(e.to_string()))?;
            let data = call.abi_encode();
            let resolver =
                contracts::IExtendedResolver::new(resolver_address, self.provider.clone());
            let tx = resolver
                .resolve(dns_encode_name.into(), data.into())
                .into_transaction_request();
            (tx, true)
        } else {
            let tx = TransactionRequest::default()
                .with_to(resolver_address)
                .with_call(&call);
            (tx, false)
        };

        let (mut bytes, requests) = self.call_ccip(&tx).await?;

        tracing::debug!(requests =? requests, "finished call_ccip");

        if parse_resp_as_bytes {
            bytes = Bytes::abi_decode(&bytes, true)?;
        }

        let result = C::abi_decode_returns(&bytes, true)?;

        Ok(result)
    }

    #[tracing::instrument(
        skip(self, transaction, requests_buffer),
        fields(tx_to =? transaction.to),
        level = "debug"
    )]
    #[async_recursion]
    async fn _call(
        &self,
        transaction: &mut TransactionRequest,
        attempt: u8,
        requests_buffer: &mut Vec<CCIPRequest>,
    ) -> Result<(Bytes, Vec<CCIPRequest>), CCIPReaderError> {
        if attempt >= self.max_redirect_attempt {
            // may need more info
            return Err(CCIPReaderError::MaxRedirection);
        }
        let response = self
            .provider
            .call(transaction)
            .block(BlockId::latest())
            .await;

        match response {
            Ok(result) => Ok((result, requests_buffer.to_vec())),
            Err(err) => {
                tracing::debug!("rpc-error: {:?}", err);
                self._handle_rpc_error(err, transaction, attempt, requests_buffer)
                    .await
            }
        }
    }

    async fn _handle_rpc_error(
        &self,
        err: RpcError<TransportErrorKind>,
        transaction: &mut TransactionRequest,
        attempt: u8,
        requests_buffer: &mut Vec<CCIPRequest>,
    ) -> Result<(Bytes, Vec<CCIPRequest>), CCIPReaderError> {
        let tx_sender = transaction
            .to
            .as_ref()
            .and_then(|to| to.to())
            .expect("call tx must have a to");

        let Some(error_payload) = err.as_error_resp() else {
            return Err(err.into());
        };
        let Some(Ok(Value::String(data))) = error_payload.try_data_as::<serde_json::Value>() else {
            return Err(err.into());
        };
        let data = sanitaze_error_data_from_rpc(data);
        let bytes = Bytes::from_hex(&data)?;

        if !bytes.starts_with(&consts::OFFCHAIN_LOOKUP_SELECTOR) {
            return Err(err.into());
        }

        let offchain_lookup = contracts::IOffChain::OffchainLookup::abi_decode(&bytes, true)?;
        let sender = &offchain_lookup.sender;
        if !sender.eq(tx_sender) {
            return Err(CCIPReaderError::Sender {
                sender: format!("0x{:x}", sender),
            });
        }

        let (ccip_result, requests) = ccip::handle_ccip(
            &self.reqwest_client,
            &offchain_lookup.sender,
            transaction,
            &offchain_lookup.callData,
            offchain_lookup.urls,
        )
        .await?;

        requests_buffer.extend(requests);

        if ccip_result.is_empty() {
            return Err(CCIPReaderError::GatewayNotFound);
        }

        let encoded_data = (ccip_result, offchain_lookup.extraData).abi_encode_params();
        let calldata = [
            offchain_lookup.callbackFunction.as_slice(),
            encoded_data.as_slice(),
        ]
        .concat();

        transaction.set_input(calldata);

        self._call(transaction, attempt + 1, requests_buffer).await
    }
}

// // TODO: add all the methods from ethers-ccip-read

// /// Middleware implementation for CCIPReadMiddleware
// #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
// #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
// impl<M> Middleware for CCIPReadResolver<M>
// where
//     M: Middleware,
// {
//     type Error = CCIPReadResolverError<M>;
//     type Provider = M::Provider;
//     type Inner = M;

//     /// Get a reference to the inner middleware
//     fn inner(&self) -> &M {
//         &self.provider
//     }

//     /// Call the underlying middleware with the provided transaction and block
//     async fn call(
//         &self,
//         tx: &TypedTransaction,
//         block: Option<BlockId>,
//     ) -> Result<Bytes, Self::Error> {
//         Ok(self.call_ccip(tx, block).await?.0)
//     }

//     /**
//     The following couple of methods were copied from ethers-rs, and modified to work with ENSIP-10
//     **/
//     /// Resolve a field of an ENS name
//     async fn resolve_field(&self, ens_name: &str, field: &str) -> Result<String, Self::Error> {
//         let field: String = self
//             .query_resolver_parameters(
//                 ParamType::String,
//                 ens_name,
//                 ens::FIELD_SELECTOR,
//                 Some(&ens::parameterhash(field)),
//             )
//             .await?;
//         Ok(field)
//     }

//     /// Resolve avatar field of an ENS name
//     async fn resolve_avatar(&self, ens_name: &str) -> Result<Url, Self::Error> {
//         let (field, owner) = try_join!(
//             self.resolve_field(ens_name, "avatar"),
//             self.resolve_name(ens_name)
//         )?;
//         let url = Url::from_str(&field)
//             .map_err(|e| CCIPReadResolverError::URLParseError(e.to_string()))?;
//         match url.scheme() {
//             "https" | "data" => Ok(url),
//             "ipfs" => erc::http_link_ipfs(url).map_err(CCIPReadResolverError::URLParseError),
//             "eip155" => {
//                 let token = erc::ERCNFT::from_str(url.path())
//                     .map_err(CCIPReadResolverError::URLParseError)?;
//                 match token.type_ {
//                     erc::ERCNFTType::ERC721 => {
//                         let tx = TransactionRequest {
//                             data: Some(
//                                 [&erc::ERC721_OWNER_SELECTOR[..], &token.id].concat().into(),
//                             ),
//                             to: Some(NameOrAddress::Address(token.contract)),
//                             ..Default::default()
//                         };
//                         let data = self.call(&tx.into(), None).await?;
//                         if decode_bytes::<Address>(ParamType::Address, &data)? != owner {
//                             return Err(CCIPReadResolverError::NFTOwnerError(
//                                 "Incorrect owner.".to_string(),
//                             ));
//                         }
//                     }
//                     erc::ERCNFTType::ERC1155 => {
//                         let tx = TransactionRequest {
//                             data: Some(
//                                 [
//                                     &erc::ERC1155_BALANCE_SELECTOR[..],
//                                     &[0x0; 12],
//                                     &owner.0,
//                                     &token.id,
//                                 ]
//                                 .concat()
//                                 .into(),
//                             ),
//                             to: Some(NameOrAddress::Address(token.contract)),
//                             ..Default::default()
//                         };
//                         let data = self.call(&tx.into(), None).await?;
//                         if decode_bytes::<u64>(ParamType::Uint(64), &data)? == 0 {
//                             return Err(CCIPReadResolverError::NFTOwnerError(
//                                 "Incorrect balance.".to_string(),
//                             ));
//                         }
//                     }
//                 }

//                 let image_url = self.resolve_nft(token).await?;
//                 match image_url.scheme() {
//                     "https" | "data" => Ok(image_url),
//                     "ipfs" => erc::http_link_ipfs(image_url)
//                         .map_err(CCIPReadResolverError::URLParseError),
//                     _ => Err(CCIPReadResolverError::UnsupportedURLSchemeError),
//                 }
//             }
//             _ => Err(CCIPReadResolverError::UnsupportedURLSchemeError),
//         }
//     }

//     /// Resolve an ENS name to an address
//     async fn resolve_name(&self, ens_name: &str) -> Result<Address, Self::Error> {
//         self.query_resolver(ParamType::Address, ens_name, ens::ADDR_SELECTOR)
//             .await
//     }

//     /// Look up an address to find its primary ENS name
//     async fn lookup_address(&self, address: Address) -> Result<String, Self::Error> {
//         let ens_name = ens::reverse_address(address);
//         let domain: String = self
//             .query_resolver(ParamType::String, &ens_name, ens::NAME_SELECTOR)
//             .await?;
//         let reverse_address = self.resolve_name(&domain).await?;
//         if address != reverse_address {
//             Err(CCIPReadResolverError::EnsNotOwned(domain))
//         } else {
//             Ok(domain)
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use alloy::{
        hex,
        primitives::{address, B256},
        providers::{ProviderBuilder, RootProvider},
        transports::BoxTransport,
    };
    use std::str::FromStr;

    use crate::namehash;

    use super::*;

    fn default_provider() -> RootProvider<BoxTransport> {
        ProviderBuilder::default()
            .on_http(consts::DEFAULT_ETHEREUM_RPC_URL.parse().unwrap())
            .boxed()
    }

    fn default_reader() -> CCIPReader<RootProvider<BoxTransport>, NamehashIdProvider> {
        CCIPReader::new(default_provider())
    }

    #[tokio::test]
    async fn test_eip_2544_ens_wildcards() {
        let reader = default_reader();

        for (ens_name, wildcarded, expected_resolver, expected_addr) in [
            (
                "1.offchainexample.eth",
                true,
                "0xC1735677a60884ABbCF72295E88d47764BeDa282",
                "0x41563129cDbbD0c5D3e1c86cf9563926b243834d",
            ),
            (
                "levvv.xyz",
                true,
                "0xF142B308cF687d4358410a4cB885513b30A42025",
                "0xc0de20a37e2dac848f81a93bd85fe4acdde7c0de",
            ),
            (
                "vitalik.eth",
                false,
                "0x231b0Ee14048e9dCcD1d247744d114a4EB5E8E63",
                "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            ),
            (
                "itslev.cb.id",
                true,
                "0x1934FC75aD10d7eEd51dc7A92773cAc96A06BE56",
                "0xD578780f1dA7404d9CC0eEbC9D684c140CC4b638",
            ),
        ] {
            let resolver_address = reader.get_resolver(ens_name).await.unwrap();
            assert_eq!(
                resolver_address,
                Address::from_str(expected_resolver).unwrap(),
                "Expected resolver_address to be {expected_resolver}, but got {}",
                resolver_address
            );

            let supports_wildcard = reader.supports_wildcard(resolver_address).await.unwrap();
            assert_eq!(
                supports_wildcard, wildcarded,
                "Wildcard support is {supports_wildcard}, expected to be {wildcarded}"
            );

            let result = reader.resolve_name(ens_name).await.unwrap();
            assert_eq!(
                result.addr,
                Address::from_str(expected_addr).unwrap(),
                "Expected resolved_address to be {expected_addr}, but got {}",
                result.addr
            );
        }
    }

    #[tokio::test]
    async fn test_ccip_call() {
        let reader = default_reader();

        let email = "nick@ens.domains";

        // parameters = text(bytes32 node, string calldata key) node: namehash('1.offchainexample.eth'), key: 'email'
        // tx_data = selector(resolve(bytes,bytes)), namehash(name), parameters
        // ensip10 interface + encode(dnsencode(name), tx_data)
        let tx = TransactionRequest::default()
            .with_input(hex!("9061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"))
            .with_to(address!("C1735677a60884ABbCF72295E88d47764BeDa282"));

        let result = reader.call(&tx).await.unwrap();

        let data: Bytes = Bytes::abi_decode(&result, true).unwrap();
        let record: String = String::abi_decode(&data, true).unwrap();

        assert_eq!(record, email);
    }

    #[tokio::test]
    async fn test_custom_domain_id_provider() {
        #[derive(Clone)]
        struct CustomDomainIdProvider;

        impl DomainIdProvider for CustomDomainIdProvider {
            fn generate(&self, name: &str) -> B256 {
                namehash(&format!("{}.eth", name))
            }
        }

        let always_eth_reader = CCIPReader::builder()
            .with_provider(default_provider())
            .with_domain_id_provider(CustomDomainIdProvider)
            .build()
            .unwrap();

        let resolver_address = always_eth_reader
            .resolve_name("vitalik")
            .await
            .unwrap()
            .addr;
        assert_eq!(
            resolver_address,
            Address::from_str("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045").unwrap()
        );
    }

    // // TODO: rewrite this test when alloy will support mocked provider
    // #[tokio::test]
    // async fn test_mismatched_sender() {
    //     let resolver_address = "0xC1735677a60884ABbCF72295E88d47764BeDa282";

    //     let (provider, mock) = Provider::mocked();
    //     let provider = CCIPReader::new(provider);

    //     let tx: TypedTransaction = TransactionRequest {
    //         // parameters = text(bytes32 node, string calldata key) node: namehash('1.offchainexample.eth'), key: 'email'
    //         // tx_data = selector(resolve(bytes,bytes)), namehash(name), parameters
    //         // ensip10 interface + encode(dnsencode(name), tx_data)
    //         data: Some(Bytes::from(hex::decode("9061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap())),
    //         to: Some(resolver_address.into()),
    //         ..Default::default()
    //     }.into();

    //     let error_code = 3;
    //     // sender information altered to c1735677a60884abbcf72295e88d47764beda283
    //     let error_data = r#""0x556f1830000000000000000000000000c1735677a60884abbcf72295e88d47764beda28300000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000160f4d4d2f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000004768747470733a2f2f6f6666636861696e2d7265736f6c7665722d6578616d706c652e75632e722e61707073706f742e636f6d2f7b73656e6465727d2f7b646174617d2e6a736f6e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001449061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001449061b92300000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000001701310f6f6666636861696e6578616d706c650365746800000000000000000000000000000000000000000000000000000000000000000000000000000000008459d1d43c1c9fb8c1fe76f464ccec6d2c003169598fdfcbcb6bbddf6af9c097a39fa0048c00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000005656d61696c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000""#;
    //     let error_message = "execution reverted";
    //     let error = JsonRpcError {
    //         code: error_code,
    //         data: Some(serde_json::from_str(error_data).unwrap()),
    //         message: error_message.to_string(),
    //     };
    //     mock.push_response(MockResponse::Error(error.clone()));

    //     let result = provider.call(&tx, None).await;
    //     assert!(result.is_err());
    //     assert_eq!(
    //         result.unwrap_err().to_string(),
    //         format!(
    //             "CCIP Read sender did not match {}",
    //             "0xc1735677a60884abbcf72295e88d47764beda283"
    //         )
    //     );
    // }
}
