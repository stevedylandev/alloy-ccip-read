use alloy::providers::ProviderBuilder;
use alloy_ccip_read::CCIPReader;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let rpc = alloy_ccip_read::consts::DEFAULT_ETHEREUM_RPC_URL;
    let provider = ProviderBuilder::new().on_http(rpc.parse().unwrap());
    let reader = CCIPReader::new(provider.boxed());
    for ens_name in [
        "1.offchainexample.eth",
        "levvv.xyz",
        "itslev.cb.id",
        "llev.me",
    ] {
        println!("\nresolving name: {}", ens_name);
        let resolver_address = reader.get_resolver(ens_name).await.unwrap();
        println!("resolver_address: {:?}", resolver_address);

        let supports_wildcard = reader.supports_wildcard(resolver_address).await.unwrap();
        println!("supports_wildcard: {:?}", supports_wildcard);

        let resolved_address = reader.resolve_name(ens_name).await.unwrap();
        println!("resolved_address: {:?}", resolved_address);
    }

    Ok(())
}
