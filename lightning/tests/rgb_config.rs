//! Public RGB configuration contracts, independent of the legacy Lightning unit-test harness.

use lightning::rgb_utils::{rgb_online_options, supported_asset_schemas};
use rgb_lib::wallet::IndexerConfig;
use rgb_lib::{AssetSchema, BitcoinNetwork};
use std::collections::HashMap;

#[test]
fn bfa_schema_requires_explicit_opt_in_on_every_network() {
	for network in [
		BitcoinNetwork::Mainnet,
		BitcoinNetwork::Testnet,
		BitcoinNetwork::Testnet4,
		BitcoinNetwork::Signet,
		BitcoinNetwork::SignetCustom,
		BitcoinNetwork::Regtest,
	] {
		let baseline = supported_asset_schemas(network, false);
		assert!(!baseline.contains(&AssetSchema::Bfa));
		assert!(baseline.contains(&AssetSchema::Nia));
		assert!(baseline.contains(&AssetSchema::Cfa));
		assert!(baseline.contains(&AssetSchema::Uda));
		assert_eq!(baseline.contains(&AssetSchema::Ifa), network != BitcoinNetwork::Mainnet);
		let enabled = supported_asset_schemas(network, true);
		assert_eq!(enabled.iter().filter(|schema| **schema == AssetSchema::Bfa).count(), 1);
		let retained: Vec<_> =
			enabled.into_iter().filter(|schema| *schema != AssetSchema::Bfa).collect();
		assert_eq!(retained, baseline, "BFA opt-in must preserve the other schema policy");
	}
}

#[test]
fn indexer_selection_preserves_the_configured_url() {
	for url in ["ssl://indexer.invalid:50002", "tcp://127.0.0.1:50001"] {
		let options = rgb_online_options(url.into(), HashMap::new(), false);
		assert!(
			matches!(options.indexer_config, IndexerConfig::Electrum { url: actual } if actual == url)
		);
	}
	for url in ["https://indexer.invalid/api", "http://127.0.0.1:3002"] {
		let options = rgb_online_options(url.into(), HashMap::new(), false);
		assert!(
			matches!(options.indexer_config, IndexerConfig::Esplora { url: actual } if actual == url)
		);
	}
}

#[test]
fn online_configuration_retains_explicit_evm_endpoints_and_safety_policy() {
	let endpoints = HashMap::from([
		(1, "https://ethereum.invalid".into()),
		(42161, "https://arbitrum.invalid/rpc".into()),
		(31337, "http://127.0.0.1:8545".into()),
	]);
	for skip_consistency_check in [false, true] {
		let options = rgb_online_options(
			"ssl://indexer.invalid:50002".into(),
			endpoints.clone(),
			skip_consistency_check,
		);
		assert_eq!(options.evm_rpc_urls, endpoints);
		assert_eq!(options.skip_consistency_check, skip_consistency_check);
		assert_eq!(options.vanilla_sync_lookback, 20);
		assert_eq!(options.failed_witness_receive_grace_secs, 86400);
		assert!(options.proxy_auth_keys.is_empty(), "proxy authentication is explicit");
	}
}

#[test]
fn missing_evm_configuration_does_not_invent_an_endpoint_or_proxy_secret() {
	let options = rgb_online_options("http://127.0.0.1:3002".into(), HashMap::new(), false);
	assert!(options.evm_rpc_urls.is_empty());
	assert!(options.proxy_auth_keys.is_empty());
	assert!(!options.skip_consistency_check);
}
