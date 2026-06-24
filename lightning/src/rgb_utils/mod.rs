//! A module to provide RGB functionality

use crate::ln::chan_utils::{
	get_countersigner_payment_script, BuiltCommitmentTransaction, ClosingTransaction,
	CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{ChannelContext, ChannelError, FundingScope};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::types::ChannelId;
use crate::sign::SignerProvider;
use crate::types::features::ChannelTypeFeatures;
use crate::types::payment::PaymentHash;
use crate::util::persist::KVStoreSync;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	keys::WitnessVersion,
	wallet::{
		rust_only::{AssetColoringInfo, ColoringInfo},
		DatabaseType, OnlineOptions, SinglesigKeys, Wallet, WalletData,
	},
	AssetSchema, Assignment, BitcoinNetwork, ConsignmentExt, ContractId, Error as RgbLibError,
	FileContent, RgbTransfer, RgbTransport, WitnessOrd,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use crate::io;
use core::ops::Deref;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

/// Static blinding constant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
/// Name of the file containing the bitcoin network
pub const BITCOIN_NETWORK_FNAME: &str = "bitcoin_network";
/// Name of the file containing the electrum URL
pub const INDEXER_URL_FNAME: &str = "indexer_url";
/// Name of the file containing the wallet fingerprint
pub const WALLET_FINGERPRINT_FNAME: &str = "wallet_fingerprint";
/// Name of the file containing the account-level xPub of the vanilla-side of the wallet
pub const WALLET_ACCOUNT_XPUB_VANILLA_FNAME: &str = "wallet_account_xpub_vanilla";
/// Name of the file containing the account-level xPub of the colored-side of the wallet
pub const WALLET_ACCOUNT_XPUB_COLORED_FNAME: &str = "wallet_account_xpub_colored";
/// Name of the file containing the master fingerprint of the wallet
pub const WALLET_MASTER_FINGERPRINT_FNAME: &str = "wallet_master_fingerprint";
/// Name of the file containing the wallet reuse_addresses setting
pub const WALLET_REUSE_ADDRESSES_FNAME: &str = "wallet_reuse_addresses";

// kv_store namespace constants for RGB data persistence
/// Primary namespace for all RGB data
pub const RGB_PRIMARY_NS: &str = "rgb";
/// Secondary namespace for channel info
pub const RGB_CHANNEL_INFO_NS: &str = "channel_info";
/// Secondary namespace for pending channel info
pub const RGB_CHANNEL_INFO_PENDING_NS: &str = "channel_info_pending";
/// Secondary namespace for inbound payment info
pub const RGB_PAYMENT_INFO_INBOUND_NS: &str = "payment_info_inbound";
/// Secondary namespace for outbound payment info
pub const RGB_PAYMENT_INFO_OUTBOUND_NS: &str = "payment_info_outbound";
/// Secondary namespace for transfer info
pub const RGB_TRANSFER_INFO_NS: &str = "transfer_info";
/// Secondary namespace for consignment data
pub const RGB_CONSIGNMENT_NS: &str = "consignment";
/// Secondary namespace for wallet configuration
pub const RGB_WALLET_CONFIG_NS: &str = "wallet_config";
const VANILLA_SYNC_LOOKBACK: u32 = 20;

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbInfo {
	/// Channel contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Channel schema
	pub schema: AssetSchema,
	/// Channel RGB local amount
	pub local_rgb_amount: u64,
	/// Channel RGB remote amount
	pub remote_rgb_amount: u64,
	/// Batch transfer index from rgb-lib (set after rgb_send_begin).
	/// NOTE: no serde skip/default attributes here — RgbInfo is persisted via
	/// bincode (a positional, non-self-describing format), so the field must be
	/// serialized unconditionally to stay in sync on read.
	pub batch_transfer_idx: Option<i32>,
}

/// RGB payment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbPaymentInfo {
	/// RGB contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// RGB payment amount
	pub amount: u64,
	/// RGB local amount
	pub local_rgb_amount: u64,
	/// RGB remote amount
	pub remote_rgb_amount: u64,
	/// Whether the RGB amount in route should be overridden
	pub swap_payment: bool,
	/// Whether the payment is inbound
	pub inbound: bool,
}

/// RGB transfer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferInfo {
	/// Transfer contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Transfer RGB amount
	pub rgb_amount: u64,
}

mod contract_id_serde {
	use super::*;
	use serde::{Deserializer, Serializer};
	use std::str::FromStr;

	pub fn serialize<S>(id: &ContractId, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&id.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<ContractId, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		ContractId::from_str(&s).map_err(serde::de::Error::custom)
	}
}

fn _get_bitcoin_network(kv_store: &dyn KVStoreSync) -> BitcoinNetwork {
	let bitcoin_network =
		kv_store.read_config(BITCOIN_NETWORK_FNAME).expect("bitcoin_network must be in KVStore");
	BitcoinNetwork::from_str(&bitcoin_network).unwrap()
}

fn _get_account_xpub_colored(kv_store: &dyn KVStoreSync) -> String {
	kv_store
		.read_config(WALLET_ACCOUNT_XPUB_COLORED_FNAME)
		.expect("account_xpub_colored must be in KVStore")
}

fn _get_account_xpub_vanilla(kv_store: &dyn KVStoreSync) -> String {
	kv_store
		.read_config(WALLET_ACCOUNT_XPUB_VANILLA_FNAME)
		.expect("account_xpub_vanilla must be in KVStore")
}

fn _get_master_fingerprint(kv_store: &dyn KVStoreSync) -> String {
	kv_store
		.read_config(WALLET_MASTER_FINGERPRINT_FNAME)
		.expect("master_fingerprint must be in KVStore")
}

fn _get_indexer_url(kv_store: &dyn KVStoreSync) -> String {
	kv_store.read_config(INDEXER_URL_FNAME).expect("indexer_url must be in KVStore")
}

fn _get_reuse_addresses(kv_store: &dyn KVStoreSync) -> bool {
	kv_store.read_config(WALLET_REUSE_ADDRESSES_FNAME).map(|v| v == "true").unwrap_or(false)
}

fn _new_rgb_wallet(
	data_dir: String, bitcoin_network: BitcoinNetwork, account_xpub_vanilla: String,
	account_xpub_colored: String, master_fingerprint: String, reuse_addresses: bool,
) -> Wallet {
	let keys = SinglesigKeys {
		account_xpub_vanilla,
		account_xpub_colored,
		vanilla_keychain: None,
		master_fingerprint,
		mnemonic: None,
		witness_version: WitnessVersion::Taproot,
	};
	Wallet::new(
		WalletData {
			data_dir,
			bitcoin_network,
			database_type: DatabaseType::Sqlite,
			max_allocations_per_utxo: 1,
			supported_schemas: vec![
				AssetSchema::Nia,
				AssetSchema::Cfa,
				AssetSchema::Uda,
				AssetSchema::Ifa,
			],
			reuse_addresses,
		},
		keys,
	)
	.expect("valid rgb-lib wallet")
}

fn _get_wallet_data(
	ldk_data_dir: &Path, kv_store: &dyn KVStoreSync,
) -> (String, BitcoinNetwork, String, String, String, bool) {
	let data_dir = ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
	let bitcoin_network = _get_bitcoin_network(kv_store);
	let account_xpub_vanilla = _get_account_xpub_vanilla(kv_store);
	let account_xpub_colored = _get_account_xpub_colored(kv_store);
	let master_fingerprint = _get_master_fingerprint(kv_store);
	let reuse_addresses = _get_reuse_addresses(kv_store);
	(
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		reuse_addresses,
	)
}

async fn _get_rgb_wallet(ldk_data_dir: &Path, kv_store: &dyn KVStoreSync) -> Wallet {
	let (
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		reuse_addresses,
	) = _get_wallet_data(ldk_data_dir, kv_store);
	tokio::task::spawn_blocking(move || {
		_new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
			reuse_addresses,
		)
	})
	.await
	.unwrap()
}

async fn _accept_transfer(
	ldk_data_dir: &Path, funding_txid: String, consignment_endpoint: RgbTransport,
	kv_store: &dyn KVStoreSync,
) -> Result<(RgbTransfer, Vec<Assignment>), RgbLibError> {
	let funding_vout = 1;
	let (
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		reuse_addresses,
	) = _get_wallet_data(ldk_data_dir, kv_store);
	let indexer_url = _get_indexer_url(kv_store);
	tokio::task::spawn_blocking(move || {
		let mut wallet = _new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
			reuse_addresses,
		);
		wallet.go_online(OnlineOptions {
			indexer_url,
			skip_consistency_check: true,
			vanilla_sync_lookback: VANILLA_SYNC_LOOKBACK,
		})?;
		wallet.accept_transfer(
			funding_txid.clone(),
			funding_vout,
			consignment_endpoint,
			STATIC_BLINDING,
		)
	})
	.await
	.unwrap()
}

fn _counterparty_output_index(
	outputs: &[TxOut], channel_type_features: &ChannelTypeFeatures, payment_key: &PublicKey,
) -> Option<usize> {
	let counterparty_payment_script =
		get_countersigner_payment_script(channel_type_features, payment_key);
	outputs
		.iter()
		.enumerate()
		.find(|(_, out)| out.script_pubkey == counterparty_payment_script)
		.map(|(idx, _)| idx)
}

/// Return the position of the OP_RETURN output, if present
pub fn op_return_position(tx: &Transaction) -> Option<usize> {
	tx.output.iter().position(|o| o.script_pubkey.is_op_return())
}

/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
pub fn is_tx_colored(tx: &Transaction) -> bool {
	op_return_position(tx).is_some()
}

/// Color commitment transaction
pub(crate) fn color_commitment<SP: Deref>(
	channel_context: &ChannelContext<SP>, funding_scope: &FundingScope,
	commitment_transaction: &mut CommitmentTransaction, counterparty: bool,
) -> Result<(), ChannelError>
where
	<SP as std::ops::Deref>::Target: SignerProvider,
{
	let channel_id = &channel_context.channel_id;
	let ldk_data_dir = channel_context.ldk_data_dir.as_path();
	let kv_store = channel_context.rgb_kv_store.as_ref();

	let commitment_tx = commitment_transaction.clone().built.transaction;

	let rgb_info = get_rgb_channel_info_pending(channel_id, kv_store);
	let contract_id = rgb_info.contract_id;

	let chan_id = channel_id.0.as_hex();
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
	let mut output_map = HashMap::new();

	for htlc in commitment_transaction.nondust_htlcs() {
		if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
			continue;
		}
		let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

		let htlc_vout = htlc.transaction_output_index.unwrap();

		let inbound = htlc.offered == counterparty;

		let htlc_payment_hash = htlc.payment_hash.0.as_hex().to_string();
		let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");
		let htlc_proxy_id_pending = format!("{htlc_proxy_id}_pending");
		let pending_key = format!("{htlc_payment_hash}_pending");
		let namespace =
			if inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };

		if let Ok(data) = kv_store.read(RGB_PRIMARY_NS, namespace, &pending_key) {
			let mut rgb_payment_info: RgbPaymentInfo =
				bincode::deserialize(&data).expect("valid data");
			rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
			rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let data = bincode::serialize(&rgb_payment_info).expect("valid rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id, data.clone())
				.expect("able to write rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
				.expect("able to write rgb pending payment info");
			kv_store
				.remove(RGB_PRIMARY_NS, namespace, &pending_key, false)
				.expect("able to remove pending payment info");
		}

		// Only accept a stored candidate if it actually describes THIS HTLC on THIS channel.
		// Matches the pre-KVStore guard in `color_commitment`: a record whose contract_id,
		// amount, or direction disagrees with what's being coloured right now cannot have been
		// written for this HTLC, so treating it as authoritative would poison the commitment
		// (e.g. two legs of an atomic RGB swap sharing a payment_hash under different assets).
		let is_compatible = |info: &RgbPaymentInfo| {
			info.contract_id == contract_id
				&& info.amount == htlc_amount_rgb
				&& info.inbound == inbound
		};

		let rgb_payment_info = if let Some(info) = kv_store
			.read(RGB_PRIMARY_NS, namespace, &htlc_proxy_id)
			.ok()
			.map(|data| bincode::deserialize::<RgbPaymentInfo>(&data).expect("valid data"))
			.filter(|info| is_compatible(info))
		{
			// Cache hit on the per-channel record. Preserve stored balances: they were the
			// channel's snapshot at the time this HTLC was first coloured, and the later
			// `remote_rgb_amount - rgb_received_htlc` (and local/offered) subtraction assumes
			// that snapshot — using current `rgb_info` values can underflow if the channel
			// state has since moved. Matches pre-KVStore `channel_rgb_payment_info_path`
			// behaviour, where `should_persist_channel_info` stayed false on this branch.
			info
		} else if let Some(mut info) = kv_store
			.read_rgb_payment_info(&htlc.payment_hash, inbound)
			.ok()
			.filter(|info| is_compatible(info))
		{
			// Fall back to the canonical payment-hash-keyed record written by the sender/payee
			// via `write_rgb_payment_info_file`. Lets a second channel on the same node recover
			// the authoritative payment info once the first channel has consumed the
			// `<payment_hash>_pending` marker. Refresh balances, then persist a per-channel
			// copy so subsequent commitment updates hit the cached branch above.
			info.local_rgb_amount = rgb_info.local_rgb_amount;
			info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let data = bincode::serialize(&info).expect("valid rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id, data.clone())
				.expect("able to write rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
				.expect("able to write rgb pending payment info");
			info
		} else {
			// No compatible record available (e.g. a forwarder that never saw a
			// sender/payee-side write). Synthesize from the channel's own RGB info plus the
			// HTLC's amount.
			let rgb_payment_info = RgbPaymentInfo {
				contract_id,
				amount: htlc_amount_rgb,
				local_rgb_amount: rgb_info.local_rgb_amount,
				remote_rgb_amount: rgb_info.remote_rgb_amount,
				swap_payment: true,
				inbound,
			};
			let data = bincode::serialize(&rgb_payment_info).expect("valid rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id, data.clone())
				.expect("able to write rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
				.expect("able to write rgb pending payment info");
			rgb_payment_info
		};

		if kv_store.read(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending).is_err() {
			let data = bincode::serialize(&rgb_payment_info).expect("valid rgb payment info");
			kv_store
				.write(RGB_PRIMARY_NS, namespace, &htlc_proxy_id_pending, data)
				.expect("able to write rgb pending payment info");
		}

		if inbound {
			rgb_received_htlc += rgb_payment_info.amount
		} else {
			rgb_offered_htlc += rgb_payment_info.amount
		};

		output_map.insert(htlc_vout, rgb_payment_info.amount);

		last_rgb_payment_info = Some(rgb_payment_info);
	}

	if channel_context.is_trusted_no_broadcast() {
		return Ok(());
	}

	let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
		(
			last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc,
			last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc,
		)
	} else {
		(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
	};
	let (vout_p2wpkh_amt, vout_p2wsh_amt) =
		if counterparty { (local_amt, remote_amt) } else { (remote_amt, local_amt) };

	let payment_point = if counterparty {
		funding_scope.get_holder_pubkeys().payment_point
	} else {
		funding_scope.get_counterparty_pubkeys().payment_point
	};

	if let Some(vout_p2wpkh) = _counterparty_output_index(
		&commitment_tx.output,
		funding_scope.get_channel_type(),
		&payment_point,
	) {
		output_map.insert(vout_p2wpkh as u32, vout_p2wpkh_amt);
	}

	if let Some(vout_p2wsh) = commitment_transaction.trust().revokeable_output_index() {
		output_map.insert(vout_p2wsh as u32, vout_p2wsh_amt);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(commitment_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	let rgb_amount = if counterparty {
		vout_p2wpkh_amt + rgb_offered_htlc
	} else {
		vout_p2wsh_amt + rgb_received_htlc
	};
	let transfer_info = TransferInfo { contract_id, rgb_amount };
	kv_store.write_rgb_transfer_info(&txid.to_string(), &transfer_info);

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(
	htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, ldk_data_dir: &Path,
	kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
		return Ok(());
	}
	let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid.to_string();

	let transfer_info = kv_store.read_rgb_transfer_info(&commitment_txid);
	let contract_id = transfer_info.contract_id;

	let asset_coloring_info = AssetColoringInfo {
		output_map: HashMap::from([(0, htlc_amount_rgb)]),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: Some(1),
	};
	let psbt = Psbt::from_unsigned_tx(htlc_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};
	let txid = &modified_tx.compute_txid();

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
	kv_store.write_rgb_transfer_info(&txid.to_string(), &transfer_info);

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(
	channel_id: &ChannelId, closing_transaction: &mut ClosingTransaction, ldk_data_dir: &Path,
	kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let closing_tx = closing_transaction.clone().built;

	let rgb_info = get_rgb_channel_info_pending(channel_id, kv_store);
	let contract_id = rgb_info.contract_id;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let mut output_map = HashMap::new();

	if closing_transaction.to_holder_value_sat() > 0 {
		let holder_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_holder_script())
			.unwrap();
		output_map.insert(holder_vout as u32, holder_vout_amount);
	}

	if closing_transaction.to_counterparty_value_sat() > 0 {
		let counterparty_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_counterparty_script())
			.unwrap();
		output_map.insert(counterparty_vout as u32, counterparty_vout_amount);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(closing_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = &modified_tx.compute_txid();
	closing_transaction.built = modified_tx;

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	let transfer_info = TransferInfo { contract_id, rgb_amount: holder_vout_amount };
	kv_store.write_rgb_transfer_info(&txid.to_string(), &transfer_info);

	Ok(())
}

/// Get RgbInfo from KVStore
pub(crate) fn get_rgb_channel_info(
	channel_id: &str, pending: bool, kv_store: &dyn KVStoreSync,
) -> RgbInfo {
	kv_store.read_rgb_channel_info(channel_id, pending).expect("channel info must exist in KVStore")
}

/// Get pending RgbInfo from KVStore
pub fn get_rgb_channel_info_pending(channel_id: &ChannelId, kv_store: &dyn KVStoreSync) -> RgbInfo {
	get_rgb_channel_info(&channel_id.0.as_hex().to_string(), true, kv_store)
}

/// Whether the channel has RGB data in KVStore
pub fn is_channel_rgb(channel_id: &ChannelId, kv_store: &dyn KVStoreSync) -> bool {
	let channel_id_str = channel_id.0.as_hex().to_string();
	kv_store.read_rgb_channel_info(&channel_id_str, false).is_ok()
}

/// Write RGB payment info to database
pub fn write_rgb_payment_info_file(
	payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64, swap_payment: bool,
	inbound: bool, kv_store: &Arc<dyn KVStoreSync + Send + Sync>,
) {
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		swap_payment,
		inbound,
	};
	kv_store.write_rgb_payment_info(payment_hash, &rgb_payment_info);
	let payment_hash_hex = payment_hash.0.as_hex();
	let pending_key = format!("{payment_hash_hex}_pending");
	let namespace =
		if inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };
	let data = bincode::serialize(&rgb_payment_info).expect("valid rgb payment info");
	kv_store
		.write(RGB_PRIMARY_NS, namespace, &pending_key, data)
		.expect("able to write rgb payment info pending");
}

/// Rename RGB channel info from temporary to final channel ID in KVStore
pub(crate) fn rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, kv_store: &dyn KVStoreSync,
) {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	let rgb_info = kv_store.read_rgb_channel_info(&temp_chan_id, false).expect("rename ok");
	kv_store.write_rgb_channel_info(&chan_id, &rgb_info, false);
	kv_store.remove_rgb_channel_info(&temp_chan_id, false).expect("rename ok");

	let rgb_info = kv_store.read_rgb_channel_info(&temp_chan_id, true).expect("rename ok");
	kv_store.write_rgb_channel_info(&chan_id, &rgb_info, true);
	kv_store.remove_rgb_channel_info(&temp_chan_id, true).expect("rename ok");

	if let Ok(consignment_data) = kv_store.read_rgb_consignment(&temp_chan_id) {
		kv_store.write_rgb_consignment(&chan_id, consignment_data);
		kv_store.remove_rgb_consignment(&temp_chan_id);
	}
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding(
	temporary_channel_id: &ChannelId, funding_txid: String, ldk_data_dir: &Path,
	consignment_endpoint: RgbTransport, push_asset_amount: Option<u64>, kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let handle = Handle::current();
	let _ = handle.enter();
	let accept_res = futures::executor::block_on(_accept_transfer(
		ldk_data_dir,
		funding_txid.clone(),
		consignment_endpoint,
		kv_store,
	));
	let (consignment, remote_rgb_assignments) = match accept_res {
		Ok(res) => res,
		Err(RgbLibError::InvalidConsignment) => {
			return Err(ChannelError::close("Invalid RGB consignment for funding".to_owned()))
		},
		Err(RgbLibError::NoConsignment) => {
			return Err(ChannelError::close("Failed to find RGB consignment".to_owned()))
		},
		Err(RgbLibError::UnknownRgbSchema { schema_id }) => {
			return Err(ChannelError::close(format!("Unknown RGB schema: {schema_id}")))
		},
		Err(RgbLibError::UnsupportedSchema { asset_schema }) => {
			return Err(ChannelError::close(format!("Unsupported RGB schema: {asset_schema}")))
		},
		Err(RgbLibError::Indexer { details })
		| Err(RgbLibError::InvalidIndexer { details })
		| Err(RgbLibError::Network { details }) => {
			return Err(ChannelError::close(format!("Failed to connect to indexer: {details}")))
		},
		Err(e) => return Err(ChannelError::close(format!("Unexpected error: {e}"))),
	};

	let mut consignment_buf = Vec::new();
	consignment.save(&mut consignment_buf).expect("unable to serialize consignment");
	kv_store.write_rgb_consignment(&funding_txid, consignment_buf.clone());
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	kv_store.write_rgb_consignment(&temp_chan_id, consignment_buf);

	if remote_rgb_assignments.len() != 1 {
		return Err(ChannelError::close(format!(
			"Unexpected number of RGB assignments: {}",
			remote_rgb_assignments.len()
		)));
	}
	let channel_rgb_amount = match remote_rgb_assignments[0] {
		Assignment::Fungible(amt) => amt,
		Assignment::NonFungible => 1,
		_ => unreachable!("unsupported schema"),
	};
	let push_amount = push_asset_amount.unwrap_or(0);
	let rgb_info = RgbInfo {
		contract_id: consignment.contract_id(),
		schema: AssetSchema::from_schema_id(consignment.schema_id()).unwrap(),
		local_rgb_amount: push_amount,
		remote_rgb_amount: channel_rgb_amount - push_amount,
		batch_transfer_idx: None,
	};
	let temporary_channel_id_str = temporary_channel_id.0.as_hex().to_string();

	kv_store.write_rgb_channel_info(&temporary_channel_id_str, &rgb_info, true);
	kv_store.write_rgb_channel_info(&temporary_channel_id_str, &rgb_info, false);

	Ok(())
}

/// Update RGB channel amount in KVStore
pub fn update_rgb_channel_amount(
	channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, pending: bool,
	kv_store: &dyn KVStoreSync,
) {
	let mut rgb_info = get_rgb_channel_info(channel_id, pending, kv_store);

	if rgb_offered_htlc > rgb_received_htlc {
		let spent = rgb_offered_htlc - rgb_received_htlc;
		rgb_info.local_rgb_amount -= spent;
		rgb_info.remote_rgb_amount += spent;
	} else {
		let received = rgb_received_htlc - rgb_offered_htlc;
		rgb_info.local_rgb_amount += received;
		rgb_info.remote_rgb_amount -= received;
	}

	kv_store.write_rgb_channel_info(channel_id, &rgb_info, pending);
}

/// Update pending RGB channel amount
pub(crate) fn update_rgb_channel_amount_pending(
	channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64,
	kv_store: &dyn KVStoreSync,
) {
	update_rgb_channel_amount(
		&channel_id.0.as_hex().to_string(),
		rgb_offered_htlc,
		rgb_received_htlc,
		true,
		kv_store,
	)
}

/// extension trait for RGB-specific KVStore operations
pub trait RgbKvStoreExt {
	/// read transfer info from KVStore
	fn read_rgb_transfer_info(&self, txid: &str) -> TransferInfo;
	/// write transfer info to KVStore
	fn write_rgb_transfer_info(&self, txid: &str, info: &TransferInfo);
	/// read channel info from KVStore
	fn read_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<RgbInfo, io::Error>;
	/// write channel info to KVStore
	fn write_rgb_channel_info(&self, channel_id: &str, rgb_info: &RgbInfo, pending: bool);
	/// read payment info from KVStore
	fn read_rgb_payment_info(
		&self, payment_hash: &PaymentHash, inbound: bool,
	) -> Result<RgbPaymentInfo, io::Error>;
	/// write payment info to KVStore
	fn write_rgb_payment_info(&self, payment_hash: &PaymentHash, info: &RgbPaymentInfo);
	/// read consignment from KVStore
	fn read_rgb_consignment(&self, id: &str) -> Result<Vec<u8>, io::Error>;
	/// write consignment to KVStore
	fn write_rgb_consignment(&self, id: &str, data: Vec<u8>);
	/// remove channel info from KVStore
	fn remove_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<(), io::Error>;
	/// remove consignment from KVStore
	fn remove_rgb_consignment(&self, id: &str);
	/// read a wallet config value from KVStore
	fn read_config(&self, key: &str) -> Result<String, io::Error>;
	/// write a wallet config value to KVStore
	fn write_config(&self, key: &str, value: &str);
	/// whether the payment is colored
	fn is_payment_rgb(&self, payment_hash: &PaymentHash) -> bool;
	/// filter first hops to only include channels with sufficient RGB assets
	fn filter_first_hops(&self, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>);
}

impl<K: KVStoreSync + ?Sized> RgbKvStoreExt for K {
	fn read_rgb_transfer_info(&self, txid: &str) -> TransferInfo {
		let data =
			self.read(RGB_PRIMARY_NS, RGB_TRANSFER_INFO_NS, txid).expect("KVStore read failed");
		bincode::deserialize(&data).expect("valid transfer info")
	}

	fn write_rgb_transfer_info(&self, txid: &str, info: &TransferInfo) {
		let data = bincode::serialize(info).expect("valid transfer info");
		self.write(RGB_PRIMARY_NS, RGB_TRANSFER_INFO_NS, txid, data).expect("KVStore write failed");
	}

	fn read_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<RgbInfo, io::Error> {
		let namespace = if pending { RGB_CHANNEL_INFO_PENDING_NS } else { RGB_CHANNEL_INFO_NS };
		let data = self.read(RGB_PRIMARY_NS, namespace, channel_id)?;
		bincode::deserialize(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
	}

	fn write_rgb_channel_info(&self, channel_id: &str, rgb_info: &RgbInfo, pending: bool) {
		let namespace = if pending { RGB_CHANNEL_INFO_PENDING_NS } else { RGB_CHANNEL_INFO_NS };
		let data = bincode::serialize(rgb_info).expect("valid rgb channel info");
		self.write(RGB_PRIMARY_NS, namespace, channel_id, data).expect("KVStore write failed");
	}

	fn read_rgb_payment_info(
		&self, payment_hash: &PaymentHash, inbound: bool,
	) -> Result<RgbPaymentInfo, io::Error> {
		let namespace =
			if inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };
		let key = payment_hash.0.as_hex().to_string();
		let data = self.read(RGB_PRIMARY_NS, namespace, &key)?;
		bincode::deserialize(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
	}

	fn write_rgb_payment_info(&self, payment_hash: &PaymentHash, info: &RgbPaymentInfo) {
		let namespace =
			if info.inbound { RGB_PAYMENT_INFO_INBOUND_NS } else { RGB_PAYMENT_INFO_OUTBOUND_NS };
		let key = payment_hash.0.as_hex().to_string();
		let data = bincode::serialize(info).expect("valid rgb payment info");
		self.write(RGB_PRIMARY_NS, namespace, &key, data).expect("KVStore write failed");
	}

	fn read_rgb_consignment(&self, id: &str) -> Result<Vec<u8>, io::Error> {
		self.read(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, id)
	}

	fn write_rgb_consignment(&self, id: &str, data: Vec<u8>) {
		self.write(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, id, data).expect("KVStore write failed");
	}

	fn remove_rgb_channel_info(&self, channel_id: &str, pending: bool) -> Result<(), io::Error> {
		let namespace = if pending { RGB_CHANNEL_INFO_PENDING_NS } else { RGB_CHANNEL_INFO_NS };
		self.remove(RGB_PRIMARY_NS, namespace, channel_id, false)
	}

	fn remove_rgb_consignment(&self, id: &str) {
		self.remove(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, id, false).expect("KVStore remove failed");
	}

	fn read_config(&self, key: &str) -> Result<String, io::Error> {
		let data = self.read(RGB_PRIMARY_NS, RGB_WALLET_CONFIG_NS, key)?;
		String::from_utf8(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
	}

	fn write_config(&self, key: &str, value: &str) {
		self.write(RGB_PRIMARY_NS, RGB_WALLET_CONFIG_NS, key, value.as_bytes().to_vec())
			.expect("KVStore write failed");
	}

	fn is_payment_rgb(&self, payment_hash: &PaymentHash) -> bool {
		self.read_rgb_payment_info(payment_hash, false).is_ok()
			|| self.read_rgb_payment_info(payment_hash, true).is_ok()
	}

	fn filter_first_hops(&self, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>) {
		let rgb_payment_info = match self.read_rgb_payment_info(payment_hash, false) {
			Ok(info) => info,
			Err(_) => return,
		};
		let contract_id = rgb_payment_info.contract_id;
		let rgb_amount = rgb_payment_info.amount;
		first_hops.retain(|h| {
			let channel_id_str = h.channel_id.0.as_hex().to_string();
			match self.read_rgb_channel_info(&channel_id_str, false) {
				Ok(rgb_info) => {
					rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
				},
				Err(_) => false,
			}
		});
	}
}

thread_local! {
	static HOLDER_VALIDATE_PSBT_WITNESS_SCRIPTS_HEX: RefCell<Option<Vec<String>>> =
		const { RefCell::new(None) };
}

/// Installed by [`crate::ln::channel`] before [`crate::sign::ChannelSigner::validate_holder_commitment`]
/// on RGB-colored holder commitments so an external signer can attach PSBT `witness_script`s for VLS.
pub fn holder_validate_install_psbt_output_witness_scripts_hex(hex_scripts: Vec<String>) {
	HOLDER_VALIDATE_PSBT_WITNESS_SCRIPTS_HEX.with(|c| *c.borrow_mut() = Some(hex_scripts));
}

/// Removes and returns witness script hex strings installed by [`holder_validate_install_psbt_output_witness_scripts_hex`], if any.
pub fn holder_validate_take_psbt_output_witness_scripts_hex() -> Option<Vec<String>> {
	HOLDER_VALIDATE_PSBT_WITNESS_SCRIPTS_HEX.with(|c| c.borrow_mut().take())
}
