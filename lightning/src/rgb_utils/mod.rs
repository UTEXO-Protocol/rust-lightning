//! A module to provide RGB functionality

// this module uses the online APIs of rgb-lib, which are only available if rgb-lib has been built
// with support for at least one indexer protocol
#[cfg(not(any(feature = "electrum", feature = "esplora")))]
compile_error!("at least one of the `electrum` and `esplora` features needs to be enabled");

use crate::chain::transaction::OutPoint;
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
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	keys::WitnessVersion,
	wallet::{
		rust_only::{
			AssetColoringInfo, ColoringInfo, PreparedRgbTransferAcceptance, RgbAcceptanceResolution,
		},
		DatabaseType, OnlineOptions, RgbWalletOpsOffline, SinglesigKeys, Wallet, WalletData,
	},
	AssetSchema, Assignment, BitcoinNetwork, ConsignmentExt, ContractId, Error as RgbLibError,
	Fascia, FileContent, WitnessOrd,
};
use serde::{Deserialize, Serialize};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use tokio::runtime::Handle;

use crate::io;
use core::ops::Deref;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

/// Static blinding constant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
/// Name of the file containing the bitcoin network
pub const BITCOIN_NETWORK_FNAME: &str = "bitcoin_network";
/// Name of the file containing the electrum URL
pub const INDEXER_URL_FNAME: &str = "indexer_url";
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
/// Secondary namespace for durable inbound RGB funding acceptance state.
pub const RGB_FUNDING_ACCEPTANCE_NS: &str = "funding_acceptance";
/// Secondary namespace for inbound payment info
pub const RGB_PAYMENT_INFO_INBOUND_NS: &str = "payment_info_inbound";
/// Secondary namespace for outbound payment info
pub const RGB_PAYMENT_INFO_OUTBOUND_NS: &str = "payment_info_outbound";
/// Secondary namespace for transfer info
pub const RGB_TRANSFER_INFO_NS: &str = "transfer_info";
/// Secondary namespace for consignment data
pub const RGB_CONSIGNMENT_NS: &str = "consignment";
/// Secondary namespace for the latest commitment fascia of each channel
pub const RGB_COMMITMENT_FASCIA_NS: &str = "commitment_fascia";
/// Secondary namespace for wallet configuration
pub const RGB_WALLET_CONFIG_NS: &str = "wallet_config";
const VANILLA_SYNC_LOOKBACK: u32 = 20;

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
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
	/// Whether the channel acceptor told us (in `accept_channel`) that it already knows the asset
	pub counterparty_knows_asset: bool,
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
	/// RGB amount assigned to each output of the transaction, by vout
	pub output_map: HashMap<u32, u64>,
}

/// Durable phase of an inbound RGB channel funding acceptance.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub enum FundingAcceptanceStage {
	/// The RGB consignment is being fetched and validated outside the peer mutex.
	Validating,
	/// The validated RGB result is durable in an isolated staging stock.
	Prepared,
	/// The staged stock is live but retains an exact rollback snapshot.
	Promoted,
	/// A rollback decision was persisted before restoring the prior stock.
	RollingBack,
	/// The embedding node observed durable funded channel state and committed the RGB result.
	Finalized,
	/// Acceptance failed and the funding handshake must be retried from a fresh channel.
	RetryRequired,
	/// The embedding node persisted a commit decision and is applying it to the RGB stock.
	Finalizing,
}

/// Crash evidence for an inbound RGB funding operation.
///
/// The embedding node reconciles this record against durable LDK channel state before deciding
/// whether to commit, roll back, or quarantine an ambiguous promoted funding attempt.
#[derive(Debug, Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingFundingAcceptance {
	/// Persistence schema version.
	pub version: u8,
	/// Temporary channel ID used as the durable record key.
	pub temporary_channel_id: String,
	/// Remote node participating in the funding handshake.
	pub counterparty_node_id: String,
	/// Proposed funding transaction ID.
	pub funding_txid: String,
	/// Funding output index in the proposed transaction.
	pub funding_output_index: u16,
	/// Asset amount pushed to the accepting node.
	pub push_asset_amount: Option<u64>,
	/// Current durable acceptance phase.
	pub stage: FundingAcceptanceStage,
	/// Validated transfer consignment, populated once preparation completes.
	pub consignment: Option<Vec<u8>>,
	/// Derived channel metadata, populated once preparation completes.
	pub rgb_info: Option<RgbInfo>,
}

impl PendingFundingAcceptance {
	const VERSION: u8 = 3;

	/// Returns the stable persistence key.
	pub fn key(&self) -> &str {
		&self.temporary_channel_id
	}

	fn validate(&self) -> Result<(), io::Error> {
		let is_fixed_hex = |value: &str, byte_len: usize| {
			value.len() == byte_len * 2
				&& value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
		};
		if self.version != Self::VERSION
			|| !is_fixed_hex(&self.temporary_channel_id, 32)
			|| !is_fixed_hex(&self.counterparty_node_id, 33)
			|| !is_fixed_hex(&self.funding_txid, 32)
		{
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"invalid RGB funding acceptance journal",
			));
		}
		Ok(())
	}
}

/// Atomically writes the current funding acceptance record.
pub fn write_pending_funding_acceptance(
	record: &PendingFundingAcceptance, kv_store: &dyn KVStoreSync,
) -> Result<(), io::Error> {
	record.validate()?;
	let data =
		bincode::serialize(record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	kv_store.write(RGB_PRIMARY_NS, RGB_FUNDING_ACCEPTANCE_NS, record.key(), data)
}

/// Reads a funding acceptance record by temporary channel ID.
pub fn read_pending_funding_acceptance(
	temporary_channel_id: &str, kv_store: &dyn KVStoreSync,
) -> Result<PendingFundingAcceptance, io::Error> {
	let data = kv_store.read(RGB_PRIMARY_NS, RGB_FUNDING_ACCEPTANCE_NS, temporary_channel_id)?;
	let record: PendingFundingAcceptance =
		bincode::deserialize(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	record.validate()?;
	if record.key() != temporary_channel_id {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"RGB funding acceptance journal key mismatch",
		));
	}
	Ok(record)
}

/// Durably removes a completed funding acceptance record.
pub fn remove_pending_funding_acceptance(
	temporary_channel_id: &str, kv_store: &dyn KVStoreSync,
) -> Result<(), io::Error> {
	kv_store.remove(RGB_PRIMARY_NS, RGB_FUNDING_ACCEPTANCE_NS, temporary_channel_id, false)
}

/// A validated RGB funding acceptance whose live wallet state is still unchanged.
pub(crate) struct PreparedFundingAcceptance {
	prepared: PreparedRgbTransferAcceptance,
	record: PendingFundingAcceptance,
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

async fn _get_rgb_wallet(
	ldk_data_dir: &Path, kv_store: &dyn KVStoreSync,
) -> Result<Wallet, ChannelError> {
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
	.map_err(|error| {
		ChannelError::close(format!("RGB wallet worker failed before completion: {error}"))
	})
}

pub(crate) fn is_asset_known(
	contract_id: ContractId, ldk_data_dir: &Path, kv_store: &dyn KVStoreSync,
) -> bool {
	let handle = Handle::current();
	let _ = handle.enter();
	let Ok(wallet) = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store)) else {
		return false;
	};
	wallet.is_asset_known(contract_id).unwrap_or(false)
}

async fn _prepare_transfer_acceptance(
	operation_id: String, ldk_data_dir: &Path, funding_txid: String, funding_vout: u32,
	kv_store: &dyn KVStoreSync,
) -> Result<(PreparedRgbTransferAcceptance, PathBuf), RgbLibError> {
	let (
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		reuse_addresses,
	) = _get_wallet_data(ldk_data_dir, kv_store);
	let indexer_url = _get_indexer_url(kv_store);
	// the consignment is received from the channel counterparty over the p2p link and written to disk
	let consignment_path = ldk_data_dir.join(format!("consignment_{funding_txid}"));
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
		let consignment_bytes =
			fs::read(&consignment_path).map_err(|_| RgbLibError::InvalidFilePath {
				file_path: consignment_path.to_string_lossy().into_owned(),
			})?;
		let prepared = wallet.prepare_accept_transfer_from_consignment(
			operation_id,
			funding_txid,
			funding_vout,
			consignment_bytes,
			STATIC_BLINDING,
		)?;
		Ok((prepared, wallet.get_media_dir()))
	})
	.await
	.map_err(|error| RgbLibError::Internal {
		details: format!("RGB funding worker failed before completion: {error}"),
	})?
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

/// Deserialize a fascia stored by `color_commitment`
pub fn deserialize_fascia(data: Vec<u8>) -> Result<Fascia, io::Error> {
	let confined = amplify::confinement::Confined::try_from(data)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	Fascia::from_strict_serialized::<{ usize::MAX }>(confined)
		.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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

	let asset_coloring_info = AssetColoringInfo {
		output_map: output_map.clone(),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let operation_id = funding_scope
		.get_funding_txo()
		.ok_or_else(|| {
			ChannelError::close("RGB commitment is missing its funding outpoint".to_owned())
		})?
		.txid
		.to_string();
	let mut psbt = RgbLibPsbt::from_unsigned_tx(commitment_tx.clone()).map_err(|error| {
		ChannelError::close(format!("Failed to construct RGB commitment PSBT: {error}"))
	})?;
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store))?;
	let fascia = wallet
		.color_psbt_and_consume_for_operation(
			&operation_id,
			&mut psbt,
			coloring_info,
			Some(WitnessOrd::Ignored),
		)
		.map_err(funding_acceptance_error)?;
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(error) => {
			return Err(ChannelError::close(format!(
				"Failed to extract colored RGB commitment transaction: {error}"
			)))
		},
	};

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	// Keep the latest fascia per commitment side so a wallet restored without
	// an RGB backup can re-consume it and color force-close sweeps.
	let fascia_key = format!("{}_{}", chan_id, if counterparty { "cp" } else { "local" });
	let fascia_bytes =
		fascia.to_strict_serialized::<{ usize::MAX }>().expect("serializable fascia").release();
	kv_store
		.write(RGB_PRIMARY_NS, RGB_COMMITMENT_FASCIA_NS, &fascia_key, fascia_bytes)
		.expect("KVStore write failed");
	let transfer_info = TransferInfo { contract_id, output_map };
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

	let output_map = HashMap::from([(0, htlc_amount_rgb)]);
	let asset_coloring_info = AssetColoringInfo {
		output_map: output_map.clone(),
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
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store))?;
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};
	let txid = &modified_tx.compute_txid();

	wallet.consume_fascia(fascia.clone(), Some(WitnessOrd::Ignored)).unwrap();

	let transfer_info = TransferInfo { contract_id, output_map };
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

	let asset_coloring_info = AssetColoringInfo {
		output_map: output_map.clone(),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
	};
	let psbt = Psbt::from_unsigned_tx(closing_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir, kv_store))?;
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

	let transfer_info = TransferInfo { contract_id, output_map };
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

/// Renames RGB channel state from a temporary to a final channel ID.
pub(crate) fn try_rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, kv_store: &dyn KVStoreSync,
) -> Result<(), io::Error> {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	for namespace in [RGB_CHANNEL_INFO_NS, RGB_CHANNEL_INFO_PENDING_NS] {
		match kv_store.read(RGB_PRIMARY_NS, namespace, &temp_chan_id) {
			Ok(data) => {
				bincode::deserialize::<RgbInfo>(&data)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
				match kv_store.read(RGB_PRIMARY_NS, namespace, &chan_id) {
					Ok(existing) if existing != data => {
						return Err(io::Error::new(
							io::ErrorKind::InvalidData,
							"final RGB channel metadata differs from temporary metadata",
						));
					},
					Ok(_) => {},
					Err(error) if error.kind() == io::ErrorKind::NotFound => {
						kv_store.write(RGB_PRIMARY_NS, namespace, &chan_id, data)?;
					},
					Err(error) => return Err(error),
				}
				match kv_store.remove(RGB_PRIMARY_NS, namespace, &temp_chan_id, false) {
					Ok(()) => {},
					Err(error) if error.kind() == io::ErrorKind::NotFound => {},
					Err(error) => return Err(error),
				}
			},
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				let data = kv_store.read(RGB_PRIMARY_NS, namespace, &chan_id)?;
				bincode::deserialize::<RgbInfo>(&data)
					.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
			},
			Err(error) => return Err(error),
		}
	}

	match kv_store.read(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, &temp_chan_id) {
		Ok(data) => {
			match kv_store.read(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, &chan_id) {
				Ok(existing) if existing != data => {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"final RGB consignment differs from temporary consignment",
					));
				},
				Ok(_) => {},
				Err(error) if error.kind() == io::ErrorKind::NotFound => {
					kv_store.write(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, &chan_id, data)?;
				},
				Err(error) => return Err(error),
			}
			match kv_store.remove(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, &temp_chan_id, false) {
				Ok(()) => {},
				Err(error) if error.kind() == io::ErrorKind::NotFound => {},
				Err(error) => return Err(error),
			}
		},
		Err(error) if error.kind() == io::ErrorKind::NotFound => {},
		Err(error) => return Err(error),
	}
	// The funding-acceptance journal intentionally remains keyed by the temporary channel ID.
	// RLN removes it only after both the finalized RGB wallet and canonical channel metadata have
	// been acknowledged by VSS. Deleting it here would make a crash between ChannelMonitor
	// persistence and RLN event handling unrecoverable on a fresh device.
	Ok(())
}

/// Renames RGB channel state while preserving the legacy fail-stop behavior.
pub(crate) fn rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, kv_store: &dyn KVStoreSync,
) {
	try_rename_rgb_files(channel_id, temporary_channel_id, kv_store)
		.expect("RGB channel ID transition must persist");
}

fn funding_acceptance_error(error: RgbLibError) -> ChannelError {
	match error {
		RgbLibError::InvalidConsignment => {
			ChannelError::close("Invalid RGB consignment for funding".to_owned())
		},
		RgbLibError::NoConsignment => {
			ChannelError::close("Failed to find RGB consignment".to_owned())
		},
		RgbLibError::UnknownRgbSchema { schema_id } => {
			ChannelError::close(format!("Unknown RGB schema: {schema_id}"))
		},
		RgbLibError::UnsupportedSchema { asset_schema } => {
			ChannelError::close(format!("Unsupported RGB schema: {asset_schema}"))
		},
		RgbLibError::Indexer { details }
		| RgbLibError::InvalidIndexer { details }
		| RgbLibError::Network { details } => {
			ChannelError::close(format!("Failed to connect to indexer: {details}"))
		},
		error => ChannelError::close(format!("Unexpected RGB funding error: {error}")),
	}
}

/// Directory holding the media received for a funding, before the contract has vouched for it.
pub fn get_media_staging_dir(ldk_data_dir: &Path, funding_txid: &str) -> PathBuf {
	ldk_data_dir.join(format!("media_staging_{funding_txid}"))
}

fn funding_storage_error(context: &str, error: impl core::fmt::Display) -> ChannelError {
	ChannelError::close(format!("{context}: {error}"))
}

fn persist_retry_required(
	record: &mut PendingFundingAcceptance, kv_store: &dyn KVStoreSync, context: &str,
) -> Result<(), ChannelError> {
	record.stage = FundingAcceptanceStage::RetryRequired;
	// Retry evidence only needs the operation identity and handshake inputs. Retaining a complete
	// validated consignment after rollback would grow storage with the asset's full history and keep
	// data which no longer participates in recovery.
	record.consignment = None;
	record.rgb_info = None;
	write_pending_funding_acceptance(record, kv_store)
		.map_err(|error| funding_storage_error(context, error))
}

fn persist_prepared_funding_artifacts(
	record: &PendingFundingAcceptance, kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let consignment = record.consignment.as_ref().ok_or_else(|| {
		ChannelError::close("Prepared RGB funding is missing its consignment".to_owned())
	})?;
	let rgb_info = record.rgb_info.as_ref().ok_or_else(|| {
		ChannelError::close("Prepared RGB funding is missing channel metadata".to_owned())
	})?;
	let serialized_info = bincode::serialize(rgb_info).map_err(|error| {
		funding_storage_error("Failed to serialize RGB channel metadata", error)
	})?;
	for namespace in [RGB_CHANNEL_INFO_PENDING_NS, RGB_CHANNEL_INFO_NS] {
		kv_store
			.write(RGB_PRIMARY_NS, namespace, &record.temporary_channel_id, serialized_info.clone())
			.map_err(|error| {
				funding_storage_error("Failed to stage RGB channel metadata", error)
			})?;
	}
	for key in [&record.funding_txid, &record.temporary_channel_id] {
		kv_store
			.write(RGB_PRIMARY_NS, RGB_CONSIGNMENT_NS, key, consignment.clone())
			.map_err(|error| funding_storage_error("Failed to stage RGB consignment", error))?;
	}
	Ok(())
}

fn remove_if_present(
	kv_store: &dyn KVStoreSync, secondary_namespace: &str, key: &str,
) -> Result<(), ChannelError> {
	match kv_store.remove(RGB_PRIMARY_NS, secondary_namespace, key, false) {
		Ok(()) => Ok(()),
		Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
		Err(error) => Err(funding_storage_error("Failed to remove staged RGB funding data", error)),
	}
}

fn clear_prepared_funding_artifacts(
	record: &PendingFundingAcceptance, kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let funding_txid = bitcoin::Txid::from_str(&record.funding_txid).map_err(|error| {
		ChannelError::close(format!("Invalid funding transaction ID in RGB journal: {error}"))
	})?;
	let final_channel_id = ChannelId::v1_from_funding_outpoint(OutPoint {
		txid: funding_txid,
		index: record.funding_output_index,
	});
	let final_channel_id = final_channel_id.0.as_hex().to_string();
	for namespace in [RGB_CHANNEL_INFO_PENDING_NS, RGB_CHANNEL_INFO_NS] {
		remove_if_present(kv_store, namespace, &record.temporary_channel_id)?;
		remove_if_present(kv_store, namespace, &final_channel_id)?;
	}
	for key in [&record.funding_txid, &record.temporary_channel_id, &final_channel_id] {
		remove_if_present(kv_store, RGB_CONSIGNMENT_NS, key)?;
	}
	Ok(())
}

fn abort_prepared_with_record(
	prepared: PreparedRgbTransferAcceptance, record: &mut PendingFundingAcceptance,
	kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	record.stage = FundingAcceptanceStage::RollingBack;
	write_pending_funding_acceptance(record, kv_store)
		.map_err(|error| funding_storage_error("Failed to persist RGB rollback decision", error))?;
	prepared.abort().map_err(funding_acceptance_error)?;
	clear_prepared_funding_artifacts(record, kv_store)?;
	persist_retry_required(record, kv_store, "Failed to persist RGB retry decision")
}

fn install_funding_media(
	media_digests: &HashSet<String>, media_dir: &Path, ldk_data_dir: &Path, funding_txid: &str,
) -> Result<(), ChannelError> {
	let staging_dir = get_media_staging_dir(ldk_data_dir, funding_txid);
	let mut pending_moves = Vec::new();
	for digest in media_digests {
		let media_path = media_dir.join(digest);
		if media_path.exists() {
			continue;
		}
		let staged_path = staging_dir.join(digest);
		let media_bytes = fs::read(&staged_path).map_err(|_| {
			ChannelError::close(format!("Missing RGB media file {digest} for funding"))
		})?;
		if sha256::Hash::hash(&media_bytes).to_string() != *digest {
			return Err(ChannelError::close(format!(
				"Corrupt RGB media file {digest} for funding"
			)));
		}
		pending_moves.push((staged_path, media_path));
	}
	for (staged_path, media_path) in pending_moves {
		fs::rename(&staged_path, &media_path).map_err(|error| {
			ChannelError::close(format!(
				"Failed to store RGB media file {} for funding: {error}",
				staged_path.display()
			))
		})?;
	}
	let _ = fs::remove_dir_all(staging_dir);
	Ok(())
}

/// Validates RGB funding into an isolated stock without changing the live wallet.
pub(crate) fn prepare_funding(
	temporary_channel_id: &ChannelId, funding_txid: String, ldk_data_dir: &Path,
	funding_output_index: u16, counterparty_node_id: &PublicKey, push_asset_amount: Option<u64>,
	kv_store: &dyn KVStoreSync,
) -> Result<PreparedFundingAcceptance, ChannelError> {
	let temporary_channel_id = temporary_channel_id.0.as_hex().to_string();
	let mut record = PendingFundingAcceptance {
		version: PendingFundingAcceptance::VERSION,
		temporary_channel_id,
		counterparty_node_id: counterparty_node_id.to_string(),
		funding_txid: funding_txid.clone(),
		funding_output_index,
		push_asset_amount,
		stage: FundingAcceptanceStage::Validating,
		consignment: None,
		rgb_info: None,
	};
	write_pending_funding_acceptance(&record, kv_store)
		.map_err(|error| funding_storage_error("Failed to persist RGB funding intent", error))?;

	let handle = Handle::current();
	let _runtime_guard = handle.enter();
	let (prepared, media_dir) = match futures::executor::block_on(_prepare_transfer_acceptance(
		funding_txid.clone(),
		ldk_data_dir,
		funding_txid.clone(),
		funding_output_index as u32,
		kv_store,
	)) {
		Ok(prepared) => prepared,
		Err(error) => {
			persist_retry_required(
				&mut record,
				kv_store,
				"Failed to persist rejected RGB funding validation",
			)?;
			return Err(funding_acceptance_error(error));
		},
	};

	let prepared_data = (|| {
		let mut consignment_buf = Vec::new();
		prepared
			.consignment()
			.save(&mut consignment_buf)
			.map_err(|error| funding_storage_error("Failed to serialize RGB consignment", error))?;
		if prepared.assignments().len() != 1 {
			return Err(ChannelError::close(format!(
				"Unexpected number of RGB assignments: {}",
				prepared.assignments().len()
			)));
		}
		let channel_rgb_amount = match prepared.assignments()[0] {
			Assignment::Fungible(amount) => amount,
			Assignment::NonFungible => 1,
			_ => unreachable!("unsupported schema"),
		};
		let push_amount = push_asset_amount.unwrap_or(0);
		let remote_rgb_amount = channel_rgb_amount.checked_sub(push_amount).ok_or_else(|| {
			ChannelError::close(format!(
				"RGB push amount {push_amount} exceeds received channel amount {channel_rgb_amount}"
			))
		})?;
		let schema =
			AssetSchema::from_schema_id(prepared.consignment().schema_id()).map_err(|error| {
				ChannelError::close(format!("Unsupported RGB funding schema: {error}"))
			})?;
		install_funding_media(prepared.media_digests(), &media_dir, ldk_data_dir, &funding_txid)?;
		Ok((
			consignment_buf,
			RgbInfo {
				contract_id: prepared.consignment().contract_id(),
				schema,
				local_rgb_amount: push_amount,
				remote_rgb_amount,
				batch_transfer_idx: None,
				counterparty_knows_asset: false,
			},
		))
	})();
	let (consignment_buf, rgb_info) = match prepared_data {
		Ok(data) => data,
		Err(error) => {
			abort_prepared_with_record(prepared, &mut record, kv_store)?;
			return Err(error);
		},
	};
	record.stage = FundingAcceptanceStage::Prepared;
	record.consignment = Some(consignment_buf);
	record.rgb_info = Some(rgb_info);
	if let Err(error) = write_pending_funding_acceptance(&record, kv_store)
		.map_err(|error| funding_storage_error("Failed to persist prepared RGB funding", error))
		.and_then(|_| persist_prepared_funding_artifacts(&record, kv_store))
	{
		abort_prepared_with_record(prepared, &mut record, kv_store)?;
		return Err(error);
	}
	Ok(PreparedFundingAcceptance { prepared, record })
}

/// Promotes a prepared RGB stock while retaining its rollback snapshot.
pub(crate) fn promote_funding(
	acceptance: PreparedFundingAcceptance, kv_store: &dyn KVStoreSync,
) -> Result<String, ChannelError> {
	let PreparedFundingAcceptance { prepared, mut record } = acceptance;
	let promoted = prepared.promote().map_err(funding_acceptance_error)?;
	record.stage = FundingAcceptanceStage::Promoted;
	if let Err(error) = write_pending_funding_acceptance(&record, kv_store)
		.map_err(|error| funding_storage_error("Failed to persist promoted RGB funding", error))
	{
		promoted.resolve(RgbAcceptanceResolution::Rollback).map_err(funding_acceptance_error)?;
		clear_prepared_funding_artifacts(&record, kv_store)?;
		persist_retry_required(
			&mut record,
			kv_store,
			"Failed to persist RGB funding retry after promotion rollback",
		)?;
		return Err(error);
	}
	Ok(record.temporary_channel_id)
}

/// Discards a prepared acceptance after durably recording the retry decision.
pub(crate) fn abort_prepared_funding(
	acceptance: PreparedFundingAcceptance, kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let PreparedFundingAcceptance { prepared, mut record } = acceptance;
	abort_prepared_with_record(prepared, &mut record, kv_store)
}

fn wallet_for_rgb_resolution(ldk_data_dir: &Path, kv_store: &dyn KVStoreSync) -> Wallet {
	let (
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		reuse_addresses,
	) = _get_wallet_data(ldk_data_dir, kv_store);
	_new_rgb_wallet(
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		reuse_addresses,
	)
}

/// Rolls back a funding acceptance before `funding_signed` can be released.
pub(crate) fn rollback_funding(
	temporary_channel_id: &str, ldk_data_dir: &Path, kv_store: &dyn KVStoreSync,
) -> Result<(), ChannelError> {
	let mut record = read_pending_funding_acceptance(temporary_channel_id, kv_store)
		.map_err(|error| funding_storage_error("Failed to load RGB funding rollback", error))?;
	record.stage = FundingAcceptanceStage::RollingBack;
	write_pending_funding_acceptance(&record, kv_store)
		.map_err(|error| funding_storage_error("Failed to persist RGB rollback decision", error))?;
	let wallet = wallet_for_rgb_resolution(ldk_data_dir, kv_store);
	if wallet.pending_rgb_acceptance().map_err(funding_acceptance_error)?.is_some() {
		wallet
			.resolve_pending_rgb_acceptance(&record.funding_txid, RgbAcceptanceResolution::Rollback)
			.map_err(funding_acceptance_error)?;
	}
	clear_prepared_funding_artifacts(&record, kv_store)?;
	persist_retry_required(&mut record, kv_store, "Failed to persist RGB retry decision")
}

pub(crate) fn set_counterparty_knows_asset(channel_id: &ChannelId, kv_store: &dyn KVStoreSync) {
	let channel_id = channel_id.0.as_hex().to_string();
	for pending in [true, false] {
		if let Ok(mut rgb_info) = kv_store.read_rgb_channel_info(&channel_id, pending) {
			rgb_info.counterparty_knows_asset = true;
			kv_store.write_rgb_channel_info(&channel_id, &rgb_info, pending);
		}
	}
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

#[cfg(test)]
mod funding_acceptance_tests {
	use super::*;
	use crate::util::test_utils::TestStore;

	fn record(stage: FundingAcceptanceStage) -> PendingFundingAcceptance {
		PendingFundingAcceptance {
			version: PendingFundingAcceptance::VERSION,
			temporary_channel_id: "01".repeat(32),
			counterparty_node_id: "02".repeat(33),
			funding_txid: "03".repeat(32),
			funding_output_index: 0,
			push_asset_amount: Some(500),
			stage,
			consignment: None,
			rgb_info: None,
		}
	}

	#[test]
	fn pending_funding_state_survives_reopen() {
		let store = TestStore::new(false);
		let validating = record(FundingAcceptanceStage::Validating);
		write_pending_funding_acceptance(&validating, &store).unwrap();

		let after_reopen = read_pending_funding_acceptance(validating.key(), &store).unwrap();
		assert_eq!(after_reopen, validating);

		remove_pending_funding_acceptance(validating.key(), &store).unwrap();
		assert!(read_pending_funding_acceptance(validating.key(), &store).is_err());
	}

	#[test]
	fn pending_funding_state_rejects_malformed_identity() {
		let store = TestStore::new(false);
		let mut malformed = record(FundingAcceptanceStage::Validating);
		malformed.funding_txid = "zz".repeat(32);
		assert!(write_pending_funding_acceptance(&malformed, &store).is_err());
	}

	#[test]
	fn channel_rename_retains_promoted_funding_journal_for_application_reconciliation() {
		let store = TestStore::new(false);
		let temporary_channel_id = ChannelId::from_bytes([1; 32]);
		let channel_id = ChannelId::from_bytes([2; 32]);
		let temporary_channel_id_hex = temporary_channel_id.0.as_hex().to_string();
		let info = RgbInfo {
			contract_id: ContractId::from_str(
				"rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E",
			)
			.unwrap(),
			schema: AssetSchema::Nia,
			local_rgb_amount: 500,
			remote_rgb_amount: 0,
			batch_transfer_idx: None,
			counterparty_knows_asset: false,
		};
		store.write_rgb_channel_info(&temporary_channel_id_hex, &info, false);
		store.write_rgb_channel_info(&temporary_channel_id_hex, &info, true);
		let mut promoted = record(FundingAcceptanceStage::Promoted);
		promoted.temporary_channel_id = temporary_channel_id_hex.clone();
		write_pending_funding_acceptance(&promoted, &store).unwrap();

		try_rename_rgb_files(&channel_id, &temporary_channel_id, &store).unwrap();

		assert_eq!(
			read_pending_funding_acceptance(&temporary_channel_id_hex, &store).unwrap(),
			promoted,
		);
		assert_eq!(
			store.read_rgb_channel_info(&channel_id.0.as_hex().to_string(), false).unwrap(),
			info,
		);
		try_rename_rgb_files(&channel_id, &temporary_channel_id, &store).unwrap();
	}

	#[test]
	fn channel_rename_reports_missing_metadata_without_panicking() {
		let store = TestStore::new(false);
		let temporary_channel_id = ChannelId::from_bytes([1; 32]);
		let channel_id = ChannelId::from_bytes([2; 32]);

		let error = try_rename_rgb_files(&channel_id, &temporary_channel_id, &store).unwrap_err();
		assert_eq!(error.kind(), io::ErrorKind::NotFound);
	}
}
