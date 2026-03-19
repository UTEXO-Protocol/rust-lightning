//! A module to provide RGB functionality

use crate::ln::chan_utils::{
	get_countersigner_payment_script, BuiltCommitmentTransaction, ClosingTransaction,
	CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{ChannelContext, ChannelError, FundingScope};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::MsgHandleErrInternal;
use crate::ln::types::ChannelId;
use crate::sign::SignerProvider;
use crate::types::features::ChannelTypeFeatures;
use crate::types::payment::PaymentHash;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hex::DisplayHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::PublicKey;
use bitcoin::TxOut;
use rgb_lib::{
	bitcoin::psbt::Psbt as RgbLibPsbt,
	wallet::{
		rust_only::{AssetColoringInfo, ColoringInfo},
		DatabaseType, WalletData,
	},
	AssetSchema, Assignment, BitcoinNetwork, ConsignmentExt, ContractId, Error as RgbLibError,
	FileContent, RgbTransfer, RgbTransport, RgbTxid, Wallet, WitnessOrd,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use core::ops::Deref;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Static blinding costant (will be removed in the future)
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
const INBOUND_EXT: &str = "inbound";
const OUTBOUND_EXT: &str = "outbound";
const VIRTUAL_CHANNEL_MARKER_PREFIX: &str = "virtual_channel_";

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

fn _get_file_in_parent(ldk_data_dir: &Path, fname: &str) -> PathBuf {
	ldk_data_dir.parent().unwrap().join(fname)
}

fn _read_file_in_parent(ldk_data_dir: &Path, fname: &str) -> String {
	fs::read_to_string(_get_file_in_parent(ldk_data_dir, fname)).unwrap()
}

fn _get_rgb_wallet_dir(ldk_data_dir: &Path) -> PathBuf {
	let fingerprint = _read_file_in_parent(ldk_data_dir, WALLET_FINGERPRINT_FNAME);
	_get_file_in_parent(ldk_data_dir, &fingerprint)
}

fn _get_bitcoin_network(ldk_data_dir: &Path) -> BitcoinNetwork {
	let bitcoin_network = _read_file_in_parent(ldk_data_dir, BITCOIN_NETWORK_FNAME);
	BitcoinNetwork::from_str(&bitcoin_network).unwrap()
}

fn _get_account_xpub_colored(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_ACCOUNT_XPUB_COLORED_FNAME)
}

fn _get_account_xpub_vanilla(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_ACCOUNT_XPUB_VANILLA_FNAME)
}

fn _get_master_fingerprint(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_MASTER_FINGERPRINT_FNAME)
}

fn _get_indexer_url(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, INDEXER_URL_FNAME)
}

fn _new_rgb_wallet(
	data_dir: String, bitcoin_network: BitcoinNetwork, account_xpub_vanilla: String,
	account_xpub_colored: String, master_fingerprint: String,
) -> Wallet {
	Wallet::new(WalletData {
		data_dir,
		bitcoin_network,
		database_type: DatabaseType::Sqlite,
		max_allocations_per_utxo: 1,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		mnemonic: None,
		vanilla_keychain: None,
		supported_schemas: vec![AssetSchema::Nia, AssetSchema::Cfa, AssetSchema::Uda],
	})
	.expect("valid rgb-lib wallet")
}

fn _get_wallet_data(ldk_data_dir: &Path) -> (String, BitcoinNetwork, String, String, String) {
	let data_dir = ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
	let bitcoin_network = _get_bitcoin_network(ldk_data_dir);
	let account_xpub_vanilla = _get_account_xpub_vanilla(ldk_data_dir);
	let account_xpub_colored = _get_account_xpub_colored(ldk_data_dir);
	let master_fingerprint = _get_master_fingerprint(ldk_data_dir);
	(data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint)
}

async fn _get_rgb_wallet(ldk_data_dir: &Path) -> Wallet {
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);
	tokio::task::spawn_blocking(move || {
		_new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
		)
	})
	.await
	.unwrap()
}

async fn _accept_transfer(
	ldk_data_dir: &Path, funding_txid: String, consignment_endpoint: RgbTransport,
) -> Result<(RgbTransfer, Vec<Assignment>), RgbLibError> {
	let funding_vout = 1;
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);
	let indexer_url = _get_indexer_url(ldk_data_dir);
	tokio::task::spawn_blocking(move || {
		let mut wallet = _new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
		);
		wallet.go_online(true, indexer_url).unwrap();
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

/// Read TransferInfo file
pub fn read_rgb_transfer_info(path: &Path) -> TransferInfo {
	let serialized_info = fs::read_to_string(path).expect("able to read transfer info file");
	serde_json::from_str(&serialized_info).expect("valid transfer info")
}

/// Write TransferInfo file
pub fn write_rgb_transfer_info(path: &PathBuf, info: &TransferInfo) {
	let serialized_info = serde_json::to_string(&info).expect("valid transfer info");
	fs::write(path, serialized_info).expect("able to write transfer info file")
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

	let commitment_tx = commitment_transaction.clone().built.transaction;

	let (rgb_info, _) = get_rgb_channel_info_pending(channel_id, ldk_data_dir);
	let contract_id = rgb_info.contract_id;

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
		let mut rgb_payment_info_path = ldk_data_dir.join(htlc_payment_hash);
		if inbound {
			rgb_payment_info_path.set_extension(INBOUND_EXT);
		} else {
			rgb_payment_info_path.set_extension(OUTBOUND_EXT);
		}
		let rgb_payment_info_tmp_path =
			get_rgb_payment_info_pending_path(&htlc.payment_hash, ldk_data_dir, inbound);
		let channel_rgb_payment_info_path = get_rgb_channel_payment_info_path(
			channel_id,
			&htlc.payment_hash,
			ldk_data_dir,
			inbound,
			false,
		);
		let channel_pending_rgb_payment_info_path = get_rgb_channel_payment_info_path(
			channel_id,
			&htlc.payment_hash,
			ldk_data_dir,
			inbound,
			true,
		);
		let is_compatible_rgb_payment_info = |rgb_payment_info: &RgbPaymentInfo| {
			rgb_payment_info.contract_id == contract_id
				&& rgb_payment_info.amount == htlc_amount_rgb
				&& rgb_payment_info.inbound == inbound
		};

		let mut rgb_payment_info = None;
		let mut should_persist_channel_info = false;
		let mut used_raw_rgb_payment_info_tmp = false;

		if channel_rgb_payment_info_path.exists() {
			let candidate = parse_rgb_payment_info(&channel_rgb_payment_info_path);
			if is_compatible_rgb_payment_info(&candidate) {
				rgb_payment_info = Some(candidate);
			}
		}
		if rgb_payment_info.is_none() && channel_pending_rgb_payment_info_path.exists() {
			let candidate = parse_rgb_payment_info(&channel_pending_rgb_payment_info_path);
			if is_compatible_rgb_payment_info(&candidate) {
				rgb_payment_info = Some(candidate);
				should_persist_channel_info = true;
			}
		}
		if rgb_payment_info.is_none() && rgb_payment_info_tmp_path.exists() {
			let candidate = parse_rgb_payment_info(&rgb_payment_info_tmp_path);
			if is_compatible_rgb_payment_info(&candidate) {
				rgb_payment_info = Some(candidate);
				should_persist_channel_info = true;
				used_raw_rgb_payment_info_tmp = true;
			}
		}
		if rgb_payment_info.is_none() && rgb_payment_info_path.exists() {
			let candidate = parse_rgb_payment_info(&rgb_payment_info_path);
			if is_compatible_rgb_payment_info(&candidate) {
				rgb_payment_info = Some(candidate);
				should_persist_channel_info = true;
			}
		}
		let mut rgb_payment_info = rgb_payment_info.unwrap_or_else(|| {
			should_persist_channel_info = true;
			let rgb_payment_info = RgbPaymentInfo {
				contract_id,
				amount: htlc_amount_rgb,
				local_rgb_amount: rgb_info.local_rgb_amount,
				remote_rgb_amount: rgb_info.remote_rgb_amount,
				swap_payment: true,
				inbound,
			};
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(&rgb_payment_info_path, serialized_info)
				.expect("able to write rgb payment info file");
			rgb_payment_info
		});
		if should_persist_channel_info {
			rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
			rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(&channel_rgb_payment_info_path, serialized_info.clone())
				.expect("able to write rgb payment info file");
			fs::write(&channel_pending_rgb_payment_info_path, serialized_info)
				.expect("able to write rgb payment info file");
			if used_raw_rgb_payment_info_tmp && rgb_payment_info_tmp_path.exists() {
				fs::remove_file(&rgb_payment_info_tmp_path).expect("able to remove file");
			}
		}

		if !channel_pending_rgb_payment_info_path.exists() {
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(&channel_pending_rgb_payment_info_path, serialized_info)
				.expect("able to write rgb payment info file");
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
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to disk
	let rgb_amount = if counterparty {
		vout_p2wpkh_amt + rgb_offered_htlc
	} else {
		vout_p2wsh_amt + rgb_received_htlc
	};
	let transfer_info = TransferInfo { contract_id, rgb_amount };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(
	htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, ldk_data_dir: &Path,
) -> Result<(), ChannelError> {
	if htlc.rgb_payment.is_none_or(|(_, a)| a == 0) {
		return Ok(());
	}
	let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid.to_string();

	let transfer_info_path = ldk_data_dir.join(format!("{commitment_txid}_transfer_info"));
	let transfer_info = read_rgb_transfer_info(&transfer_info_path);
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
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};
	let txid = &modified_tx.compute_txid();

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(
	channel_id: &ChannelId, closing_transaction: &mut ClosingTransaction, ldk_data_dir: &Path,
) -> Result<(), ChannelError> {
	let closing_tx = closing_transaction.clone().built;

	let (rgb_info, _) = get_rgb_channel_info_pending(channel_id, ldk_data_dir);
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
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = &modified_tx.compute_txid();
	closing_transaction.built = modified_tx;

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, rgb_amount: holder_vout_amount };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Get RgbPaymentInfo file path
pub fn get_rgb_payment_info_path(
	payment_hash: &PaymentHash, ldk_data_dir: &Path, inbound: bool,
) -> PathBuf {
	let mut path = ldk_data_dir.join(payment_hash.0.as_hex().to_string());
	path.set_extension(if inbound { INBOUND_EXT } else { OUTBOUND_EXT });
	path
}

/// Get pending RgbPaymentInfo file path scoped only to the payment hash.
pub fn get_rgb_payment_info_pending_path(
	payment_hash: &PaymentHash, ldk_data_dir: &Path, inbound: bool,
) -> PathBuf {
	_append_pending_extension(&get_rgb_payment_info_path(payment_hash, ldk_data_dir, inbound))
}

/// Get channel-scoped RgbPaymentInfo file path for a payment attached to a concrete channel.
pub fn get_rgb_channel_payment_info_path(
	channel_id: &ChannelId, payment_hash: &PaymentHash, ldk_data_dir: &Path, inbound: bool,
	pending: bool,
) -> PathBuf {
	let mut path =
		ldk_data_dir.join(format!("{}{}", channel_id.0.as_hex(), payment_hash.0.as_hex()));
	path.set_extension(if inbound { INBOUND_EXT } else { OUTBOUND_EXT });
	if pending {
		_append_pending_extension(&path)
	} else {
		path
	}
}

/// Parse RgbPaymentInfo
pub fn parse_rgb_payment_info(rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
	let serialized_info =
		fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Get RgbInfo file path
pub fn get_rgb_channel_info_path(channel_id: &str, ldk_data_dir: &Path, pending: bool) -> PathBuf {
	let mut info_file_path = ldk_data_dir.join(channel_id);
	if pending {
		info_file_path.set_extension("pending");
	}
	info_file_path
}

/// Get RgbInfo file
pub(crate) fn get_rgb_channel_info(
	channel_id: &str, ldk_data_dir: &Path, pending: bool,
) -> (RgbInfo, PathBuf) {
	let info_file_path = get_rgb_channel_info_path(channel_id, ldk_data_dir, pending);
	let info = parse_rgb_channel_info(&info_file_path);
	(info, info_file_path)
}

/// Get pending RgbInfo file
pub fn get_rgb_channel_info_pending(
	channel_id: &ChannelId, ldk_data_dir: &Path,
) -> (RgbInfo, PathBuf) {
	get_rgb_channel_info(&channel_id.0.as_hex().to_string(), ldk_data_dir, true)
}

/// Get marker file path used to identify trusted virtual channels for routing policy.
pub fn get_virtual_channel_marker_path(channel_id: &str, ldk_data_dir: &Path) -> PathBuf {
	ldk_data_dir.join(format!("{VIRTUAL_CHANNEL_MARKER_PREFIX}{channel_id}"))
}

/// Parse RgbInfo
pub fn parse_rgb_channel_info(rgb_channel_info_path: &PathBuf) -> RgbInfo {
	let serialized_info = fs::read_to_string(rgb_channel_info_path).expect("valid rgb info file");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Whether the channel data for a channel exist
pub fn is_channel_rgb(channel_id: &ChannelId, ldk_data_dir: &Path) -> bool {
	get_rgb_channel_info_path(&channel_id.0.as_hex().to_string(), ldk_data_dir, false).exists()
}

/// Write RgbInfo file
pub fn write_rgb_channel_info(path: &PathBuf, rgb_info: &RgbInfo) {
	let serialized_info = serde_json::to_string(&rgb_info).expect("valid rgb info");
	fs::write(path, serialized_info).expect("able to write")
}

fn _append_pending_extension(path: &Path) -> PathBuf {
	let mut new_path = path.to_path_buf();
	new_path.set_extension(format!("{}_pending", new_path.extension().unwrap().to_string_lossy()));
	new_path
}

/// Write RGB payment info to file
pub fn write_rgb_payment_info_file(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64,
	swap_payment: bool, inbound: bool,
) {
	let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir, inbound);
	let rgb_payment_info_tmp_path =
		get_rgb_payment_info_pending_path(payment_hash, ldk_data_dir, inbound);
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		swap_payment,
		inbound,
	};
	let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
	std::fs::write(rgb_payment_info_path, serialized_info.clone())
		.expect("able to write rgb payment info file");
	std::fs::write(rgb_payment_info_tmp_path, serialized_info)
		.expect("able to write rgb payment info tmp file");
}

/// Rename RGB files from temporary to final channel ID
pub(crate) fn rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, ldk_data_dir: &Path,
) {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	fs::rename(
		get_rgb_channel_info_path(&temp_chan_id, ldk_data_dir, false),
		get_rgb_channel_info_path(&chan_id, ldk_data_dir, false),
	)
	.expect("rename ok");
	fs::rename(
		get_rgb_channel_info_path(&temp_chan_id, ldk_data_dir, true),
		get_rgb_channel_info_path(&chan_id, ldk_data_dir, true),
	)
	.expect("rename ok");

	let funding_consignment_tmp = ldk_data_dir.join(format!("consignment_{}", temp_chan_id));
	if funding_consignment_tmp.exists() {
		let funding_consignment = ldk_data_dir.join(format!("consignment_{}", chan_id));
		fs::rename(funding_consignment_tmp, funding_consignment).expect("rename ok");
	}
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding(
	temporary_channel_id: &ChannelId, funding_txid: String, ldk_data_dir: &Path,
	consignment_endpoint: RgbTransport, push_asset_amount: Option<u64>,
) -> Result<(), MsgHandleErrInternal> {
	let handle = Handle::current();
	let _ = handle.enter();
	let accept_res = futures::executor::block_on(_accept_transfer(
		ldk_data_dir,
		funding_txid.clone(),
		consignment_endpoint,
	));
	let (consignment, remote_rgb_assignments) = match accept_res {
		Ok(res) => res,
		Err(RgbLibError::InvalidConsignment) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Invalid RGB consignment for funding".to_owned(),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::NoConsignment) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Failed to find RGB consignment".to_owned(),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::UnknownRgbSchema { schema_id }) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unknown RGB schema: {schema_id}"),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::UnsupportedSchema { asset_schema }) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unsupported RGB schema: {asset_schema}"),
				*temporary_channel_id,
			))
		},
		Err(e) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unexpected error: {e}"),
				*temporary_channel_id,
			))
		},
	};

	let consignment_path = ldk_data_dir.join(format!("consignment_{}", funding_txid));
	consignment.save_file(consignment_path).expect("unable to write file");
	let consignment_path =
		ldk_data_dir.join(format!("consignment_{}", temporary_channel_id.0.as_hex()));
	consignment.save_file(consignment_path).expect("unable to write file");

	if remote_rgb_assignments.len() != 1 {
		return Err(MsgHandleErrInternal::send_err_msg_no_close(
			format!("Unexpected number of RGB assignments: {}", remote_rgb_assignments.len()),
			*temporary_channel_id,
		));
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
	};
	let temporary_channel_id_str = temporary_channel_id.0.as_hex().to_string();
	write_rgb_channel_info(
		&get_rgb_channel_info_path(&temporary_channel_id_str, ldk_data_dir, true),
		&rgb_info,
	);
	write_rgb_channel_info(
		&get_rgb_channel_info_path(&temporary_channel_id_str, ldk_data_dir, false),
		&rgb_info,
	);

	Ok(())
}

/// Update RGB channel amount
pub fn update_rgb_channel_amount(
	channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
	pending: bool,
) {
	let (mut rgb_info, info_file_path) = get_rgb_channel_info(channel_id, ldk_data_dir, pending);

	if rgb_offered_htlc > rgb_received_htlc {
		let spent = rgb_offered_htlc - rgb_received_htlc;
		rgb_info.local_rgb_amount -= spent;
		rgb_info.remote_rgb_amount += spent;
	} else {
		let received = rgb_received_htlc - rgb_offered_htlc;
		rgb_info.local_rgb_amount += received;
		rgb_info.remote_rgb_amount -= received;
	}

	write_rgb_channel_info(&info_file_path, &rgb_info)
}

/// Update pending RGB channel amount
pub(crate) fn update_rgb_channel_amount_pending(
	channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
) {
	update_rgb_channel_amount(
		&channel_id.0.as_hex().to_string(),
		rgb_offered_htlc,
		rgb_received_htlc,
		ldk_data_dir,
		true,
	)
}

/// Whether the payment is colored
pub(crate) fn is_payment_rgb(ldk_data_dir: &Path, payment_hash: &PaymentHash) -> bool {
	get_rgb_payment_info_path(payment_hash, ldk_data_dir, false).exists()
		|| get_rgb_payment_info_path(payment_hash, ldk_data_dir, true).exists()
}

/// Detect the contract ID of the payment and then filter hops based on contract ID and amount
pub(crate) fn filter_first_hops(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
) -> (ContractId, u64) {
	let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir, false);
	let rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_path);
	let contract_id = rgb_payment_info.contract_id;
	let rgb_amount = rgb_payment_info.amount;
	first_hops.retain(|h| {
		let info_file_path = ldk_data_dir.join(h.channel_id.0.as_hex().to_string());
		if !info_file_path.exists() {
			return false;
		}
		let serialized_info = fs::read_to_string(info_file_path).expect("valid rgb info file");
		let rgb_info: RgbInfo =
			serde_json::from_str(&serialized_info).expect("valid rgb info file");
		rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
	});
	let has_virtual_rgb_hop = first_hops.iter().any(|h| {
		let marker =
			get_virtual_channel_marker_path(&h.channel_id.0.as_hex().to_string(), ldk_data_dir);
		marker.exists()
	});
	if has_virtual_rgb_hop {
		first_hops.retain(|h| {
			let marker =
				get_virtual_channel_marker_path(&h.channel_id.0.as_hex().to_string(), ldk_data_dir);
			marker.exists()
		});
	}
	(contract_id, rgb_amount)
}
