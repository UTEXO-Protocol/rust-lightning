use crate::crypto::chacha20::ChaCha20;
use crate::crypto::chacha20poly1305rfc::ChaCha20Poly1305RFC;
use crate::crypto::fixed_time_eq;
use crate::crypto::poly1305::Poly1305;

use crate::io::{self, Read, Write};
use crate::ln::msgs::DecodeError;
use crate::util::ser::{
	FixedLengthReader, LengthLimitedRead, LengthReadableArgs, Readable, Writeable, Writer,
};

use alloc::vec::Vec;

pub(crate) struct ChaChaReader<'a, R: io::Read> {
	pub chacha: &'a mut ChaCha20,
	pub read: R,
}
impl<'a, R: io::Read> io::Read for ChaChaReader<'a, R> {
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.process_in_place(&mut dest[0..res]);
		}
		Ok(res)
	}
}

/// Enables the use of the serialization macros for objects that need to be simultaneously encrypted and
/// serialized. This allows us to avoid an intermediate Vec allocation.
pub(crate) struct ChaChaPolyWriteAdapter<'a, W: Writeable> {
	pub rho: [u8; 32],
	pub writeable: &'a W,
}

impl<'a, W: Writeable> ChaChaPolyWriteAdapter<'a, W> {
	#[allow(unused)] // This will be used for onion messages soon
	pub fn new(rho: [u8; 32], writeable: &'a W) -> ChaChaPolyWriteAdapter<'a, W> {
		Self { rho, writeable }
	}
}

impl<'a, T: Writeable> Writeable for ChaChaPolyWriteAdapter<'a, T> {
	// Simultaneously write and encrypt Self::writeable.
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		let mut chacha = ChaCha20Poly1305RFC::new(&self.rho, &[0; 12], &[]);
		let mut chacha_stream = ChaChaPolyWriter { chacha: &mut chacha, write: w };
		self.writeable.write(&mut chacha_stream)?;
		let mut tag = [0 as u8; 16];
		chacha.finish_and_get_tag(&mut tag);
		tag.write(w)?;

		Ok(())
	}

	fn serialized_length(&self) -> usize {
		self.writeable.serialized_length() + 16
	}
}

/// Encrypts the provided plaintext with the given key using ChaCha20Poly1305 in the modified
/// with-AAD form accepted by [`chachapoly_decrypt_with_optional_aad`].
pub(crate) fn chachapoly_encrypt_with_swapped_aad(
	mut plaintext: Vec<u8>, key: [u8; 32], aad: [u8; 32],
) -> Vec<u8> {
	let mut chacha = ChaCha20::new(&key[..], &[0; 12]);
	let mut mac_key = [0u8; 64];
	chacha.process_in_place(&mut mac_key);

	let mut mac = Poly1305::new(&mac_key[..32]);
	chacha.process_in_place(&mut plaintext[..]);
	mac.input(&plaintext[..]);

	if plaintext.len() % 16 != 0 {
		mac.input(&[0; 16][0..16 - (plaintext.len() % 16)]);
	}

	mac.input(&aad[..]);
	// Note that we don't need to pad the AAD since its a multiple of 16 bytes

	mac.input(&(plaintext.len() as u64).to_le_bytes());
	mac.input(&32u64.to_le_bytes());

	plaintext.extend_from_slice(&mac.result());
	plaintext
}

/// Decrypts ciphertext produced by [`chachapoly_encrypt_with_swapped_aad`] or plain
/// [`ChaChaPolyWriteAdapter`] output, returning the plaintext and whether the swapped-AAD form was
/// used.
pub(crate) fn chachapoly_decrypt_with_optional_aad(
	ciphertext: &[u8], key: [u8; 32], aad: [u8; 32],
) -> Result<(Vec<u8>, bool), DecodeError> {
	if ciphertext.len() < 16 {
		return Err(DecodeError::InvalidValue);
	}

	let mut chacha = ChaCha20::new(&key[..], &[0; 12]);
	let mut mac_key = [0u8; 64];
	chacha.process_in_place(&mut mac_key);

	#[cfg(not(fuzzing))]
	let mut mac = Poly1305::new(&mac_key[..32]);
	#[cfg(fuzzing)]
	let mut mac = Poly1305::new(&key);

	let decrypted_len = ciphertext.len() - 16;
	let mut plaintext = ciphertext[..decrypted_len].to_vec();
	mac.input(&plaintext);
	chacha.process_in_place(&mut plaintext);

	if decrypted_len % 16 != 0 {
		mac.input(&[0; 16][0..16 - (decrypted_len % 16)]);
	}

	let mut mac_aad = mac;
	mac_aad.input(&aad[..]);
	mac_aad.input(&(decrypted_len as u64).to_le_bytes());
	mac_aad.input(&32u64.to_le_bytes());

	mac.input(&0u64.to_le_bytes());
	mac.input(&(decrypted_len as u64).to_le_bytes());

	let mut tag = [0u8; 16];
	tag.copy_from_slice(&ciphertext[decrypted_len..]);

	if fixed_time_eq(&mac.result(), &tag) {
		Ok((plaintext, false))
	} else if fixed_time_eq(&mac_aad.result(), &tag) {
		Ok((plaintext, true))
	} else {
		Err(DecodeError::InvalidValue)
	}
}

/// Enables the use of the serialization macros for objects that need to be simultaneously decrypted and
/// deserialized. This allows us to avoid an intermediate Vec allocation.
pub(crate) struct ChaChaPolyReadAdapter<R: Readable> {
	pub readable: R,
}

impl<T: Readable> LengthReadableArgs<[u8; 32]> for ChaChaPolyReadAdapter<T> {
	// Simultaneously read and decrypt an object from a LengthLimitedRead storing it in
	// Self::readable. LengthLimitedRead must be used instead of std::io::Read because we need the
	// total length to separate out the tag at the end.
	fn read<R: LengthLimitedRead>(r: &mut R, secret: [u8; 32]) -> Result<Self, DecodeError> {
		if r.remaining_bytes() < 16 {
			return Err(DecodeError::InvalidValue);
		}

		let mut chacha = ChaCha20Poly1305RFC::new(&secret, &[0; 12], &[]);
		let decrypted_len = r.remaining_bytes() - 16;
		let s = FixedLengthReader::new(r, decrypted_len);
		let mut chacha_stream = ChaChaPolyReader { chacha: &mut chacha, read: s };
		let readable: T = Readable::read(&mut chacha_stream)?;
		while chacha_stream.read.bytes_remain() {
			let mut buf = [0; 256];
			chacha_stream.read(&mut buf)?;
		}

		let mut tag = [0 as u8; 16];
		r.read_exact(&mut tag)?;
		if !chacha.finish_and_check_tag(&tag) {
			return Err(DecodeError::InvalidValue);
		}

		Ok(Self { readable })
	}
}

/// Enables simultaneously reading and decrypting a ChaCha20Poly1305RFC stream from a std::io::Read.
struct ChaChaPolyReader<'a, R: Read> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub read: R,
}

impl<'a, R: Read> Read for ChaChaPolyReader<'a, R> {
	// Decrypt bytes from Self::read into `dest`.
	// `ChaCha20Poly1305RFC::finish_and_check_tag` must be called to check the tag after all reads
	// complete.
	fn read(&mut self, dest: &mut [u8]) -> Result<usize, io::Error> {
		let res = self.read.read(dest)?;
		if res > 0 {
			self.chacha.decrypt_in_place(&mut dest[0..res]);
		}
		Ok(res)
	}
}

/// Enables simultaneously writing and encrypting a byte stream into a Writer.
struct ChaChaPolyWriter<'a, W: Writer> {
	pub chacha: &'a mut ChaCha20Poly1305RFC,
	pub write: &'a mut W,
}

impl<'a, W: Writer> Writer for ChaChaPolyWriter<'a, W> {
	// Encrypt then write bytes from `src` into Self::write.
	// `ChaCha20Poly1305RFC::finish_and_get_tag` can be called to retrieve the tag after all writes
	// complete.
	fn write_all(&mut self, src: &[u8]) -> Result<(), io::Error> {
		let mut src_idx = 0;
		while src_idx < src.len() {
			let mut write_buffer = [0; 8192];
			let bytes_written = (&mut write_buffer[..])
				.write(&src[src_idx..])
				.expect("In-memory writes can't fail");
			self.chacha.encrypt_in_place(&mut write_buffer[..bytes_written]);
			self.write.write_all(&write_buffer[..bytes_written])?;
			src_idx += bytes_written;
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{ChaChaPolyReadAdapter, ChaChaPolyWriteAdapter};
	use crate::ln::msgs::DecodeError;
	use crate::util::ser::{self, FixedLengthReader, LengthReadableArgs, Writeable};

	// Used for for testing various lengths of serialization.
	#[derive(Debug, PartialEq, Eq)]
	struct TestWriteable {
		field1: Vec<u8>,
		field2: Vec<u8>,
		field3: Vec<u8>,
	}
	impl_writeable_tlv_based!(TestWriteable, {
		(1, field1, required_vec),
		(2, field2, required_vec),
		(3, field3, required_vec),
	});

	#[test]
	fn test_chacha_stream_adapters() {
		// Check that ChaChaPolyReadAdapter and ChaChaPolyWriteAdapter correctly encode and decode an
		// encrypted object.
		macro_rules! check_object_read_write {
			($obj: expr) => {
				// First, serialize the object, encrypted with ChaCha20Poly1305.
				let rho = [42; 32];
				let writeable_len = $obj.serialized_length() as u64 + 16;
				let write_adapter = ChaChaPolyWriteAdapter::new(rho, &$obj);
				let encrypted_writeable_bytes = write_adapter.encode();
				let encrypted_writeable = &mut &encrypted_writeable_bytes[..];

				// Now deserialize the object back and make sure it matches the original.
				let mut rd = FixedLengthReader::new(encrypted_writeable, writeable_len);
				let read_adapter =
					<ChaChaPolyReadAdapter<TestWriteable>>::read(&mut rd, rho).unwrap();
				assert_eq!($obj, read_adapter.readable);
			};
		}

		// Try a big object that will require multiple write buffers.
		let big_writeable =
			TestWriteable { field1: vec![43], field2: vec![44; 4192], field3: vec![45; 4192 + 1] };
		check_object_read_write!(big_writeable);

		// Try a small object that fits into one write buffer.
		let small_writeable =
			TestWriteable { field1: vec![43], field2: vec![44], field3: vec![45] };
		check_object_read_write!(small_writeable);
	}

	fn do_chacha_stream_adapters_ser_macros() -> Result<(), DecodeError> {
		let writeable =
			TestWriteable { field1: vec![43], field2: vec![44; 4192], field3: vec![45; 4192 + 1] };

		// First, serialize the object into a TLV stream, encrypted with ChaCha20Poly1305.
		let rho = [42; 32];
		let write_adapter = ChaChaPolyWriteAdapter::new(rho, &writeable);
		let mut writer = ser::VecWriter(Vec::new());
		encode_tlv_stream!(&mut writer, {
			(1, write_adapter, required),
		});

		// Now deserialize the object back and make sure it matches the original.
		let mut read_adapter: Option<ChaChaPolyReadAdapter<TestWriteable>> = None;
		decode_tlv_stream!(&mut &writer.0[..], {
			(1, read_adapter, (option: LengthReadableArgs, rho)),
		});
		assert_eq!(writeable, read_adapter.unwrap().readable);

		Ok(())
	}

	#[test]
	fn chacha_stream_adapters_ser_macros() {
		// Test that our stream adapters work as expected with the TLV macros.
		// This also serves to test the `option: $trait` variant of the `_decode_tlv` ser macro.
		do_chacha_stream_adapters_ser_macros().unwrap()
	}

}
