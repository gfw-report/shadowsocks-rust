//! AEAD packet I/O facilities
//!
//! AEAD protocol is defined in <https://shadowsocks.org/en/spec/AEAD.html>.
//!
//! ```plain
//! TCP request (before encryption)
//! +------+---------------------+------------------+
//! | ATYP | Destination Address | Destination Port |
//! +------+---------------------+------------------+
//! |  1   |       Variable      |         2        |
//! +------+---------------------+------------------+
//!
//! TCP request (after encryption, *ciphertext*)
//! +--------+--------------+------------------+--------------+---------------+
//! | NONCE  |  *HeaderLen* |   HeaderLen_TAG  |   *Header*   |  Header_TAG   |
//! +--------+--------------+------------------+--------------+---------------+
//! | Fixed  |       2      |       Fixed      |   Variable   |     Fixed     |
//! +--------+--------------+------------------+--------------+---------------+
//!
//! TCP Chunk (before encryption)
//! +----------+
//! |  DATA    |
//! +----------+
//! | Variable |
//! +----------+
//!
//! TCP Chunk (after encryption, *ciphertext*)
//! +--------------+---------------+--------------+------------+
//! |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
//! +--------------+---------------+--------------+------------+
//! |      2       |     Fixed     |   Variable   |   Fixed    |
//! +--------------+---------------+--------------+------------+
//! ```
use std::{
    io::{self, ErrorKind},
    marker::Unpin,
    pin::Pin,
    slice,
    task::{self, Poll},
    u16,
};

use byte_string::ByteStr;
use bytes::{BufMut, Bytes, BytesMut};
use futures::ready;
use log::trace;
use rand::seq::SliceRandom;
use rand::Rng;
use rand_pcg::Pcg64;
use rand_seeder::Seeder;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    context::Context,
    crypto::{v1::Cipher, CipherKind},
};

/// AEAD packet payload must be smaller than 0x3FFF
pub const MAX_PACKET_SIZE: usize = 0x3FFF;

/// Since we append extra 1s or 0s to the payload, the actual payload size should be smaller
pub const MAX_PAYLOAD_SIZE: usize = 0x2F00;

/// AEAD Protocol Error
#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("header too short, expecting {0} bytes, but found {1} bytes")]
    HeaderTooShort(usize, usize),
    #[error("decrypt data failed")]
    DecryptDataError,
    #[error("decrypt length failed")]
    DecryptLengthError,
    #[error("buffer size too large ({0:#x}), AEAD encryption protocol requires buffer to be smaller than 0x3FFF, the higher two bits must be set to zero")]
    DataTooLong(usize),
}

/// AEAD Protocol result
pub type ProtocolResult<T> = Result<T, ProtocolError>;

impl From<ProtocolError> for io::Error {
    fn from(e: ProtocolError) -> io::Error {
        match e {
            ProtocolError::IoError(err) => err,
            _ => io::Error::new(ErrorKind::Other, e),
        }
    }
}

enum DecryptReadState {
    WaitSalt { key: Bytes },
    ReadLength,
    ReadData { length: usize },
    BufferedData { pos: usize },
}

/// Reader wrapper that will decrypt data automatically
pub struct DecryptedReader {
    state: DecryptReadState,
    cipher_for_length: Option<Cipher>,
    cipher_for_data: Option<Cipher>,
    buffer: BytesMut,
    method: CipherKind,
    salt: Option<Bytes>,
    has_handshaked: bool,
    key: Vec<u8>,
    is_first_packet: bool,
}

impl DecryptedReader {
    pub fn new(method: CipherKind, key: &[u8]) -> DecryptedReader {
        if method.salt_len() > 0 {
            DecryptedReader {
                state: DecryptReadState::WaitSalt {
                    key: Bytes::copy_from_slice(key),
                },
                cipher_for_length: None,
                cipher_for_data: None,
                buffer: BytesMut::with_capacity(method.salt_len()),
                method,
                salt: None,
                has_handshaked: false,
                key: key.to_vec(),
                is_first_packet: true,
            }
        } else {
            DecryptedReader {
                state: DecryptReadState::ReadLength,
                cipher_for_length: Some(Cipher::new(method, key, &[])),
                cipher_for_data: Some(Cipher::new(method, key, &[])),
                buffer: BytesMut::with_capacity(2 + method.tag_len()),
                method,
                salt: None,
                has_handshaked: false,
                key: key.to_vec(),
                is_first_packet: true,
            }
        }
    }

    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_deref()
    }

    /// Attempt to read decrypted data from stream
    pub fn poll_read_decrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match self.state {
                DecryptReadState::WaitSalt { ref key } => {
                    let key = unsafe { &*(key.as_ref() as *const _) };
                    ready!(self.poll_read_salt(cx, stream, key))?;

                    self.buffer.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buffer.reserve(2 + self.method.tag_len());
                    self.has_handshaked = true;
                }
                DecryptReadState::ReadLength => match ready!(self.poll_read_length(cx, stream))? {
                    None => {
                        return Ok(()).into();
                    }
                    Some(length) => {
                        self.buffer.clear();
                        self.state = DecryptReadState::ReadData { length };
                        self.buffer.reserve(length);
                    }
                },
                DecryptReadState::ReadData { length } => {
                    ready!(self.poll_read_data(cx, context, stream, length))?;

                    self.state = DecryptReadState::BufferedData { pos: 0 };
                }
                DecryptReadState::BufferedData { ref mut pos } => {
                    if *pos < self.buffer.len() {
                        let buffered = &self.buffer[*pos..];

                        let consumed = usize::min(buffered.len(), buf.remaining());
                        buf.put_slice(&buffered[..consumed]);

                        *pos += consumed;

                        return Ok(()).into();
                    }

                    self.buffer.clear();
                    self.state = DecryptReadState::ReadLength;
                    self.buffer.reserve(2 + self.method.tag_len());
                }
            }
        }
    }

    fn poll_read_salt<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, key: &[u8]) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let salt_len = self.method.salt_len();

        let n = ready!(self.poll_read_exact(cx, stream, salt_len))?;
        if n < salt_len {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }

        let salt = &self.buffer[..salt_len];
        // #442 Remember salt in filter after first successful decryption.
        //
        // If we check salt right here will allow attacker to flood our filter and eventually block all of our legitimate clients' requests.
        self.salt = Some(Bytes::copy_from_slice(salt));

        trace!("got AEAD salt {:?}", ByteStr::new(salt));

        let cipher_for_length = Cipher::new(self.method, key, salt);
        let cipher_for_data = Cipher::new(self.method, key, salt);

        self.cipher_for_length = Some(cipher_for_length);
        self.cipher_for_data = Some(cipher_for_data);

        Ok(()).into()
    }

    fn poll_read_length<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S) -> Poll<ProtocolResult<Option<usize>>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let length_len = 2 + self.method.tag_len();

        let n = ready!(self.poll_read_exact(cx, stream, length_len))?;
        if n == 0 {
            return Ok(None).into();
        }

        let cipher = self.cipher_for_length.as_mut().expect("cipher is None");

        let m = &mut self.buffer[..length_len];
        let length = DecryptedReader::decrypt_length(cipher, m)?;

        Ok(Some(length)).into()
    }

    fn poll_read_data<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        context: &Context,
        stream: &mut S,
        size: usize,
    ) -> Poll<ProtocolResult<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        let n = ready!(self.poll_read_exact(cx, stream, size))?;
        if n == 0 {
            return Err(io::Error::from(ErrorKind::UnexpectedEof).into()).into();
        }

        if self.is_first_packet {
            // Decode data
            //trace!("before decoding: {:02x?}", ByteStr::new(&self.buffer));
            trace!("before decoding size: {}", self.buffer.len());

            // Decode the packet
            let bit_vector_len = size * 8;

            // Initialize random number generator from seed
            let mut rng: Pcg64 = Seeder::from(&self.key).make_rng();
            let mut shuffled_idx: Vec<usize> = (0..bit_vector_len).collect();
            shuffled_idx.shuffle(&mut rng);

            // Convert byte vector to bit vector
            let mut bit_vector: Vec<u8> = Vec::new();
            for i in 0..size {
                for j in 0..8 {
                    let bit = (self.buffer[i] >> j) & 1;
                    bit_vector.push(bit);
                }
            }

            // Unshuffle bit vector
            let mut bit_vector_unshuffled = vec![0u8; bit_vector_len];
            for i in 0..bit_vector_len {
                bit_vector_unshuffled[i] = bit_vector[shuffled_idx[i]];
            }

            // Convert unshuffled bit vector back to byte vector
            let mut decoded_data: Vec<u8> = Vec::new();
            for i in 0..size {
                let mut byte: u8 = 0;
                for j in 0..8 {
                    byte |= bit_vector_unshuffled[(i * 8 + j) as usize] << j;
                }
                decoded_data.push(byte);
            }
            //trace!("new_buffer_unshuffled = {:02x?}", ByteStr::new(&new_buffer_unshuffled));

            // get the last 4 bytes of the unshuffled buffer as extra bytes length
            let mut extra_bytes_len: u32 = 0;
            for i in 0..4 {
                extra_bytes_len |= (decoded_data[size - i - 1] as u32) << (i * 8);
            }

            decoded_data.truncate(size - extra_bytes_len as usize - 4);

            // Update self.buffer with decoded data
            self.buffer.clear();
            self.buffer.put_slice(&decoded_data);
            //trace!("after decoding: {:02x?}", ByteStr::new(&self.buffer));
            trace!("after decoding size: {}", self.buffer.len());

            self.is_first_packet = false;
        }

        let data_len = self.buffer.len() - self.method.tag_len();

        let cipher = self.cipher_for_data.as_mut().expect("cipher is None");

        let m = &mut self.buffer[..];
        if !cipher.decrypt_packet(m) {
            return Err(ProtocolError::DecryptDataError).into();
        }

        // Check repeated salt after first successful decryption #442
        if let Some(ref salt) = self.salt {
            context.check_nonce_replay(self.method, salt)?;
        }

        // Remote TAG
        self.buffer.truncate(data_len);

        Ok(()).into()
    }

    fn poll_read_exact<S>(&mut self, cx: &mut task::Context<'_>, stream: &mut S, size: usize) -> Poll<io::Result<usize>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        assert!(size != 0);

        while self.buffer.len() < size {
            let remaining = size - self.buffer.len();
            let buffer = &mut self.buffer.chunk_mut()[..remaining];

            let mut read_buf =
                ReadBuf::uninit(unsafe { slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut _, remaining) });
            ready!(Pin::new(&mut *stream).poll_read(cx, &mut read_buf))?;

            let n = read_buf.filled().len();
            if n == 0 {
                if !self.buffer.is_empty() {
                    return Err(ErrorKind::UnexpectedEof.into()).into();
                } else {
                    return Ok(0).into();
                }
            }

            unsafe {
                self.buffer.advance_mut(n);
            }
        }

        Ok(size).into()
    }

    fn decrypt_length(cipher: &mut Cipher, m: &mut [u8]) -> ProtocolResult<usize> {
        let plen = {
            if !cipher.decrypt_packet(m) {
                return Err(ProtocolError::DecryptLengthError);
            }

            u16::from_be_bytes([m[0], m[1]]) as usize
        };

        if plen > MAX_PACKET_SIZE {
            // https://shadowsocks.org/en/spec/AEAD-Ciphers.html
            //
            // AEAD TCP protocol have reserved the higher two bits for future use
            return Err(ProtocolError::DataTooLong(plen));
        }

        Ok(plen)
    }

    /// Check if handshake finished
    pub fn handshaked(&self) -> bool {
        self.has_handshaked
    }
}

enum EncryptWriteState {
    AssemblePacket,
    Writing { pos: usize },
}

/// Writer wrapper that will encrypt data automatically
pub struct EncryptedWriter {
    cipher_for_length: Cipher,
    cipher_for_data: Cipher,
    buffer: BytesMut,
    state: EncryptWriteState,
    salt: Bytes,
    key: Vec<u8>,
    is_first_packet: bool,
}

impl EncryptedWriter {
    /// Creates a new EncryptedWriter
    pub fn new(method: CipherKind, key: &[u8], nonce: &[u8]) -> EncryptedWriter {
        // nonce should be sent with the first packet
        let mut buffer = BytesMut::with_capacity(nonce.len());
        buffer.put(nonce);

        EncryptedWriter {
            cipher_for_length: Cipher::new(method, key, nonce),
            cipher_for_data: Cipher::new(method, key, nonce),
            buffer,
            state: EncryptWriteState::AssemblePacket,
            salt: Bytes::copy_from_slice(nonce),
            key: key.to_vec(),
            is_first_packet: true,
        }
    }

    /// Salt (nonce)
    pub fn salt(&self) -> &[u8] {
        self.salt.as_ref()
    }

    /// Attempt to write encrypted data into the writer
    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut task::Context<'_>,
        stream: &mut S,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        if buf.len() > MAX_PAYLOAD_SIZE {
            buf = &buf[..MAX_PAYLOAD_SIZE];
        }

        loop {
            match self.state {
                EncryptWriteState::AssemblePacket => {
                    // Step 1. Encrypt data
                    let data_size = buf.len() + self.cipher_for_data.tag_len();
                    let mut buffer = BytesMut::with_capacity(data_size);
                    let mbuf = buffer.chunk_mut();
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    buffer.put_slice(buf);
                    self.cipher_for_data.encrypt_packet(mbuf);
                    unsafe { buffer.advance_mut(self.cipher_for_data.tag_len()) };

                    if self.is_first_packet {
                        // Encode data
                        //trace!("before encoding: {:02x?}", ByteStr::new(&buffer));
                        trace!("before encoding size: {}", buffer.len());
                        let buffer_len = buffer.len();

                        // Count number of 1s and 0s in the packet
                        let mut number_of_ones: u32 = 0;
                        let mut number_of_zeros: u32 = 0;
                        for i in 0..buffer_len {
                            for j in 0..8 {
                                let bit = (buffer[i] >> j) & 1;
                                if bit == 1 {
                                    number_of_ones += 1;
                                } else {
                                    number_of_zeros += 1;
                                }
                            }
                        }
                        trace!(
                            "number_of_ones = {}, number_of_zeros = {}",
                            number_of_ones,
                            number_of_zeros
                        );

                        // take into account the salt and encrypted length field
                        number_of_ones += ((self.salt.len() + self.cipher_for_length.tag_len() + 2) * 8) as u32;
                        number_of_zeros += ((self.salt.len() + self.cipher_for_length.tag_len() + 2) * 8) as u32;

                        let mut rng = rand::thread_rng();
                        let current_ratio = number_of_ones as f32 / number_of_zeros as f32;
                        trace!("1/0 ratio = {}", current_ratio);
                        let mut extra_bytes_len = 0u32;

                        // Append extra 1s or 0s to the data
                        if current_ratio > 0.7 && current_ratio < 1.4 {
                            if number_of_ones <= number_of_zeros {
                                // Append more 0s
                                let target_ratio = rng.gen_range(0.6..0.7);
                                trace!("target 1/0 ratio = {}", target_ratio);
                                extra_bytes_len =
                                    ((number_of_ones as f32 / target_ratio) as u32 - number_of_zeros) / 8 + 1;
                                buffer.reserve(extra_bytes_len as usize + 4);
                                for _ in 0..extra_bytes_len {
                                    buffer.put_u8(0);
                                }
                            } else {
                                // Append more 1s
                                let target_ratio = rng.gen_range(1.4..1.5);
                                trace!("target 1/0 ratio = {}", target_ratio);
                                extra_bytes_len =
                                    ((number_of_zeros as f32 * target_ratio) as u32 - number_of_ones) / 8 + 1;
                                buffer.reserve(extra_bytes_len as usize + 4);
                                for _ in 0..extra_bytes_len {
                                    buffer.put_u8(0xff);
                                }
                            }
                        }
                        trace!("extra_bytes_len = {}", extra_bytes_len);
                        // Append extra bytes length to the end
                        buffer.put_u32(extra_bytes_len);

                        // Now we are going to shuffle the buffer...
                        let encoded_data_size = buffer.len();
                        let bit_vector_len = encoded_data_size * 8;

                        // Initialize random number generator from seed
                        //let mut rng: ChaChaRng = Seeder::from("stripy zebra").make_rng();
                        let mut rng: Pcg64 = Seeder::from(&self.key).make_rng();
                        let mut shuffled_idx: Vec<usize> = (0..bit_vector_len).collect();
                        shuffled_idx.shuffle(&mut rng);

                        // Convert byte vector to bit vector
                        let mut bit_vector: Vec<u8> = Vec::new();
                        for i in 0..encoded_data_size {
                            for j in 0..8 {
                                let bit = (buffer[i] >> j) & 1;
                                bit_vector.push(bit);
                            }
                        }

                        // Shuffle bit vector
                        let mut bit_vector_shuffled: Vec<u8> = vec![0u8; bit_vector_len];
                        for i in 0..bit_vector_len {
                            bit_vector_shuffled[shuffled_idx[i]] = bit_vector[i];
                        }

                        // Convert bit vector back to byte vector
                        let mut encoded_data_shuffled: Vec<u8> = Vec::new();
                        for i in 0..encoded_data_size {
                            let mut byte: u8 = 0;
                            for j in 0..8 {
                                byte |= bit_vector_shuffled[i * 8 + j] << j;
                            }
                            encoded_data_shuffled.push(byte);
                        }
                        //trace!("after encoding: {:02x?}", ByteStr::new(&encoded_data_shuffled));
                        trace!("after encoding size = {}", encoded_data_shuffled.len());

                        // Count number of 1s in the buffer
                        let mut number_of_ones = 0;
                        let mut number_of_zeros = 0;
                        for i in 0..encoded_data_size {
                            for j in 0..8 {
                                let bit = (encoded_data_shuffled[i] >> j) & 1;
                                if bit == 1 {
                                    number_of_ones += 1;
                                } else {
                                    number_of_zeros += 1;
                                }
                            }
                        }
                        trace!(
                            "number_of_ones = {}, number_of_zeros = {}",
                            number_of_ones,
                            number_of_zeros
                        );
                        let adjusted_ratio = number_of_ones as f32 / number_of_zeros as f32;
                        trace!("adjusted 1/0 ratio = {}", adjusted_ratio);

                        buffer.clear();
                        buffer.put_slice(&encoded_data_shuffled);

                        self.is_first_packet = false;
                    }

                    // Step 2. Append length
                    let length_size = 2 + self.cipher_for_length.tag_len();
                    self.buffer.reserve(length_size);

                    let mbuf = &mut self.buffer.chunk_mut()[..length_size];
                    let mbuf = unsafe { slice::from_raw_parts_mut(mbuf.as_mut_ptr(), mbuf.len()) };

                    self.buffer.put_u16(buffer.len() as u16);
                    self.cipher_for_length.encrypt_packet(mbuf);
                    unsafe { self.buffer.advance_mut(self.cipher_for_length.tag_len()) };

                    // Step 3. Append data
                    self.buffer.put_slice(&buffer);

                    // Step 4. Write all
                    self.state = EncryptWriteState::Writing { pos: 0 };
                }
                EncryptWriteState::Writing { ref mut pos } => {
                    while *pos < self.buffer.len() {
                        let n = ready!(Pin::new(&mut *stream).poll_write(cx, &self.buffer[*pos..]))?;
                        if n == 0 {
                            return Err(ErrorKind::UnexpectedEof.into()).into();
                        }
                        *pos += n;
                    }

                    // Reset state
                    self.state = EncryptWriteState::AssemblePacket;
                    self.buffer.clear();

                    return Ok(buf.len()).into();
                }
            }
        }
    }
}
