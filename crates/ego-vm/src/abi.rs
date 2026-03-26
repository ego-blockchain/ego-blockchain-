use blake2::{Blake2s256, Digest};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AbiError {
    #[error("buffer underflow: need {need} bytes at offset {offset}, have {have}")]
    BufferUnderflow { need: usize, offset: usize, have: usize },

    #[error("invalid bool byte 0x{byte:02x} at offset {offset}")]
    InvalidBool { byte: u8, offset: usize },

    #[error("invalid UTF-8 in String value at offset {offset}: {detail}")]
    InvalidUtf8 { offset: usize, detail: String },

    #[error("FixedBytes length must be 1–32, got {len}")]
    InvalidFixedBytesLen { len: usize },

    #[error("AbiValue type mismatch: expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },

    #[error("call data too short for selector (need 4 bytes, have {have})")]
    MissingSelector { have: usize },

    #[error("type/value count mismatch: {types} types but {values} values")]
    CountMismatch { types: usize, values: usize },

    #[error("trailing bytes after decode: {trailing} bytes unused")]
    TrailingBytes { trailing: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiType {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Int8,
    Int16,
    Int32,
    Int64,
    Bool,

    Address,

    Bytes,

    String,

    FixedBytes(u8),
}

impl AbiType {

    pub fn canonical(&self) -> std::string::String {
        match self {
            AbiType::Uint8    => "uint8".into(),
            AbiType::Uint16   => "uint16".into(),
            AbiType::Uint32   => "uint32".into(),
            AbiType::Uint64   => "uint64".into(),
            AbiType::Uint128  => "uint128".into(),
            AbiType::Int8     => "int8".into(),
            AbiType::Int16    => "int16".into(),
            AbiType::Int32    => "int32".into(),
            AbiType::Int64    => "int64".into(),
            AbiType::Bool     => "bool".into(),
            AbiType::Address  => "address".into(),
            AbiType::Bytes    => "bytes".into(),
            AbiType::String   => "string".into(),
            AbiType::FixedBytes(n) => format!("bytes{}", n),
        }
    }

    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            AbiType::Uint8    => Some(1),
            AbiType::Uint16   => Some(2),
            AbiType::Uint32   => Some(4),
            AbiType::Uint64   => Some(8),
            AbiType::Uint128  => Some(16),
            AbiType::Int8     => Some(1),
            AbiType::Int16    => Some(2),
            AbiType::Int32    => Some(4),
            AbiType::Int64    => Some(8),
            AbiType::Bool     => Some(1),
            AbiType::Address  => Some(20),
            AbiType::FixedBytes(n) => Some(*n as usize),
            AbiType::Bytes | AbiType::String => None,
        }
    }
}

impl std::fmt::Display for AbiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.canonical())
    }
}

// ─── Values ───────────────────────────────────────────────────────────────────

/// A concrete ABI-encoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiValue {
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Uint128(u128),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Bool(bool),
    /// 20-byte address.
    Address([u8; 20]),
    /// Variable-length bytes.
    Bytes(Vec<u8>),
    /// UTF-8 string.
    String(std::string::String),
    /// Fixed-width bytes (length recorded by the variant data).
    FixedBytes(Vec<u8>),
}

impl AbiValue {
    /// Return the `AbiType` that corresponds to this value.
    pub fn abi_type(&self) -> AbiType {
        match self {
            AbiValue::Uint8(_)    => AbiType::Uint8,
            AbiValue::Uint16(_)   => AbiType::Uint16,
            AbiValue::Uint32(_)   => AbiType::Uint32,
            AbiValue::Uint64(_)   => AbiType::Uint64,
            AbiValue::Uint128(_)  => AbiType::Uint128,
            AbiValue::Int8(_)     => AbiType::Int8,
            AbiValue::Int16(_)    => AbiType::Int16,
            AbiValue::Int32(_)    => AbiType::Int32,
            AbiValue::Int64(_)    => AbiType::Int64,
            AbiValue::Bool(_)     => AbiType::Bool,
            AbiValue::Address(_)  => AbiType::Address,
            AbiValue::Bytes(_)    => AbiType::Bytes,
            AbiValue::String(_)   => AbiType::String,
            AbiValue::FixedBytes(v) => AbiType::FixedBytes(v.len() as u8),
        }
    }
}

// ─── Encoder ──────────────────────────────────────────────────────────────────

pub struct AbiEncoder;

impl AbiEncoder {
    /// Encode a slice of values into a compact byte buffer (concatenated).
    pub fn encode(values: &[AbiValue]) -> Vec<u8> {
        let mut buf = Vec::new();
        for v in values {
            buf.extend_from_slice(&Self::encode_one(v));
        }
        buf
    }

    /// Encode a single value.
    pub fn encode_one(value: &AbiValue) -> Vec<u8> {
        match value {
            AbiValue::Uint8(v)    => vec![*v],
            AbiValue::Uint16(v)   => v.to_le_bytes().to_vec(),
            AbiValue::Uint32(v)   => v.to_le_bytes().to_vec(),
            AbiValue::Uint64(v)   => v.to_le_bytes().to_vec(),
            AbiValue::Uint128(v)  => v.to_le_bytes().to_vec(),
            AbiValue::Int8(v)     => vec![*v as u8],
            AbiValue::Int16(v)    => v.to_le_bytes().to_vec(),
            AbiValue::Int32(v)    => v.to_le_bytes().to_vec(),
            AbiValue::Int64(v)    => v.to_le_bytes().to_vec(),
            AbiValue::Bool(b)     => vec![if *b { 1u8 } else { 0u8 }],
            AbiValue::Address(a)  => a.to_vec(),
            AbiValue::Bytes(b) => {
                let len = b.len() as u32;
                let mut out = len.to_le_bytes().to_vec();
                out.extend_from_slice(b);
                out
            }
            AbiValue::String(s) => {
                let bytes = s.as_bytes();
                let len = bytes.len() as u32;
                let mut out = len.to_le_bytes().to_vec();
                out.extend_from_slice(bytes);
                out
            }
            AbiValue::FixedBytes(b) => b.clone(),
        }
    }
}

// ─── Decoder ──────────────────────────────────────────────────────────────────

pub struct AbiDecoder;

impl AbiDecoder {
    /// Decode all types from `data`, consuming exactly as many bytes as needed.
    /// Returns `AbiError::TrailingBytes` if bytes remain after all types are decoded.
    pub fn decode(types: &[AbiType], data: &[u8]) -> Result<Vec<AbiValue>, AbiError> {
        let mut offset = 0usize;
        let mut values = Vec::with_capacity(types.len());
        for t in types {
            values.push(Self::decode_one(t, data, &mut offset)?);
        }
        if offset != data.len() {
            return Err(AbiError::TrailingBytes { trailing: data.len() - offset });
        }
        Ok(values)
    }

    /// Decode a single value of type `t` from `data` starting at `*offset`.
    /// Advances `*offset` past the consumed bytes.
    pub fn decode_one(t: &AbiType, data: &[u8], offset: &mut usize) -> Result<AbiValue, AbiError> {
        match t {
            AbiType::Uint8 => {
                let b = Self::read_bytes(data, offset, 1)?;
                Ok(AbiValue::Uint8(b[0]))
            }
            AbiType::Uint16 => {
                let b = Self::read_bytes(data, offset, 2)?;
                Ok(AbiValue::Uint16(u16::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Uint32 => {
                let b = Self::read_bytes(data, offset, 4)?;
                Ok(AbiValue::Uint32(u32::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Uint64 => {
                let b = Self::read_bytes(data, offset, 8)?;
                Ok(AbiValue::Uint64(u64::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Uint128 => {
                let b = Self::read_bytes(data, offset, 16)?;
                Ok(AbiValue::Uint128(u128::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Int8 => {
                let b = Self::read_bytes(data, offset, 1)?;
                Ok(AbiValue::Int8(b[0] as i8))
            }
            AbiType::Int16 => {
                let b = Self::read_bytes(data, offset, 2)?;
                Ok(AbiValue::Int16(i16::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Int32 => {
                let b = Self::read_bytes(data, offset, 4)?;
                Ok(AbiValue::Int32(i32::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Int64 => {
                let b = Self::read_bytes(data, offset, 8)?;
                Ok(AbiValue::Int64(i64::from_le_bytes(b.try_into().unwrap())))
            }
            AbiType::Bool => {
                let b = Self::read_bytes(data, offset, 1)?;
                match b[0] {
                    0 => Ok(AbiValue::Bool(false)),
                    1 => Ok(AbiValue::Bool(true)),
                    byte => Err(AbiError::InvalidBool { byte, offset: *offset - 1 }),
                }
            }
            AbiType::Address => {
                let b = Self::read_bytes(data, offset, 20)?;
                let mut arr = [0u8; 20];
                arr.copy_from_slice(b);
                Ok(AbiValue::Address(arr))
            }
            AbiType::Bytes => {
                let len_bytes = Self::read_bytes(data, offset, 4)?;
                let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
                let body = Self::read_bytes(data, offset, len)?;
                Ok(AbiValue::Bytes(body.to_vec()))
            }
            AbiType::String => {
                let len_bytes = Self::read_bytes(data, offset, 4)?;
                let len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
                let body = Self::read_bytes(data, offset, len)?;
                let s = std::str::from_utf8(body).map_err(|e| AbiError::InvalidUtf8 {
                    offset: *offset - len,
                    detail: e.to_string(),
                })?;
                Ok(AbiValue::String(s.to_owned()))
            }
            AbiType::FixedBytes(n) => {
                let n = *n as usize;
                if n == 0 || n > 32 {
                    return Err(AbiError::InvalidFixedBytesLen { len: n });
                }
                let b = Self::read_bytes(data, offset, n)?;
                Ok(AbiValue::FixedBytes(b.to_vec()))
            }
        }
    }

    // Internal: borrow `need` bytes from `data` starting at `*offset` and advance it.
    fn read_bytes<'a>(data: &'a [u8], offset: &mut usize, need: usize) -> Result<&'a [u8], AbiError> {
        let have = data.len().saturating_sub(*offset);
        if have < need {
            return Err(AbiError::BufferUnderflow { need, offset: *offset, have });
        }
        let slice = &data[*offset..*offset + need];
        *offset += need;
        Ok(slice)
    }
}

pub struct FunctionSelector;

impl FunctionSelector {

    pub fn signature(fn_name: &str, param_types: &[AbiType]) -> std::string::String {
        let params: Vec<_> = param_types.iter().map(|t| t.canonical()).collect();
        format!("{}({})", fn_name, params.join(","))
    }

    pub fn compute(fn_name: &str, param_types: &[AbiType]) -> [u8; 4] {
        let sig = Self::signature(fn_name, param_types);
        let hash = Blake2s256::digest(sig.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    pub fn encode_call(fn_name: &str, param_types: &[AbiType], args: &[AbiValue]) -> Vec<u8> {
        assert_eq!(
            param_types.len(),
            args.len(),
            "param_types and args must have the same length"
        );
        let mut buf = Self::compute(fn_name, param_types).to_vec();
        buf.extend_from_slice(&AbiEncoder::encode(args));
        buf
    }

    pub fn decode_call(
        param_types: &[AbiType],
        data: &[u8],
    ) -> Result<([u8; 4], Vec<AbiValue>), AbiError> {
        if data.len() < 4 {
            return Err(AbiError::MissingSelector { have: data.len() });
        }
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&data[..4]);
        let args = AbiDecoder::decode(param_types, &data[4..])?;
        Ok((selector, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(value: AbiValue) {
        let encoded = AbiEncoder::encode_one(&value);
        let t = value.abi_type();
        let mut off = 0;
        let decoded = AbiDecoder::decode_one(&t, &encoded, &mut off).expect("decode_one failed");
        assert_eq!(value, decoded, "round-trip failed for {:?}", t);
        assert_eq!(off, encoded.len(), "offset not fully consumed");
    }

    #[test]
    fn test_uint8_rt() {
        rt(AbiValue::Uint8(255));
        rt(AbiValue::Uint8(0));
    }

    #[test]
    fn test_uint16_rt() {
        rt(AbiValue::Uint16(0x1234));

        let enc = AbiEncoder::encode_one(&AbiValue::Uint16(0x0102));
        assert_eq!(enc, vec![0x02, 0x01]);
    }

    #[test]
    fn test_uint32_rt() {
        rt(AbiValue::Uint32(u32::MAX));
        rt(AbiValue::Uint32(0));
    }

    #[test]
    fn test_uint64_rt() {
        rt(AbiValue::Uint64(u64::MAX));
    }

    #[test]
    fn test_uint128_rt() {
        rt(AbiValue::Uint128(u128::MAX));
        let enc = AbiEncoder::encode_one(&AbiValue::Uint128(1u128));
        assert_eq!(enc.len(), 16);
        assert_eq!(enc[0], 1);
        assert!(enc[1..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_signed_ints_rt() {
        rt(AbiValue::Int8(-1));
        rt(AbiValue::Int8(i8::MIN));
        rt(AbiValue::Int16(-1000));
        rt(AbiValue::Int32(i32::MIN));
        rt(AbiValue::Int64(-9999999999i64));
    }

    #[test]
    fn test_bool_rt() {
        rt(AbiValue::Bool(true));
        rt(AbiValue::Bool(false));
        let enc = AbiEncoder::encode_one(&AbiValue::Bool(true));
        assert_eq!(enc, vec![1u8]);
    }

    #[test]
    fn test_bool_invalid() {
        let data = vec![0x02u8];
        let mut off = 0;
        let err = AbiDecoder::decode_one(&AbiType::Bool, &data, &mut off).unwrap_err();
        assert!(matches!(err, AbiError::InvalidBool { byte: 0x02, .. }));
    }

    #[test]
    fn test_address_rt() {
        let addr = [0xabu8; 20];
        rt(AbiValue::Address(addr));
        let enc = AbiEncoder::encode_one(&AbiValue::Address(addr));
        assert_eq!(enc.len(), 20);
        assert!(enc.iter().all(|&b| b == 0xab));
    }

    #[test]
    fn test_bytes_rt() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        rt(AbiValue::Bytes(payload.clone()));
        let enc = AbiEncoder::encode_one(&AbiValue::Bytes(payload.clone()));

        assert_eq!(&enc[..4], &4u32.to_le_bytes());
        assert_eq!(&enc[4..], payload.as_slice());

        rt(AbiValue::Bytes(vec![]));
    }

    #[test]
    fn test_string_rt() {
        rt(AbiValue::String("hello, ego!".into()));
        rt(AbiValue::String(String::new()));

        rt(AbiValue::String("ego💎chain".into()));
    }

    #[test]
    fn test_fixed_bytes_rt() {
        let fb = AbiValue::FixedBytes(vec![0x01, 0x02, 0x03, 0x04]);
        rt(fb.clone());
        let enc = AbiEncoder::encode_one(&fb);
        assert_eq!(enc, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_multi_value_rt() {
        let values = vec![
            AbiValue::Uint32(42),
            AbiValue::Bool(true),
            AbiValue::Address([0x11u8; 20]),
            AbiValue::String("transfer".into()),
        ];
        let types: Vec<AbiType> = values.iter().map(|v| v.abi_type()).collect();
        let encoded = AbiEncoder::encode(&values);
        let decoded = AbiDecoder::decode(&types, &encoded).expect("multi decode failed");
        assert_eq!(values, decoded);
    }

    #[test]
    fn test_buffer_underflow() {
        let truncated = vec![0x01u8];
        let mut off = 0;
        let err = AbiDecoder::decode_one(&AbiType::Uint32, &truncated, &mut off).unwrap_err();
        assert!(matches!(err, AbiError::BufferUnderflow { need: 4, .. }));
    }

    #[test]
    fn test_trailing_bytes() {
        let mut data = AbiEncoder::encode_one(&AbiValue::Uint8(7));
        data.push(0xFF);
        let err = AbiDecoder::decode(&[AbiType::Uint8], &data).unwrap_err();
        assert!(matches!(err, AbiError::TrailingBytes { trailing: 1 }));
    }

    #[test]
    fn test_selector_determinism() {
        let s1 = FunctionSelector::compute("transfer", &[AbiType::Address, AbiType::Uint64]);
        let s2 = FunctionSelector::compute("transfer", &[AbiType::Address, AbiType::Uint64]);
        assert_eq!(s1, s2);

        let s3 = FunctionSelector::compute("send", &[AbiType::Address, AbiType::Uint64]);
        assert_ne!(s1, s3);

        let s4 = FunctionSelector::compute("transfer", &[AbiType::Address, AbiType::Uint32]);
        assert_ne!(s1, s4);
    }

    #[test]
    fn test_selector_signature_string() {
        let sig = FunctionSelector::signature(
            "mint",
            &[AbiType::Address, AbiType::Uint128, AbiType::FixedBytes(32)],
        );
        assert_eq!(sig, "mint(address,uint128,bytes32)");

        let no_args = FunctionSelector::signature("init", &[]);
        assert_eq!(no_args, "init()");
    }

    #[test]
    fn test_encode_decode_call_rt() {
        let fn_name = "transfer";
        let param_types = vec![AbiType::Address, AbiType::Uint64];
        let args = vec![
            AbiValue::Address([0x42u8; 20]),
            AbiValue::Uint64(1_000_000),
        ];

        let call_data = FunctionSelector::encode_call(fn_name, &param_types, &args);
        assert_eq!(call_data.len(), 4 + 20 + 8);

        let (sel, decoded_args) =
            FunctionSelector::decode_call(&param_types, &call_data).expect("decode_call failed");

        let expected_sel = FunctionSelector::compute(fn_name, &param_types);
        assert_eq!(sel, expected_sel);
        assert_eq!(decoded_args, args);
    }

    #[test]
    fn test_decode_call_missing_selector() {
        let err = FunctionSelector::decode_call(&[], &[0x01, 0x02]).unwrap_err();
        assert!(matches!(err, AbiError::MissingSelector { have: 2 }));
    }

    #[test]
    fn test_encode_call_no_args() {
        let call = FunctionSelector::encode_call("pause", &[], &[]);
        assert_eq!(call.len(), 4);
        let (sel, args) = FunctionSelector::decode_call(&[], &call).unwrap();
        assert_eq!(sel, FunctionSelector::compute("pause", &[]));
        assert!(args.is_empty());
    }

    #[test]
    fn test_abi_type_helper() {
        assert_eq!(AbiValue::Uint8(0).abi_type(),   AbiType::Uint8);
        assert_eq!(AbiValue::Bool(true).abi_type(), AbiType::Bool);
        let fb = AbiValue::FixedBytes(vec![0u8; 16]);
        assert_eq!(fb.abi_type(), AbiType::FixedBytes(16));
    }

    #[test]
    fn test_canonical_strings() {
        assert_eq!(AbiType::Uint8.canonical(),       "uint8");
        assert_eq!(AbiType::Uint128.canonical(),     "uint128");
        assert_eq!(AbiType::Int64.canonical(),       "int64");
        assert_eq!(AbiType::Bool.canonical(),        "bool");
        assert_eq!(AbiType::Address.canonical(),     "address");
        assert_eq!(AbiType::Bytes.canonical(),       "bytes");
        assert_eq!(AbiType::String.canonical(),      "string");
        assert_eq!(AbiType::FixedBytes(1).canonical(),  "bytes1");
        assert_eq!(AbiType::FixedBytes(32).canonical(), "bytes32");
    }

    #[test]
    fn test_le_encoding() {

        let enc = AbiEncoder::encode_one(&AbiValue::Uint32(0x0102_0304));
        assert_eq!(enc, vec![0x04, 0x03, 0x02, 0x01]);

        let enc = AbiEncoder::encode_one(&AbiValue::Int64(-1));
        assert_eq!(enc, vec![0xFF; 8]);
    }

    #[test]
    fn test_complex_call_rt() {
        let fn_name = "store";
        let param_types = vec![
            AbiType::String,
            AbiType::Bytes,
            AbiType::Uint32,
            AbiType::Bool,
        ];
        let args = vec![
            AbiValue::String("my_key".into()),
            AbiValue::Bytes(vec![0xCA, 0xFE, 0xBA, 0xBE]),
            AbiValue::Uint32(99),
            AbiValue::Bool(false),
        ];
        let call = FunctionSelector::encode_call(fn_name, &param_types, &args);
        let (_, decoded) = FunctionSelector::decode_call(&param_types, &call).unwrap();
        assert_eq!(decoded, args);
    }
}
