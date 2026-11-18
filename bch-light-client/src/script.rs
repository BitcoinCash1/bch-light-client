//! Scripts as Bitcoin Cash Node's RPC shows them: the `asm` text of
//! `ScriptToAsmStr`, and the output type, required signatures and addresses
//! of `Solver` and `ExtractDestinations` (BCHN 29, with the May 2026 rules,
//! which the RPC always applies).

use crate::cashaddr::{Address, AddressKind};
use crate::hash::sha256;
use ripemd::Digest;
use std::fmt::Write;

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_RETURN: u8 = 0x6a;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKMULTISIG: u8 = 0xae;

/// Scripts longer than this cannot be spent.
const MAX_SCRIPT_SIZE: usize = 10_000;
/// Pay-to-script outputs (May 2026): any other script up to this size.
const MAX_P2S_SCRIPT_SIZE: usize = 201;
/// Pushes up to this size show as numbers.
const MAX_NUMBER_SIZE: usize = 8;

const SIGHASH_UTXOS: u8 = 0x20;
const SIGHASH_FORKID: u8 = 0x40;
const SIGHASH_ANYONECANPAY: u8 = 0x80;

/// The next instruction at `*pos`: its opcode and, for a push, the data.
/// None when a push runs past the end of the script.
pub fn read_op<'a>(script: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let opcode = *script.get(*pos)?;
    *pos += 1;
    if opcode > OP_PUSHDATA4 {
        return Some((opcode, &[]));
    }
    let size = match opcode {
        OP_PUSHDATA1 => usize::from(*script.get(*pos)?),
        OP_PUSHDATA2 => usize::from(u16::from_le_bytes(
            script.get(*pos..*pos + 2)?.try_into().ok()?,
        )),
        OP_PUSHDATA4 => usize::try_from(u32::from_le_bytes(
            script.get(*pos..*pos + 4)?.try_into().ok()?,
        ))
        .ok()?,
        n => usize::from(n),
    };
    *pos += match opcode {
        OP_PUSHDATA1 => 1,
        OP_PUSHDATA2 => 2,
        OP_PUSHDATA4 => 4,
        _ => 0,
    };
    let data = script.get(*pos..pos.checked_add(size)?)?;
    *pos += size;
    Some((opcode, data))
}

/// A script number of up to 8 bytes: little-endian, sign and magnitude.
fn script_number(data: &[u8]) -> i64 {
    let Some(&last) = data.last() else { return 0 };
    let mut value = 0u64;
    for (i, b) in data.iter().enumerate() {
        value |= u64::from(*b) << (8 * i);
    }
    if last & 0x80 != 0 {
        let magnitude = value & !(0x80u64 << (8 * (data.len() - 1)));
        // At most 2^63 - 1: the sign bit is cleared.
        -(magnitude as i64)
    } else {
        value as i64
    }
}

/// The name BCHN gives an opcode that pushes no data.
pub fn op_name(opcode: u8) -> &'static str {
    const NAMES: [&str; 0xd6 - 0x4f] = [
        "-1",
        "OP_RESERVED",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "10",
        "11",
        "12",
        "13",
        "14",
        "15",
        "16",
        "OP_NOP",
        "OP_VER",
        "OP_IF",
        "OP_NOTIF",
        "OP_BEGIN",
        "OP_UNTIL",
        "OP_ELSE",
        "OP_ENDIF",
        "OP_VERIFY",
        "OP_RETURN",
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK",
        "OP_2DROP",
        "OP_2DUP",
        "OP_3DUP",
        "OP_2OVER",
        "OP_2ROT",
        "OP_2SWAP",
        "OP_IFDUP",
        "OP_DEPTH",
        "OP_DROP",
        "OP_DUP",
        "OP_NIP",
        "OP_OVER",
        "OP_PICK",
        "OP_ROLL",
        "OP_ROT",
        "OP_SWAP",
        "OP_TUCK",
        "OP_CAT",
        "OP_SPLIT",
        "OP_NUM2BIN",
        "OP_BIN2NUM",
        "OP_SIZE",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_EQUAL",
        "OP_EQUALVERIFY",
        "OP_DEFINE",
        "OP_INVOKE",
        "OP_1ADD",
        "OP_1SUB",
        "OP_LSHIFTNUM",
        "OP_RSHIFTNUM",
        "OP_NEGATE",
        "OP_ABS",
        "OP_NOT",
        "OP_0NOTEQUAL",
        "OP_ADD",
        "OP_SUB",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFTBIN",
        "OP_RSHIFTBIN",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_GREATERTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHANOREQUAL",
        "OP_MIN",
        "OP_MAX",
        "OP_WITHIN",
        "OP_RIPEMD160",
        "OP_SHA1",
        "OP_SHA256",
        "OP_HASH160",
        "OP_HASH256",
        "OP_CODESEPARATOR",
        "OP_CHECKSIG",
        "OP_CHECKSIGVERIFY",
        "OP_CHECKMULTISIG",
        "OP_CHECKMULTISIGVERIFY",
        "OP_NOP1",
        "OP_CHECKLOCKTIMEVERIFY",
        "OP_CHECKSEQUENCEVERIFY",
        "OP_NOP4",
        "OP_NOP5",
        "OP_NOP6",
        "OP_NOP7",
        "OP_NOP8",
        "OP_NOP9",
        "OP_NOP10",
        "OP_CHECKDATASIG",
        "OP_CHECKDATASIGVERIFY",
        "OP_REVERSEBYTES",
        "OP_UNKNOWN",
        "OP_UNKNOWN",
        "OP_UNKNOWN",
        "OP_INPUTINDEX",
        "OP_ACTIVEBYTECODE",
        "OP_TXVERSION",
        "OP_TXINPUTCOUNT",
        "OP_TXOUTPUTCOUNT",
        "OP_TXLOCKTIME",
        "OP_UTXOVALUE",
        "OP_UTXOBYTECODE",
        "OP_OUTPOINTTXHASH",
        "OP_OUTPOINTINDEX",
        "OP_INPUTBYTECODE",
        "OP_INPUTSEQUENCENUMBER",
        "OP_OUTPUTVALUE",
        "OP_OUTPUTBYTECODE",
        "OP_UTXOTOKENCATEGORY",
        "OP_UTXOTOKENCOMMITMENT",
        "OP_UTXOTOKENAMOUNT",
        "OP_OUTPUTTOKENCATEGORY",
        "OP_OUTPUTTOKENCOMMITMENT",
        "OP_OUTPUTTOKENAMOUNT",
        "OP_RESERVED3",
        "OP_RESERVED4",
    ];
    match opcode {
        OP_0 => "0",
        OP_PUSHDATA1 => "OP_PUSHDATA1",
        OP_PUSHDATA2 => "OP_PUSHDATA2",
        OP_PUSHDATA4 => "OP_PUSHDATA4",
        0x4f..=0xd5 => NAMES[usize::from(opcode - 0x4f)],
        0xef => "SPECIAL_TOKEN_PREFIX",
        _ => "OP_UNKNOWN",
    }
}

/// Whether `sig` is a strict DER signature (BIP66), as BCHN checks it.
fn is_der(sig: &[u8]) -> bool {
    let len = sig.len();
    if !(8..=72).contains(&len) || sig[0] != 0x30 || usize::from(sig[1]) != len - 2 {
        return false;
    }
    let len_r = usize::from(sig[3]);
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 || len_r > len - 7 {
        return false;
    }
    if len_r > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
        return false;
    }
    let start_s = len_r + 4;
    let len_s = usize::from(sig[start_s + 1]);
    if sig[start_s] != 0x02 || len_s == 0 || sig[start_s + 2] & 0x80 != 0 {
        return false;
    }
    if start_s + len_s + 2 != len {
        return false;
    }
    !(len_s > 1 && sig[start_s + 2] == 0 && sig[start_s + 3] & 0x80 == 0)
}

/// The sighash name a pushed signature ends with, as BCHN decodes it in a
/// scriptSig: a Schnorr or strict DER signature with a defined hash type.
fn sighash_name(data: &[u8]) -> Option<String> {
    let (&hash_type, sig) = data.split_last()?;
    if sig.len() != 64 && !is_der(sig) {
        return None;
    }
    let base = hash_type & !(SIGHASH_UTXOS | SIGHASH_FORKID | SIGHASH_ANYONECANPAY);
    let fork = hash_type & SIGHASH_FORKID != 0;
    let anyone = hash_type & SIGHASH_ANYONECANPAY != 0;
    let utxos = hash_type & SIGHASH_UTXOS != 0;
    // SIGHASH_UTXOS needs the fork ID and refuses ANYONECANPAY.
    if utxos && (!fork || anyone) {
        return None;
    }
    let mut name = match base {
        1 => "ALL",
        2 => "NONE",
        3 => "SINGLE",
        _ => return None,
    }
    .to_string();
    for (set, flag) in [
        (fork, "|FORKID"),
        (anyone, "|ANYONECANPAY"),
        (utxos, "|UTXOS"),
    ] {
        if set {
            name.push_str(flag);
        }
    }
    Some(name)
}

/// The `asm` text of a script, as BCHN's RPC writes it. With
/// `decode_sighash` (scriptSigs), a pushed signature shows its hash type,
/// such as `[ALL|FORKID]`, in place of its last byte.
pub fn to_asm(script: &[u8], decode_sighash: bool) -> String {
    let unspendable = script.first() == Some(&OP_RETURN) || script.len() > MAX_SCRIPT_SIZE;
    let mut out = String::new();
    let mut pos = 0;
    while pos < script.len() {
        if !out.is_empty() {
            out.push(' ');
        }
        let Some((opcode, data)) = read_op(script, &mut pos) else {
            out.push_str("[error]");
            break;
        };
        if opcode > OP_PUSHDATA4 {
            out.push_str(op_name(opcode));
        } else if data.len() <= MAX_NUMBER_SIZE {
            let _ = write!(out, "{}", script_number(data));
        } else {
            match sighash_name(data).filter(|_| decode_sighash && !unspendable) {
                Some(name) => {
                    out.push_str(&hex::encode(&data[..data.len() - 1]));
                    let _ = write!(out, "[{name}]");
                }
                None => out.push_str(&hex::encode(data)),
            }
        }
    }
    out
}

/// What an output pays to, by BCHN's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputType {
    NonStandard,
    PubKey,
    PubKeyHash,
    ScriptHash,
    Multisig,
    NullData,
    /// Pay to script (May 2026): any other script of up to 201 bytes.
    Script,
}

impl OutputType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OutputType::NonStandard => "nonstandard",
            OutputType::PubKey => "pubkey",
            OutputType::PubKeyHash => "pubkeyhash",
            OutputType::ScriptHash => "scripthash",
            OutputType::Multisig => "multisig",
            OutputType::NullData => "nulldata",
            OutputType::Script => "script",
        }
    }
}

/// An output's type and, for the types BCHN gives addresses to, the
/// signatures it needs and its addresses (token-unaware, as BCHN shows them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Solution {
    pub kind: OutputType,
    pub destinations: Option<(u32, Vec<Address>)>,
}

/// The length a public key with this first byte has, or 0.
fn pubkey_length(first: u8) -> usize {
    match first {
        2 | 3 => 33,
        4 | 6 | 7 => 65,
        _ => 0,
    }
}

fn valid_pubkey_size(key: &[u8]) -> bool {
    key.first().is_some_and(|&b| pubkey_length(b) == key.len())
}

fn key_address(key: &[u8]) -> Address {
    Address {
        kind: AddressKind::P2pkh,
        hash: ripemd::Ripemd160::digest(sha256(key)).to_vec(),
        token_aware: false,
    }
}

fn is_push_only(script: &[u8]) -> bool {
    let mut pos = 0;
    while pos < script.len() {
        match read_op(script, &mut pos) {
            Some((opcode, _)) if opcode <= OP_16 => {}
            _ => return false,
        }
    }
    true
}

/// A bare multisig script: (signatures needed, public keys).
fn multisig(script: &[u8]) -> Option<(u32, Vec<&[u8]>)> {
    if script.last() != Some(&OP_CHECKMULTISIG) {
        return None;
    }
    let small = |opcode: u8| {
        (OP_1..=OP_16)
            .contains(&opcode)
            .then(|| u32::from(opcode - 0x50))
    };
    let mut pos = 0;
    let required = small(read_op(script, &mut pos)?.0)?;
    let mut keys = Vec::new();
    let count = loop {
        let (opcode, data) = read_op(script, &mut pos)?;
        if !valid_pubkey_size(data) {
            break small(opcode)?;
        }
        // Minimal for a 33- or 65-byte key: the direct push of its size.
        if usize::from(opcode) != data.len() {
            return None;
        }
        keys.push(data);
    };
    (keys.len() == count as usize && count >= required && pos + 1 == script.len())
        .then_some((required, keys))
}

/// The output type, required signatures and addresses of a locking script.
pub fn solve(script: &[u8]) -> Solution {
    let one = |address: Address| Some((1, vec![address]));
    let p2sh = |hash: &[u8]| Address {
        kind: AddressKind::P2sh,
        hash: hash.to_vec(),
        token_aware: false,
    };
    let (kind, destinations) = match script {
        [OP_HASH160, 0x14, hash @ .., OP_EQUAL] if hash.len() == 20 => {
            (OutputType::ScriptHash, one(p2sh(hash)))
        }
        [OP_HASH256, 0x20, hash @ .., OP_EQUAL] if hash.len() == 32 => {
            (OutputType::ScriptHash, one(p2sh(hash)))
        }
        [OP_RETURN, rest @ ..] if is_push_only(rest) => (OutputType::NullData, None),
        [size, key @ .., OP_CHECKSIG]
            if usize::from(*size) == key.len()
                && matches!(key.len(), 33 | 65)
                && valid_pubkey_size(key) =>
        {
            (OutputType::PubKey, one(key_address(key)))
        }
        [OP_DUP, OP_HASH160, 0x14, hash @ .., OP_EQUALVERIFY, OP_CHECKSIG] if hash.len() == 20 => {
            let address = Address {
                kind: AddressKind::P2pkh,
                hash: hash.to_vec(),
                token_aware: false,
            };
            (OutputType::PubKeyHash, one(address))
        }
        _ => match multisig(script) {
            Some((required, keys)) => (
                OutputType::Multisig,
                Some((required, keys.into_iter().map(key_address).collect())),
            ),
            None if script.len() <= MAX_P2S_SCRIPT_SIZE => (OutputType::Script, None),
            None => (OutputType::NonStandard, None),
        },
    };
    Solution { kind, destinations }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Transaction;

    #[test]
    fn numbers_names_and_errors() {
        // OP_0; pushes of up to 8 bytes as numbers: 0xff (-127), 0x8100
        // (129), 3 bytes, the largest 8-byte number and a negative zero;
        // OP_NUM2BIN, OP_1NEGATE and OP_16.
        let script = hex::decode(
            "0001ff0281000301020308ffffffffffffff7f08000000000000008080 4f60".replace(' ', ""),
        )
        .unwrap();
        assert_eq!(
            to_asm(&script, false),
            "0 -127 129 197121 9223372036854775807 0 OP_NUM2BIN -1 16"
        );
        assert_eq!(
            to_asm(&[0xef, 0xbd, 0xd6, 0x89], false),
            "SPECIAL_TOKEN_PREFIX OP_UNKNOWN OP_UNKNOWN OP_DEFINE"
        );
        for (opcode, name) in [
            (0x50, "OP_RESERVED"),
            (0x65, "OP_BEGIN"),
            (0x76, "OP_DUP"),
            (0x98, "OP_LSHIFTBIN"),
            (0xac, "OP_CHECKSIG"),
            (0xb9, "OP_NOP10"),
            (0xbc, "OP_REVERSEBYTES"),
            (0xbf, "OP_UNKNOWN"),
            (0xc0, "OP_INPUTINDEX"),
            (0xd3, "OP_OUTPUTTOKENAMOUNT"),
            (0xd5, "OP_RESERVED4"),
            (0xff, "OP_UNKNOWN"),
        ] {
            assert_eq!(op_name(opcode), name);
        }
        // A push that runs past the end.
        assert_eq!(to_asm(&[0x76, 0x05, 1, 2], false), "OP_DUP [error]");
        assert_eq!(to_asm(&[0x4c], false), "[error]");
        assert_eq!(to_asm(&[], false), "");
    }

    #[test]
    fn signatures_show_their_hash_type_only_in_spendable_scriptsigs() {
        let schnorr = |hash_type: u8| {
            let mut s = vec![0x41];
            s.extend_from_slice(&[0x11; 64]);
            s.push(hash_type);
            s
        };
        let sig = "11".repeat(64);
        assert_eq!(to_asm(&schnorr(0x41), true), format!("{sig}[ALL|FORKID]"));
        assert_eq!(
            to_asm(&schnorr(0x61), true),
            format!("{sig}[ALL|FORKID|UTXOS]")
        );
        assert_eq!(
            to_asm(&schnorr(0xc3), true),
            format!("{sig}[SINGLE|FORKID|ANYONECANPAY]")
        );
        assert_eq!(
            to_asm(&schnorr(0x81), true),
            format!("{sig}[ALL|ANYONECANPAY]")
        );
        // UTXOS needs FORKID and refuses ANYONECANPAY; base type 4 is not defined.
        for undefined in [0x21, 0xe1, 0x44, 0x40] {
            assert_eq!(
                to_asm(&schnorr(undefined), true),
                format!("{sig}{undefined:02x}")
            );
        }
        // Not decoded in a locking script, nor after OP_RETURN.
        assert_eq!(to_asm(&schnorr(0x41), false), format!("{sig}41"));
        let mut unspendable = vec![OP_RETURN];
        unspendable.extend(schnorr(0x41));
        assert_eq!(to_asm(&unspendable, true), format!("OP_RETURN {sig}41"));
        // A 9-byte push that is no signature stays hex.
        assert_eq!(
            to_asm(&[9, 1, 2, 3, 4, 5, 6, 7, 8, 0x41], true),
            "010203040506070841"
        );
    }

    #[test]
    fn standard_types_and_their_addresses() {
        let p2sh32 = hex::decode(format!("aa20{}87", "22".repeat(32))).unwrap();
        let s = solve(&p2sh32);
        assert_eq!(s.kind.as_str(), "scripthash");
        let (n, addresses) = s.destinations.unwrap();
        assert_eq!(n, 1);
        assert_eq!(addresses[0].hash.len(), 32);
        assert!(!addresses[0].token_aware);
        // P2S since May 2026: up to 201 bytes, else nonstandard; empty is P2S too.
        assert_eq!(solve(&[0x75]).kind, OutputType::Script);
        assert_eq!(solve(&[]).kind, OutputType::Script);
        assert_eq!(solve(&[0x75; 202]).kind, OutputType::NonStandard);
        // OP_RETURN with a non-push is no null data.
        assert_eq!(solve(&[OP_RETURN, 1, 7]).kind, OutputType::NullData);
        assert_eq!(solve(&[OP_RETURN, 0x75]).kind, OutputType::Script);
        // A multisig with a key count that does not match.
        let key = format!("21{}", "02".repeat(33));
        let bad = hex::decode(format!("51{key}{key}51ae")).unwrap();
        assert_eq!(solve(&bad).kind, OutputType::Script);
        let good = hex::decode(format!("51{key}{key}52ae")).unwrap();
        assert_eq!(
            solve(&good).destinations.map(|d| (d.0, d.1.len())),
            Some((1, 2))
        );
    }

    fn bchn_vectors() -> Vec<(String, Transaction, serde_json::Value)> {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/bchn");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).expect("vectors") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let json: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let raw = hex::decode(json["hex"].as_str().unwrap()).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push((name, Transaction::from_bytes(&raw).unwrap(), json));
        }
        out
    }

    /// Bitcoin Cash Node's own `bitcoin-tx -json` vectors (MIT License,
    /// copyright The Bitcoin developers and The Bitcoin Core developers;
    /// tests/data/bchn/COPYING), test/util/data at v29.2.0: every scriptSig
    /// and locking script gives BCHN's asm, type, required signatures and
    /// addresses.
    #[test]
    fn bchn_vectors_give_the_same_asm_types_and_addresses() {
        let vectors = bchn_vectors();
        assert_eq!(vectors.len(), 8);
        for (name, tx, json) in vectors {
            assert_eq!(tx.txid().to_hex(), json["txid"].as_str().unwrap(), "{name}");
            for (input, vin) in tx.inputs.iter().zip(json["vin"].as_array().unwrap()) {
                assert_eq!(
                    to_asm(&input.script_sig, true),
                    vin["scriptSig"]["asm"].as_str().unwrap(),
                    "{name}"
                );
            }
            for (output, vout) in tx.outputs.iter().zip(json["vout"].as_array().unwrap()) {
                let spk = &vout["scriptPubKey"];
                assert_eq!(
                    to_asm(&output.script, false),
                    spk["asm"].as_str().unwrap(),
                    "{name}"
                );
                let solution = solve(&output.script);
                assert_eq!(
                    solution.kind.as_str(),
                    spk["type"].as_str().unwrap(),
                    "{name}"
                );
                let expected = spk.get("reqSigs").map(|n| {
                    let addresses: Vec<String> = spk["addresses"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|a| a.as_str().unwrap().to_string())
                        .collect();
                    (n.as_u64().unwrap() as u32, addresses)
                });
                let ours = solution.destinations.map(|(n, addresses)| {
                    (
                        n,
                        addresses
                            .iter()
                            .map(|a| a.encode("bitcoincash").unwrap())
                            .collect(),
                    )
                });
                assert_eq!(ours, expected, "{name}");
            }
        }
    }
}
