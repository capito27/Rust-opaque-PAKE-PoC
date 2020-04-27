use h2c_rust_ref::{P256_XMDSHA256_SSWU_RO_, GetHashToCurve};
use redox_ecc::weierstrass::Point;
use redox_ecc::ellipticcurve::*;
use redox_ecc::instances::{P256, GetCurve};
use num_bigint::*;
use hmac::{Hmac, Mac};
use sodiumoxide::randombytes::randombytes;
use sodiumoxide::crypto::secretbox::*;
use std::fs::File;
use std::io::Write;

type HmacSha3256 = Hmac<sha3::Sha3_256>;

// computes hash_over_curve of a message over the NIST P256 curve.
// cf : https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06
fn hash_prime(msg: &str) -> Point {
    let dst = b"P256_XMD:SHA-256_SSWU_RO_OPAQUE";
    let h = P256_XMDSHA256_SSWU_RO_.get(dst);
    let mut p = h.hash(msg.as_ref());
    p.normalize();
    return p;
}


// Opaque pseudorandom function primitive over NIST P256 curve
fn oprf(key: &[u8], msg: &str) -> [u8; 32] {
    // hash the message over NIST P256
    let h = hash_prime(msg);
    // Convert the Key to a scalar over NIST P256
    let k_scalar = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, key));
    // Compute h * k
    let hp = h * k_scalar;
    // extract the encoded point
    let hp_bytes = &hp.encode(true)[1..]; // We drop the sign byte, as it's irrelevant entropy wise and makes the byte array 33 bytes long...

    // compute an HMAC using the encoded point as key, and msg as value
    let mut mac = HmacSha3256::new_varkey(hp_bytes).expect("Hmac can take key of any size");
    mac.input(msg.as_ref());
    let mut res: [u8; 32] = [0; 32];
    res.clone_from_slice(mac.result().code().as_slice());
    return res;
}

fn serialize_secret(pu: &[u8], point_u: &Point, point_s: &Point) -> [u8; 98] {
    let mut res: [u8; 32 + 33 * 2] = [0; 32 + 33 * 2];
    // Copy from slice ensures that the source and destination MUST have the same length
    // Values hard coded to get screamed at by the compiler/runtime if somehow they become invalid
    res[..32].copy_from_slice(pu);
    res[32..65].copy_from_slice(&point_u.encode(true));
    res[65..98].copy_from_slice(&point_s.encode(true));
    return res;
}

fn deserialize_secret(encoded: &[u8; 32 + 33 * 2]) -> (&[u8], Point, Point) {
    let point_u = P256.get().decode(&encoded[32..65]).expect("Could not decode the Point u");
    let point_s = P256.get().decode(&encoded[65..]).expect("Could not decode the Point s");
    return (&encoded[..32], point_u, point_s);
}

fn serialize_records(ks: &[u8], ps: &[u8], point_s: &Point, point_u: &Point, sealed: &[u8], nonce: &Nonce) -> [u8; 268] {
    let mut res: [u8; 32 * 2 + 33 * 2 + 114 + 24] = [0; 268];
    // Copy from slice ensures that the source and destination MUST have the same length
    // Values hard coded to get screamed at by the compiler/runtime if somehow they become invalid
    res[..32].copy_from_slice(ks);
    res[32..64].copy_from_slice(ps);
    res[64..97].copy_from_slice(&point_s.encode(true));
    res[97..130].copy_from_slice(&point_u.encode(true));
    res[130..244].copy_from_slice(sealed);
    res[244..].copy_from_slice(&nonce.0);
    return res;
}

fn deserialize_records(encoded: &[u8; 32 * 2 + 33 * 2 + 114 + 24]) -> (&[u8], &[u8], Point, Point, &[u8], Nonce) {
    let point_s = P256.get().decode(&encoded[64..97]).expect("Could not decode the Point s");
    let point_u = P256.get().decode(&encoded[97..130]).expect("Could not decode the Point u");
    let mut nonce: [u8; 24] = [0; 24];
    nonce.copy_from_slice(&encoded[244..268]);
    let nonce = Nonce(nonce);
    return (&encoded[..32], &encoded[32..64], point_s, point_u, &encoded[130..244], nonce);
}

// TODO implement password hashing before oprf even if it will be hashed a bunch ?
// This function will encode
fn register(sid: &str, pw: &str) {
    // Uses libsodium to generate cryptographic pseudo-random bytes using chacha20
    let ks = randombytes(32);
    let rw = oprf(&ks, pw);

    let ps = randombytes(32);
    let ps_scalar = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, &ps));

    let pu = randombytes(32);
    let pu_scalar = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, &pu));

    let point_s = P256.get().get_generator() * ps_scalar;
    let point_u = P256.get().get_generator() * pu_scalar;

    // Encode pu, Pu and Ps as a byte array
    let serialized_secret = serialize_secret(&pu, &point_u, &point_s);

    // If we're running in debug mode, check that encoding and decoding of secrets are valid
    if cfg!(debug_assertions) {
        let decoded_secret = deserialize_secret(&serialized_secret);
        println!("secret encoding/decoding test : pu ({}), Pu ({}), Ps ({})",
                 pu.as_slice() == decoded_secret.0,
                 point_u == decoded_secret.1,
                 point_s == decoded_secret.2);
    }

    let nonce = gen_nonce();
    let key = Key(rw);
    let sealed = seal(&serialized_secret, &nonce, &key);

    let serialized_records = serialize_records(&ks, &ps, &point_s, &point_u, &sealed, &nonce);

    // If we're running in debug mode, check that file encoding and decoding are working properly
    if cfg!(debug_assertions) {
        let decoded_file = deserialize_records(&serialized_records);
        println!("file encoding/decoding test : ks ({}), ps ({}), Ps ({}), Pu ({}), c ({}), nonce ({})",
                 ks.as_slice() == decoded_file.0,
                 ps.as_slice() == decoded_file.1,
                 point_s == decoded_file.2,
                 point_u == decoded_file.3,
                 sealed.as_slice() == decoded_file.4,
                 nonce == decoded_file.5);
    }

    let mut file = File::create(sid).expect("Could not create the user registration");
    file.write(&serialized_records).expect("Could not save the user registration");
}

fn main() {
    register("toto", "titi")
}