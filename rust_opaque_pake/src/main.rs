use h2c_rust_ref::{P256_XMDSHA256_SSWU_RO_, GetHashToCurve};
use redox_ecc::weierstrass::{Point, Scalar};
use redox_ecc::ellipticcurve::*;
use redox_ecc::instances::{P256, GetCurve};
use num_bigint::*;
use hmac::{Hmac, Mac};
use sodiumoxide::randombytes::randombytes;
use sodiumoxide::crypto::secretbox::*;
use std::fs::File;
use std::io::{Write, Read};
use std::convert::TryInto;
use redox_ecc::ops::Serialize;
use std::process::exit;
use std::time::Instant;

type HmacSha3256 = Hmac<sha3::Sha3_256>;

struct OpaqueInternalCommon<'a> {
    sid: &'a str,
    ssid: [u8; 32],
    ssid_p: [u8; 32],
    k: [u8; 32],
    sk: [u8; 32],
}

impl OpaqueInternalCommon<'_> {
    fn new(sid: &str) -> OpaqueInternalCommon {
        return OpaqueInternalCommon {
            sid,
            ssid: [0; 32],
            ssid_p: [0; 32],
            k: [0; 32],
            sk: [0; 32],
        };
    }
}

struct OpaqueInternalClient<'a> {
    common: OpaqueInternalCommon<'a>,
    r: Scalar,
    xu: Scalar,
    xu_point: Point,
    alpha: Point,
}

impl OpaqueInternalClient<'_> {
    fn new(sid: &str) -> OpaqueInternalClient {
        return OpaqueInternalClient {
            common: OpaqueInternalCommon::new(sid),
            r: P256.get().new_scalar(BigInt::from(0)),
            xu: P256.get().new_scalar(BigInt::from(0)),
            xu_point: P256.get().identity(),
            alpha: P256.get().identity(),
        };
    }
}

struct OpaqueInternalServer<'a> {
    common: OpaqueInternalCommon<'a>,
}

impl OpaqueInternalServer<'_> {
    fn new(sid: &str) -> OpaqueInternalServer {
        return OpaqueInternalServer {
            common: OpaqueInternalCommon::new(sid),
        };
    }
}

struct Secrets {
    pu: Scalar,
    pu_point: Point,
    ps_point: Point,
}

impl Secrets {
    fn new() -> Secrets {
        return Secrets {
            pu: P256.get().new_scalar(BigInt::from(0)),
            pu_point: P256.get().identity(),
            ps_point: P256.get().identity(),
        };
    }
}

impl PartialEq for Secrets {
    fn eq(&self, other: &Self) -> bool {
        self.pu == other.pu &&
            self.pu_point == other.pu_point &&
            self.ps_point == other.ps_point
    }
}

struct Records {
    ks: Scalar,
    ps: Scalar,
    ps_point: Point,
    pu_point: Point,
    ciphertext: [u8; 114],
    nonce: Nonce,
}

impl Records {
    fn new() -> Records {
        return Records {
            ks: P256.get().new_scalar(BigInt::from(0)),
            ps: P256.get().new_scalar(BigInt::from(0)),
            ps_point: P256.get().identity(),
            pu_point: P256.get().identity(),
            ciphertext: [0; 114],
            nonce: Nonce([0; 24]),
        };
    }
}

impl PartialEq for Records {
    fn eq(&self, other: &Self) -> bool {
        self.ps_point == other.ps_point &&
            self.ps == other.ps &&
            self.pu_point == other.pu_point &&
            self.nonce == other.nonce &&
            self.ciphertext.len() == other.ciphertext.len() &&
            self.ciphertext.iter().zip(other.ciphertext.iter()).all(|(a, b)| a == b)
    }
}


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
fn oprf(key: &Scalar, msg: &str) -> [u8; 32] {
    // hash the message over NIST P256
    let h = hash_prime(msg);
    // Compute h * k
    let hp = h * key.clone();
    // extract the encoded point
    let hp_bytes = &hp.encode(true)[1..]; // We drop the sign byte, as it's irrelevant entropy wise and makes the byte array 33 bytes long...

    // compute an HMAC using the encoded point as key, and msg as value
    let mut mac = HmacSha3256::new_varkey(hp_bytes).expect("Hmac can take key of any size");
    mac.input(msg.as_ref());
    return mac.result().code().try_into().expect("slice with incorrect length");
}

fn serialize_secret(secrets: &Secrets) -> [u8; 98] {
    let mut res: [u8; 32 + 33 * 2] = [0; 32 + 33 * 2];
    // Copy from slice ensures that the source and destination MUST have the same length
    // Values hard coded to get screamed at by the compiler/runtime if somehow they become invalid
    res[..32].copy_from_slice(&secrets.pu.to_bytes_le());
    res[32..65].copy_from_slice(&secrets.pu_point.encode(true));
    res[65..98].copy_from_slice(&secrets.ps_point.encode(true));
    return res;
}

fn deserialize_secret(encoded: &[u8]) -> Secrets {
    let curve = P256.get();
    return Secrets {
        pu: curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, encoded[..32].as_ref())),
        pu_point: curve.decode(&encoded[32..65]).expect("Could not decode the Point u"),
        ps_point: curve.decode(&encoded[65..]).expect("Could not decode the Point s"),
    };
}

fn serialize_records(records: &Records) -> [u8; 268] {
    let mut res: [u8; 32 * 2 + 33 * 2 + 114 + 24] = [0; 268];
    // Copy from slice ensures that the source and destination MUST have the same length
    // Values hard coded to get screamed at by the compiler/runtime if somehow they become invalid
    res[..32].copy_from_slice(&records.ks.to_bytes_le());
    res[32..64].copy_from_slice(&records.ps.to_bytes_le());
    res[64..97].copy_from_slice(&records.ps_point.encode(true));
    res[97..130].copy_from_slice(&records.pu_point.encode(true));
    res[130..244].copy_from_slice(&records.ciphertext);
    res[244..].copy_from_slice(&records.nonce.0);
    return res;
}

fn deserialize_records(encoded: &[u8; 32 * 2 + 33 * 2 + 114 + 24]) -> Records {
    let curve = P256.get();
    let mut res = Records {
        ks: curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &encoded[..32])),
        ps: curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &encoded[32..64])),
        ps_point: curve.decode(&encoded[64..97]).expect("Could not decode the Point s"),
        pu_point: curve.decode(&encoded[97..130]).expect("Could not decode the Point u"),
        ciphertext: [0; 114],
        nonce: Nonce(encoded[244..268].try_into().unwrap()),
    };
    res.ciphertext.copy_from_slice(&encoded[130..244]);
    return res;
}

fn is_valid(p: &Point) -> bool {
    let curve = P256.get();
    // first, check that alpha is in curve,
    // not the point to infinity,
    // and is generated by the generator
    curve.is_on_curve(p) &&
        *p != curve.identity() &&
        p * curve.new_scalar(curve.get_order().to_bigint().unwrap() - 1) + p == curve.identity()
}

// change the boolean as the last param to do the key exchange as client or server
fn key_exchange(p: &Scalar, x: &Scalar, p_point: &Point, xu_point: &Point, xs_point: &Point, ssid_p: &[u8], server: bool) -> Result<Point, String> {
    if !is_valid(p_point) || !is_valid(xu_point) || !is_valid(xs_point) {
        return Err(String::from("one of the points is not valid"));
    }

    let mut mac = HmacSha3256::new_varkey(ssid_p).expect("Hmac can take key of any size");
    mac.input(xu_point.encode(true).as_ref());
    mac.input("Server".as_ref());

    let eu: [u8; 32] = mac.clone().result().code().try_into().unwrap();
    let eu_scalar = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, &eu));

    mac.reset();
    mac.input(xs_point.encode(true).as_ref());
    mac.input("Client".as_ref());
    let es: [u8; 32] = mac.result().code().try_into().unwrap();
    let es_scalar = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, &es));

    return if server {
        let res = xu_point + p_point * eu_scalar;
        Ok(res.clone() * x.clone() + res * (es_scalar * p.clone()))
    } else {
        let res = xs_point + p_point * es_scalar;
        Ok(res.clone() * x.clone() + res * (eu_scalar * p.clone()))
    };
}

fn register(sid: &str, pw: &str) {
    // Uses libsodium to generate cryptographic pseudo-random bytes using chacha20
    let curve = P256.get();

    let mut records = Records::new();
    let mut secrets = Secrets::new();

    records.ks = curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &randombytes(32)));

    records.ps = curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &randombytes(32)));
    secrets.pu = curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &randombytes(32)));

    records.pu_point = P256.get().get_generator() * secrets.pu.clone();
    secrets.pu_point = records.pu_point.clone();

    records.ps_point = P256.get().get_generator() * records.ps.clone();
    secrets.ps_point = records.ps_point.clone();


    let rw = oprf(&records.ks, pw);

    // Encode pu, Pu and Ps as a byte array
    let serialized_secrets = serialize_secret(&secrets);

    // If we're running in debug mode, check that encoding and decoding of secrets are valid
    if cfg!(debug_assertions) {
        let decoded_secrets = deserialize_secret(&serialized_secrets);
        println!("secret encoding/decoding test : {}",
                 if secrets == decoded_secrets { "Success!" } else { "Failure!" });
    }

    records.nonce = gen_nonce();
    let key = Key(rw);

    records.ciphertext.copy_from_slice(seal(&serialized_secrets, &records.nonce, &key).as_slice());

    let serialized_records = serialize_records(&records);

    // If we're running in debug mode, check that file encoding and decoding are working properly
    if cfg!(debug_assertions) {
        let deserialized_records = deserialize_records(&serialized_records);
        println!("records serializing/deserializing test : {}",
                 if records == deserialized_records { "Success!" } else { "Failure!" });
    }

    let mut file = File::create(sid).expect("Could not create the user registration");
    file.write(&serialized_records).expect("Could not save the user registration");
}

fn client_init_login(internal: &mut OpaqueInternalClient, pw: &str) -> Result<(Point, Point), String> {
    internal.r = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, &randombytes(32)));

    internal.alpha = hash_prime(pw) * internal.r.clone();
    internal.xu = P256.get().new_scalar(BigInt::from_bytes_le(Sign::Plus, &randombytes(32)));
    internal.xu_point = P256.get().get_generator() * internal.xu.clone();
    return Ok((internal.alpha.clone(), internal.xu_point.clone()));
}

fn server_init_login(internal: &mut OpaqueInternalServer, alpha: &Point, xu_point: &Point)
                     -> Result<(Point, Point, [u8; 114], Nonce, [u8; 32], [u8; 32]), String> {
    let curve = P256.get();
    if !is_valid(alpha) {
        return Err(String::from("Point not in curve"));
    }

    // Then we generate a random session id and copy sid ref to the internals
    internal.common.ssid = randombytes(32).as_slice().try_into().unwrap();

    // Then fetch the serialized records, and deserialize them
    let mut serialized_records: [u8; 268] = [0; 268];

    let mut file = File::open(internal.common.sid).expect("Could not create the user registration");
    file.read(&mut serialized_records).expect("Could not save the user registration");

    let records = deserialize_records(&serialized_records);


    // Then generate beta and Xs
    let xs = curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &randombytes(32)));

    let beta = alpha * records.ks;
    let xs_point = curve.get_generator() * xs.clone();

    // Then create ssid'
    let mut mac = HmacSha3256::new_varkey(&alpha.encode(true)).unwrap();
    mac.input(internal.common.sid.as_ref());
    mac.input(&internal.common.ssid);

    internal.common.ssid_p = mac.result().code().try_into().unwrap();

    internal.common.k = match key_exchange(&records.ps, &xs, &records.pu_point, xu_point, &xs_point, &internal.common.ssid_p, true) {
        Ok(p) => p.encode(true)[1..].try_into().unwrap(),
        Err(s) => return Err(s),
    };

    // If we're running in debug mode, print the value of the common key
    if cfg!(debug_assertions) {
        println!("Server K : {:?}", internal.common.k);
    }

    let mut mac = HmacSha3256::new_varkey(&internal.common.k).unwrap();
    mac.input(&[0x00u8]);
    mac.input(&internal.common.ssid_p);
    internal.common.sk = mac.clone().result().code().try_into().unwrap();

    mac.reset();
    mac.input(&[0x01u8]);
    mac.input(&internal.common.ssid_p);
    let authentication_server = mac.result().code().try_into().unwrap();

    return Ok((beta, xs_point, records.ciphertext, records.nonce, authentication_server, internal.common.ssid));
}

fn client_validate(internal: &mut OpaqueInternalClient, beta: &Point, xs_point: &Point, c: &[u8; 114], nonce: &Nonce, authentication_server: &[u8; 32], pw: &str) -> Result<[u8; 32], String> {
    // check that beta is valid
    let curve = P256.get();
    if !is_valid(beta) {
        return Err(String::from("beta was not valid"));
    }

    // Compute beta times 1/r

    let b_div_r: [u8; 32] = (beta * (curve.new_scalar(BigInt::from(1)) / internal.r.clone())).encode(true)[1..].try_into().unwrap();

    // extract the RW key from beta * 1/r and the password
    let mut mac = HmacSha3256::new_varkey(&b_div_r).unwrap();
    mac.input(pw.as_ref());
    let rw: [u8; 32] = mac.result().code().try_into().unwrap();

    // Now to use the key to decrypt and validate c
    let key = Key(rw);

    let mut serialised_secrets: [u8; 98] = [0; 98];
    match open(c, nonce, &key) {
        Ok(s) => serialised_secrets.copy_from_slice(s.as_slice()),
        Err(_) => return Err(String::from("Could not decrypt AEAD ciphertext")),
    };

    let secrets = deserialize_secret(&serialised_secrets);
    let mut mac = HmacSha3256::new_varkey(&internal.alpha.encode(true)).unwrap();
    mac.input(internal.common.sid.as_ref());
    mac.input(&internal.common.ssid);

    internal.common.ssid_p = mac.result().code().try_into().unwrap();

    internal.common.k = match key_exchange(&secrets.pu, &internal.xu, &secrets.ps_point, &internal.xu_point, &xs_point, &internal.common.ssid_p, false) {
        Ok(p) => p.encode(true)[1..].try_into().unwrap(),
        Err(s) => return Err(s),
    };

    // If we're running in debug mode, print the value of the common key
    if cfg!(debug_assertions) {
        println!("Client K : {:?}", internal.common.k);
    }

    let mut mac = HmacSha3256::new_varkey(&internal.common.k).unwrap();
    mac.input(&[0x00u8]);
    mac.input(&internal.common.ssid_p);
    internal.common.sk = mac.clone().result().code().try_into().unwrap();

    mac.reset();
    mac.input(&[0x01u8]);
    mac.input(&internal.common.ssid_p);
    let authentication_server_verify: [u8; 32] = mac.clone().result().code().try_into().unwrap();

    mac.reset();
    mac.input(&[0x02u8]);
    mac.input(&internal.common.ssid_p);
    let authentication_user: [u8; 32] = mac.result().code().try_into().unwrap();

    return if *authentication_server == authentication_server_verify {
        Ok(authentication_user)
    } else {
        Err(String::from("Could not verify server identity"))
    };
}

fn server_validate(internal: &mut OpaqueInternalServer, authentication_user: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut mac = HmacSha3256::new_varkey(&internal.common.k).unwrap();
    mac.input(&[0x02u8]);
    mac.input(&internal.common.ssid_p);
    let authentication_user_verify: [u8; 32] = mac.result().code().try_into().unwrap();

    return if authentication_user_verify == *authentication_user {
        Ok(internal.common.sk)
    } else {
        Err(String::from("Could not verify client identity"))
    };
}

fn main() {
    let now = Instant::now();
    let mut client_ctx = OpaqueInternalClient::new("toto");
    let mut server_ctx = OpaqueInternalServer::new("toto");
    register("toto", "titi");

    // client doesn't know the value of session id yet, simply computes a couple points for the server
    // and initializes the context
    let client_init = match client_init_login(&mut client_ctx, "titi") {
        Ok(t) => t,
        Err(_) => exit(-1),
    };

    // Client transmits the 2 points to the server

    // server init a bunch of stuff, along with the session id
    let server_init = match server_init_login(&mut server_ctx, &client_init.0, &client_init.1) {
        Ok(t) => t,
        Err(_) => exit(-1),
    };

    // Server transmits some data to client, including the session id
    client_ctx.common.ssid = server_ctx.common.ssid.clone();

    // The client is now able to validate the server identity and compute the shared key
    let client_validate = match client_validate(&mut client_ctx, &server_init.0, &server_init.1, &server_init.2, &server_init.3, &server_init.4, "titi") {
        Ok(t) => t,
        Err(_) => exit(-1)
    };

    // The client finally transmits to the server a proof of knowledge

    // The server can now validate the client identity
    match server_validate(&mut server_ctx, &client_validate) {
        Ok(t) => t,
        Err(_) => exit(-1)
    };

    println!("Successful login, here is the final shared key :\nClient : {:?}\nServer : {:?}",
             client_ctx.common.sk,
             server_ctx.common.sk);

    println!("Full Opaque Key exchange protocol duration : {} ms", now.elapsed().as_millis());
}