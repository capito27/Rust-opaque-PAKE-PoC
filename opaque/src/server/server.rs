use crate::common::{h_prime, key_exchange, random_scalar, is_valid, hashmac_separated, hash_separated, gen_multiple};
use crate::types::{Records, CtxServer, Secrets};

use redox_ecc::weierstrass::{Point, Scalar};
use redox_ecc::ellipticcurve::{Encode, Decode};
use std::convert::TryInto;
use std::fs::File;
use sodiumoxide::randombytes::randombytes;
use std::io::{Read, Write};
use redox_ecc::instances::{P256, GetCurve};
use sodiumoxide::crypto::secretbox::{gen_nonce, seal, Nonce, Key};
use zeroize::Zeroize;


// Opaque pseudorandom function primitive over NIST P256 curve
pub fn oprf(key: &Scalar, msg: &str) -> [u8; 32] {
    // hash the message over NIST P256
    let h = h_prime(msg);
    // Compute h * k
    let hp = h * key.clone();
    // compute a hash with both the key and encoded point
    return hash_separated(&[msg.as_bytes(), &hp.encode(true)], b"|");
}

pub fn register(sid: &str, pw: &str) {
    let mut records = Records::new();
    let mut secrets = Secrets::new();

    records.ks = random_scalar(32);

    records.ps = random_scalar(32);
    secrets.pu = random_scalar(32);

    records.pu_point = gen_multiple(secrets.pu.clone());
    secrets.pu_point = records.pu_point.clone();

    records.ps_point = gen_multiple(records.ps.clone());
    secrets.ps_point = records.ps_point.clone();

    // If we're running in debug mode, check that encoding and decoding of secrets are valid
    if cfg!(debug_assertions) {
        let decoded_secrets = Secrets::deserialize(&secrets.serialize());
        println!("secret encoding/decoding test : {}",
                 if secrets == decoded_secrets { "Success!" } else { "Failure!" });
    }

    records.nonce = gen_nonce();
    let mut key = Key(oprf(&records.ks, pw));

    records.ciphertext.copy_from_slice(seal(&secrets.serialize(), &records.nonce, &key).as_slice());

    // Clear the key contents before going out of function
    key.0.zeroize();

    // If we're running in debug mode, check that file encoding and decoding are working properly
    if cfg!(debug_assertions) {
        let deserialized_records = Records::deserialize(&records.serialize());
        println!("records serializing/deserializing test : {}",
                 if records == deserialized_records { "Success!" } else { "Failure!" });
    }

    let mut file = File::create(sid).expect("Could not create the user registration");
    file.write(&records.serialize()).expect("Could not save the user registration");
}

pub fn server_init_login(internal: &mut CtxServer, alpha: &Point, xu_point: &Point)
                         -> Result<(Point, Point, [u8; 114], Nonce, [u8; 32], [u8; 32]), String> {
    if !is_valid(alpha) {
        internal.common.in_progress = false;
        return Err(String::from("Point not in curve"));
    }

    // Then we generate a random session id and copy sid ref to the internals
    internal.common.ssid = randombytes(32).as_slice().try_into().unwrap();

    // Then fetch the serialized records, and deserialize them
    let mut serialized_records: [u8; 268] = [0; 268];

    let mut file = match File::open(internal.common.sid) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Could not find file \"{}\"", internal.common.sid);
            internal.common.in_progress = false;
            return Err("Could not find file \"".to_owned() + internal.common.sid + "\"");
        }
    };
    match file.read(&mut serialized_records) {
        Err(_) => {
            eprintln!("Contents of  \"{}\" were corrupted", internal.common.sid);
            internal.common.in_progress = false;
            return Err("Contents of  \"".to_owned() + internal.common.sid + "\" were corrupted");
        }
        _ => {}
    }

    let records = Records::deserialize(&serialized_records);


    // Then generate beta and Xs
    let xs = random_scalar(32);

    let beta = alpha * records.ks;
    let xs_point = gen_multiple(xs.clone());


    internal.common.ssid_p = hash_separated(&[internal.common.sid.as_bytes(), &internal.common.ssid, &alpha.encode(true)], b"|");

    internal.common.k = match key_exchange(&records.ps, &xs, &records.pu_point, xu_point, &xs_point, &internal.common.ssid_p, "Server", "User", true) {
        Ok(p) => p,
        Err(s) => {
            internal.common.in_progress = false;
            return Err(s);
        }
    };

    // If we're running in debug mode, print the value of the common key
    if cfg!(debug_assertions) {
        println!("Server K : {:x?}", internal.common.k);
    }

    internal.common.sk = hashmac_separated(&[&[0x00u8], &internal.common.ssid_p], b"|", &internal.common.k);

    let authentication_server: [u8; 32] = hashmac_separated(&[&[0x01u8], &internal.common.ssid_p], b"|", &internal.common.k);

    return Ok((beta, xs_point, records.ciphertext, records.nonce, authentication_server, internal.common.ssid));
}

pub fn server_init_login_bytes(internal: &mut CtxServer, data: &[u8]) -> Result<[u8; 268], String> {
    if data.len() < 66 {
        return Err("Incomplete data blob for server init login".to_owned());
    }
    let alpha = P256.get().decode(&data[..33]).unwrap();
    let xu_point = P256.get().decode(&data[33..66]).unwrap();
    return match server_init_login(internal, &alpha, &xu_point) {
        Ok(result) => {
            let mut res: [u8; 268] = [0; 268];

            res[..33].copy_from_slice(&result.0.encode(true));
            res[33..66].copy_from_slice(&result.1.encode(true));
            res[66..180].copy_from_slice(&result.2);
            res[180..204].copy_from_slice(&(result.3).0);
            res[204..236].copy_from_slice(&result.4);
            res[236..268].copy_from_slice(&result.5);
            Ok(res)
        }
        Err(e) => Err(e)
    };
}


pub fn server_validate(internal: &mut CtxServer, authentication_user: &[u8; 32]) -> Result<[u8; 32], String> {
    let authentication_user_verify: [u8; 32] = hashmac_separated(&[&[0x02u8], &internal.common.ssid_p], b"|", &internal.common.k);


    return if authentication_user_verify == *authentication_user {
        internal.common.in_progress = false;
        internal.common.valid = true;
        Ok(internal.common.sk)
    } else {
        internal.common.in_progress = false;
        Err(String::from("Could not verify client identity"))
    };
}

pub fn server_validate_bytes(internal: &mut CtxServer, data: &[u8]) -> Result<[u8; 32], String> {
    if data.len() < 32 {
        return Err("Incomplete data blob for server validate".to_owned());
    }
    let mut authentification_user: [u8; 32] = [0; 32];
    authentification_user.copy_from_slice(&data[..32]);

    return server_validate(internal, &authentification_user);
}