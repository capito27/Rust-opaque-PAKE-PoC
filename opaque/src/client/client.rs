use crate::types::*;
use crate::common::*;

use redox_ecc::weierstrass::Point;
use redox_ecc::instances::{P256, GetCurve};
use redox_ecc::ellipticcurve::{EllipticCurve, Encode, Decode};
use sodiumoxide::crypto::secretbox::{open, Nonce, Key};
use num_bigint::BigInt;
use std::convert::TryInto;
use zeroize::Zeroize;

pub fn client_init_login(internal: &mut CtxClient, pw: &str) -> Result<(Point, Point), String> {
    if internal.is_finished() {
        return Err(String::from("Can't reuse a finished context"));
    }
    internal.r = random_scalar(32);

    internal.alpha = h_prime(pw) * internal.r.clone();

    internal.xu = random_scalar(32);

    internal.xu_point = gen_multiple( internal.xu.clone());

    return Ok((internal.alpha.clone(), internal.xu_point.clone()));
}

pub fn client_init_login_bytes(internal: &mut CtxClient, pw: &str) -> Result<[u8; 66], String> {
    return match client_init_login(internal, pw) {
        Ok(data) => {
            let mut res: [u8; 66] = [0; 66];
            res[..33].copy_from_slice(&data.0.encode(true));
            res[33..66].copy_from_slice(&data.1.encode(true));
            Ok(res)
        }
        Err(err) => Err(err)
    };
}

pub fn client_validate(internal: &mut CtxClient, beta: &Point, xs_point: &Point, c: &[u8], nonce: &Nonce, authentication_server: &[u8; 32], pw: &str) -> Result<[u8; 32], String> {
    if internal.is_finished() {
        return Err(String::from("Can't reuse a finished context"));
    }

    // check that beta is valid
    let curve = P256.get();
    if !is_valid(beta) {
        internal.common.in_progress = false;
        return Err(String::from("beta was not valid"));
    }

    // Compute beta times 1/r
    let b_div_r: Vec<u8> = (beta * (curve.new_scalar(BigInt::from(1)) / internal.r.clone())).encode(true);

    // derivate the RW key from beta * 1/r and the password
    let mut key = Key(hash_separated(&[pw.as_bytes(), &b_div_r], b"|"));

    let secrets =
        match open(c, nonce, &key) {
            Ok(s) => Secrets::deserialize(&s),
            Err(_) => {
                // Clear the key contents before going out of function
                key.0.zeroize();
                internal.common.in_progress = false;
                return Err(String::from("Could not decrypt AEAD ciphertext"));
            }
        };
    // Clear the key contents since we don't need them anymore
    key.0.zeroize();

    internal.common.ssid_p = hash_separated(&[internal.common.sid.as_bytes(), &internal.common.ssid, &internal.alpha.encode(true)], b"|");

    internal.common.k = match key_exchange(&secrets.pu, &internal.xu, &secrets.ps_point, &internal.xu_point, &xs_point, &internal.common.ssid_p, "Server", "User", false) {
        Ok(p) => p,
        Err(s) => {
            internal.common.in_progress = false;
            return Err(s);
        }
    };

    // If we're running in debug mode, print the value of the common key
    if cfg!(debug_assertions) {
        println!("Client K : {:x?}", internal.common.k);
    }

    internal.common.sk = hashmac_separated(&[&[0x00u8], &internal.common.ssid_p], b"|",&internal.common.k);

    let authentication_server_verify: [u8; 32] = hashmac_separated(&[&[0x01u8], &internal.common.ssid_p], b"|",&internal.common.k);

    let authentication_user: [u8; 32] = hashmac_separated(&[&[0x02u8], &internal.common.ssid_p], b"|",&internal.common.k);

    internal.common.in_progress = false;
    return if *authentication_server == authentication_server_verify {
        internal.common.valid = true;
        Ok(authentication_user)
    } else {
        Err(String::from("Could not verify server identity"))
    };
}

pub fn client_validate_bytes(internal: &mut CtxClient, password: &str, data: &[u8]) -> Result<[u8; 32], String> {
    if data.len() < 268 {
        return Err("Incomplete data blob for client validate".to_owned());
    }
    let beta = P256.get().decode(&data[..33]).unwrap();
    let xs_point = P256.get().decode(&data[33..66]).unwrap();
    let nonce = Nonce(data[180..204].try_into().unwrap());
    internal.set_ssid(&data[236..268]);

    return match client_validate(internal, &beta, &xs_point, &data[66..180], &nonce, &data[204..236].try_into().unwrap(), password) {
        Ok(t) => Ok(t),
        Err(e) => Err(e),
    };
}