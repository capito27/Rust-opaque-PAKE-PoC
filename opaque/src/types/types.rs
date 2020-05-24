use redox_ecc::weierstrass::{Point, Scalar};
use redox_ecc::ellipticcurve::*;
use redox_ecc::instances::{P256, GetCurve};
use sodiumoxide::crypto::secretbox::Nonce;
use num_bigint::*;
use std::convert::TryInto;
use redox_ecc::ops::Serialize;
use std::fmt::{Debug, Formatter};
use core::fmt;


pub struct CtxCommon<'a> {
    pub(in super::super) sid: &'a str,
    pub(in super::super) ssid: [u8; 32],
    pub(in super::super) ssid_p: [u8; 32],
    pub(in super::super) k: [u8; 32],
    pub(in super::super) sk: [u8; 32],
    pub(in super::super) valid: bool,
    pub(in super::super) in_progress: bool,
}

impl CtxCommon<'_> {
    pub fn new(sid: &str) -> CtxCommon {
        return CtxCommon {
            sid,
            ssid: [0; 32],
            ssid_p: [0; 32],
            k: [0; 32],
            sk: [0; 32],
            valid: false,
            in_progress: true,
        };
    }
    pub fn set_ssid(&mut self, ssid: &[u8]) {
        self.ssid.copy_from_slice(ssid);
    }

    pub fn get_ssid(&self) -> [u8; 32]{
        self.ssid.clone()
    }

    pub fn is_finished(&self) -> bool {
        !self.in_progress
    }

    pub fn is_successful(&self) -> bool {
        self.is_finished() && self.valid
    }

    pub fn get_shared_key(&self) -> Result<[u8; 32], String> {
        if self.in_progress {
            Err(String::from("Can't access the shared key before the protocol is done !"))
        } else if !self.is_successful() {
            Err(String::from("Can't access the shared key of a failed protocol !"))
        } else {
            Ok(self.sk.clone())
        }
    }
}

pub struct Secrets {
    pub(in super::super) pu: Scalar,
    pub(in super::super) pu_point: Point,
    pub(in super::super) ps_point: Point,
}

impl Secrets {
    pub fn new() -> Secrets {
        return Secrets {
            pu: P256.get().new_scalar(BigInt::from(0)),
            pu_point: P256.get().identity(),
            ps_point: P256.get().identity(),
        };
    }

    pub fn serialize(&self) -> [u8; 98] {
        let mut res: [u8; 32 + 33 * 2] = [0; 32 + 33 * 2];
        // Copy from slice ensures that the source and destination MUST have the same length
        // Values hard coded to get screamed at by the compiler/runtime if somehow they become invalid
        res[..32].copy_from_slice(&self.pu.to_bytes_le());
        res[32..65].copy_from_slice(&self.pu_point.encode(true));
        res[65..98].copy_from_slice(&self.ps_point.encode(true));
        return res;
    }

    pub fn deserialize(encoded: &[u8]) -> Secrets {
        let curve = P256.get();
        return Secrets {
            pu: curve.new_scalar(BigInt::from_bytes_le(Sign::Plus, &encoded[..32])),
            pu_point: curve.decode(&encoded[32..65]).expect("Could not decode the Point u"),
            ps_point: curve.decode(&encoded[65..]).expect("Could not decode the Point s"),
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


impl Debug for Secrets {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        unimplemented!("The scalar type does not define a debug formatter")
    }
}

pub struct Records {
    pub(in super::super) ks: Scalar,
    pub(in super::super) ps: Scalar,
    pub(in super::super) ps_point: Point,
    pub(in super::super) pu_point: Point,
    pub(in super::super) ciphertext: [u8; 114],
    pub(in super::super) nonce: Nonce,
}

impl Records {
    pub fn new() -> Records {
        return Records {
            ks: P256.get().new_scalar(BigInt::from(0)),
            ps: P256.get().new_scalar(BigInt::from(0)),
            ps_point: P256.get().identity(),
            pu_point: P256.get().identity(),
            ciphertext: [0; 114],
            nonce: Nonce([0; 24]),
        };
    }

    pub fn serialize(&self) -> [u8; 268] {
        let mut res: [u8; 32 * 2 + 33 * 2 + 114 + 24] = [0; 268];
        // Copy from slice ensures that the source and destination MUST have the same length
        // Values hard coded to get screamed at by the compiler/runtime if somehow they become invalid
        res[..32].copy_from_slice(&self.ks.to_bytes_le());
        res[32..64].copy_from_slice(&self.ps.to_bytes_le());
        res[64..97].copy_from_slice(&self.ps_point.encode(true));
        res[97..130].copy_from_slice(&self.pu_point.encode(true));
        res[130..244].copy_from_slice(&self.ciphertext);
        res[244..].copy_from_slice(&self.nonce.0);
        return res;
    }

    pub fn deserialize(encoded: &[u8]) -> Records {
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

impl Debug for Records {
    fn fmt(&self, _: &mut Formatter<'_>) -> fmt::Result {
        unimplemented!("The scalar type does not define a debug formatter")
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{Records, Secrets};
    use crate::common::random_scalar;
    use redox_ecc::instances::{P256, GetCurve};
    use redox_ecc::ellipticcurve::EllipticCurve;
    use sodiumoxide::crypto::secretbox::gen_nonce;
    use rand::{Rng, thread_rng};

    #[test]
    fn serialised_records_can_be_deserialized() {
        let rec = Records {
            ks: random_scalar(32),
            ps: random_scalar(32),
            ps_point: P256.get().get_generator() * random_scalar(32),
            pu_point: P256.get().get_generator() * random_scalar(32),
            ciphertext: [thread_rng().gen(); 114],
            nonce: gen_nonce(),
        };
        assert_eq!(rec, Records::deserialize(&rec.serialize()));
    }

    #[test]
    fn serialised_secrets_can_be_deserialized() {
        let sec = Secrets {
            pu: random_scalar(32),
            pu_point: P256.get().get_generator() * random_scalar(32),
            ps_point: P256.get().get_generator() * random_scalar(32),
        };
        assert_eq!(sec, Secrets::deserialize(&sec.serialize()));
    }
}
