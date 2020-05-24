use crate::types::CtxCommon;
use redox_ecc::weierstrass::{Scalar, Point};
use redox_ecc::instances::{P256, GetCurve};
use redox_ecc::ellipticcurve::EllipticCurve;
use num_bigint::BigInt;

pub struct CtxClient<'a> {
    pub(in super::super) common: CtxCommon<'a>,
    pub(in super::super) r: Scalar,
    pub(in super::super) xu: Scalar,
    pub(in super::super) xu_point: Point,
    pub(in super::super) alpha: Point,
}

impl CtxClient<'_> {
    pub fn new(sid: &str) -> CtxClient {
        return CtxClient {
            common: CtxCommon::new(sid),
            r: P256.get().new_scalar(BigInt::from(0)),
            xu: P256.get().new_scalar(BigInt::from(0)),
            xu_point: P256.get().identity(),
            alpha: P256.get().identity(),
        };
    }
    pub fn set_ssid(&mut self, ssid: &[u8]) {
        self.common.set_ssid(ssid);
    }

    pub fn get_ssid(&self) -> [u8; 32] {
        self.common.get_ssid()
    }

    pub fn is_finished(&self) -> bool {
        self.common.is_finished()
    }

    pub fn is_successful(&self) -> bool {
        self.common.is_successful()
    }

    pub fn get_shared_key(&self) -> Result<[u8; 32], String> {
        self.common.get_shared_key()
    }
}