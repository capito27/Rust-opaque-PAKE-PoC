use crate::types::CtxCommon;

pub struct CtxServer<'a> {
    pub(in super::super) common: CtxCommon<'a>,
}

impl CtxServer<'_> {
    pub fn new(sid: &str) -> CtxServer {
        return CtxServer {
            common: CtxCommon::new(sid),
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