//! Stable filesystem-object identity codec used by local recovery journals.

use anyhow::{Result, ensure};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilesystemIdentityV1 {
    pub filesystem_id: u64,
    pub object_id: u128,
    pub kind: u8,
    pub len: u64,
    pub mode: u32,
    pub owner_id: u64,
    pub link_count: u64,
}

impl FilesystemIdentityV1 {
    pub const ENCODED_LEN: usize = 57;
    pub fn encode(self) -> Result<[u8; Self::ENCODED_LEN]> {
        self.validate()?;
        let mut out = [0; Self::ENCODED_LEN];
        out[..4].copy_from_slice(b"RFI1");
        out[4..12].copy_from_slice(&self.filesystem_id.to_be_bytes());
        out[12..28].copy_from_slice(&self.object_id.to_be_bytes());
        out[28] = self.kind;
        out[29..37].copy_from_slice(&self.len.to_be_bytes());
        out[37..41].copy_from_slice(&self.mode.to_be_bytes());
        out[41..49].copy_from_slice(&self.owner_id.to_be_bytes());
        out[49..57].copy_from_slice(&self.link_count.to_be_bytes());
        Ok(out)
    }
    fn validate(self) -> Result<()> {
        ensure!(
            matches!(self.kind, 1 | 2),
            "invalid filesystem identity kind"
        );
        ensure!(self.link_count > 0, "filesystem identity has no links");
        let mode_kind = self.mode & 0o170000;
        ensure!(
            (self.kind == 1 && mode_kind == 0o100000) || (self.kind == 2 && mode_kind == 0o040000),
            "filesystem identity kind and mode disagree"
        );
        Ok(())
    }
    pub fn decode(value: &[u8]) -> Result<Self> {
        ensure!(
            value.len() == Self::ENCODED_LEN && &value[..4] == b"RFI1",
            "invalid filesystem identity codec"
        );
        let array =
            |range: std::ops::Range<usize>| -> Result<[u8; 8]> { Ok(value[range].try_into()?) };
        let decoded = Self {
            filesystem_id: u64::from_be_bytes(array(4..12)?),
            object_id: u128::from_be_bytes(value[12..28].try_into()?),
            kind: value[28],
            len: u64::from_be_bytes(array(29..37)?),
            mode: u32::from_be_bytes(value[37..41].try_into()?),
            owner_id: u64::from_be_bytes(array(41..49)?),
            link_count: u64::from_be_bytes(array(49..57)?),
        };
        decoded.validate()?;
        Ok(decoded)
    }
}
