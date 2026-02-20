//! Transport parameters (RFC 9000 Section 18).

use crate::{Reader, Result, WireError, Writer};

/// Transport parameters exchanged in the TLS handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParams {
    /// original_destination_connection_id (server only).
    pub original_dcid: Option<Vec<u8>>,
    /// max_idle_timeout in milliseconds.
    pub max_idle_timeout: u64,
    /// stateless_reset_token (server only).
    pub stateless_reset_token: Option<[u8; 16]>,
    /// max_udp_payload_size.
    pub max_udp_payload_size: u64,
    /// initial_max_data.
    pub initial_max_data: u64,
    /// initial_max_stream_data_bidi_local.
    pub initial_max_stream_data_bidi_local: u64,
    /// initial_max_stream_data_bidi_remote.
    pub initial_max_stream_data_bidi_remote: u64,
    /// initial_max_stream_data_uni.
    pub initial_max_stream_data_uni: u64,
    /// initial_max_streams_bidi.
    pub initial_max_streams_bidi: u64,
    /// initial_max_streams_uni.
    pub initial_max_streams_uni: u64,
    /// ack_delay_exponent.
    pub ack_delay_exponent: u64,
    /// max_ack_delay in milliseconds.
    pub max_ack_delay: u64,
    /// disable_active_migration.
    pub disable_active_migration: bool,
    /// active_connection_id_limit.
    pub active_connection_id_limit: u64,
    /// initial_source_connection_id.
    pub initial_scid: Option<Vec<u8>>,
    /// retry_source_connection_id (server only).
    pub retry_scid: Option<Vec<u8>>,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            original_dcid: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_connection_id_limit: 2,
            initial_scid: None,
            retry_scid: None,
        }
    }
}

fn int(w: &mut Writer<'_>, id: u64, v: u64) -> Result<()> {
    w.varint(id)?;
    w.varint(crate::codec::varint_len(v)? as u64)?;
    w.varint(v)
}

impl TransportParams {
    /// Encodes the parameters, omitting values equal to their defaults.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut buf = vec![0u8; 1024];
        let mut w = Writer::new(&mut buf);
        let d = Self::default();
        if let Some(c) = &self.original_dcid {
            w.varint(0x00)?;
            w.vbytes(c)?;
        }
        let ints = [
            (0x01, self.max_idle_timeout, d.max_idle_timeout),
            (0x03, self.max_udp_payload_size, d.max_udp_payload_size),
            (0x04, self.initial_max_data, d.initial_max_data),
            (0x05, self.initial_max_stream_data_bidi_local, 0),
            (0x06, self.initial_max_stream_data_bidi_remote, 0),
            (0x07, self.initial_max_stream_data_uni, 0),
            (0x08, self.initial_max_streams_bidi, 0),
            (0x09, self.initial_max_streams_uni, 0),
            (0x0a, self.ack_delay_exponent, d.ack_delay_exponent),
            (0x0b, self.max_ack_delay, d.max_ack_delay),
            (
                0x0e,
                self.active_connection_id_limit,
                d.active_connection_id_limit,
            ),
        ];
        for (id, v, def) in ints {
            if v != def {
                int(&mut w, id, v)?;
            }
        }
        if let Some(t) = &self.stateless_reset_token {
            w.varint(0x02)?;
            w.vbytes(t)?;
        }
        if self.disable_active_migration {
            w.varint(0x0c)?;
            w.varint(0)?;
        }
        if let Some(c) = &self.initial_scid {
            w.varint(0x0f)?;
            w.vbytes(c)?;
        }
        if let Some(c) = &self.retry_scid {
            w.varint(0x10)?;
            w.vbytes(c)?;
        }
        out.extend_from_slice(w.written());
        Ok(())
    }

    /// Decodes parameters, rejecting duplicates and out-of-range values.
    /// Unknown parameters are ignored as required by RFC 9000 18.1.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut p = Self::default();
        let mut seen: Vec<u64> = Vec::new();
        let mut r = Reader::new(buf);
        while r.remaining() > 0 {
            let id = r.varint()?;
            let val = r.vbytes()?;
            if seen.contains(&id) {
                return Err(WireError::InvalidParam(id));
            }
            seen.push(id);
            let bad = |_| WireError::InvalidParam(id);
            let vint = || -> Result<u64> {
                let mut vr = Reader::new(val);
                let v = vr.varint().map_err(bad)?;
                if vr.remaining() != 0 {
                    return Err(WireError::InvalidParam(id));
                }
                Ok(v)
            };
            let cid = || -> Result<Vec<u8>> {
                if val.len() > crate::header::MAX_CID_LEN {
                    return Err(WireError::InvalidParam(id));
                }
                Ok(val.to_vec())
            };
            match id {
                0x00 => p.original_dcid = Some(cid()?),
                0x01 => p.max_idle_timeout = vint()?,
                0x02 => {
                    let t: [u8; 16] = val.try_into().map_err(|_| WireError::InvalidParam(id))?;
                    p.stateless_reset_token = Some(t);
                }
                0x03 => {
                    p.max_udp_payload_size = vint()?;
                    if p.max_udp_payload_size < 1200 {
                        return Err(WireError::InvalidParam(id));
                    }
                }
                0x04 => p.initial_max_data = vint()?,
                0x05 => p.initial_max_stream_data_bidi_local = vint()?,
                0x06 => p.initial_max_stream_data_bidi_remote = vint()?,
                0x07 => p.initial_max_stream_data_uni = vint()?,
                0x08 | 0x09 => {
                    let v = vint()?;
                    if v > 1 << 60 {
                        return Err(WireError::InvalidParam(id));
                    }
                    if id == 0x08 {
                        p.initial_max_streams_bidi = v
                    } else {
                        p.initial_max_streams_uni = v
                    }
                }
                0x0a => {
                    p.ack_delay_exponent = vint()?;
                    if p.ack_delay_exponent > 20 {
                        return Err(WireError::InvalidParam(id));
                    }
                }
                0x0b => {
                    p.max_ack_delay = vint()?;
                    if p.max_ack_delay >= 1 << 14 {
                        return Err(WireError::InvalidParam(id));
                    }
                }
                0x0c => {
                    if !val.is_empty() {
                        return Err(WireError::InvalidParam(id));
                    }
                    p.disable_active_migration = true;
                }
                0x0e => {
                    p.active_connection_id_limit = vint()?;
                    if p.active_connection_id_limit < 2 {
                        return Err(WireError::InvalidParam(id));
                    }
                }
                0x0f => p.initial_scid = Some(cid()?),
                0x10 => p.retry_scid = Some(cid()?),
                _ => {}
            }
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn params_roundtrip(a in 0u64..(1<<40), b in 0u64..(1<<20), c in 0u64..1000, idle in 0u64..100_000,
                            exp in 0u64..=20, mad in 0u64..16000, dam: bool, cidl in 2u64..10,
                            scid in proptest::collection::vec(any::<u8>(), 0..=20), tok: Option<[u8;16]>) {
            let p = TransportParams {
                original_dcid: Some(scid.clone()), max_idle_timeout: idle, stateless_reset_token: tok,
                max_udp_payload_size: 1200 + b, initial_max_data: a,
                initial_max_stream_data_bidi_local: b, initial_max_stream_data_bidi_remote: a,
                initial_max_stream_data_uni: c, initial_max_streams_bidi: c, initial_max_streams_uni: b,
                ack_delay_exponent: exp, max_ack_delay: mad, disable_active_migration: dam,
                active_connection_id_limit: cidl, initial_scid: Some(scid.clone()), retry_scid: None,
            };
            let mut out = Vec::new();
            p.encode(&mut out).unwrap();
            prop_assert_eq!(TransportParams::decode(&out).unwrap(), p);
        }

        #[test]
        fn decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..100)) {
            let _ = TransportParams::decode(&data);
        }
    }

    #[test]
    fn duplicate_rejected() {
        assert_eq!(
            TransportParams::decode(&[0x04, 1, 5, 0x04, 1, 5]),
            Err(WireError::InvalidParam(4))
        );
    }
}
