// Constants for all structure field sizes
pub mod sizes {
    pub const NAME: usize = 128;
    pub const DESC: usize = 512;
    pub const MAX_PARAMS: usize = 16;
    pub const MAX_ERRORS: usize = 32;
    pub const MAX_CONSTRAINTS: usize = 16;
    pub const MAX_CAPABILITIES: usize = 8;
    pub const MAX_SIGNALS: usize = 16;
    pub const MAX_STRUCT_SPECS: usize = 8;
    pub const MAX_SIDE_EFFECTS: usize = 32;
    pub const MAX_STATE_TRANS: usize = 16;
    pub const MAX_PROTOCOL_BEHAVIORS: usize = 8;
    pub const MAX_ADDR_FAMILIES: usize = 8;
}

// Helper for reading data at specific offsets
pub struct DataReader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> DataReader<'a> {
    pub fn new(data: &'a [u8], offset: usize) -> Self {
        Self { data, pos: offset }
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let bytes = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Some(bytes)
        } else {
            None
        }
    }

    pub fn read_cstring(&mut self, max_len: usize) -> Option<String> {
        let bytes = self.read_bytes(max_len)?;
        if let Some(null_pos) = bytes.iter().position(|&b| b == 0) {
            if null_pos > 0 {
                if let Ok(s) = std::str::from_utf8(&bytes[..null_pos]) {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        self.read_bytes(4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        self.read_bytes(1).map(|b| b[0])
    }

    pub fn read_i32(&mut self) -> Option<i32> {
        self.read_bytes(4).map(|b| i32::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_u64(&mut self) -> Option<u64> {
        self.read_bytes(8).map(|b| u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_i64(&mut self) -> Option<i64> {
        self.read_bytes(8).map(|b| i64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn read_usize(&mut self) -> Option<usize> {
        self.read_u64().map(|v| v as usize)
    }

    pub fn skip(&mut self, len: usize) {
        self.pos = (self.pos + len).min(self.data.len());
    }

    // Helper methods for common patterns
    pub fn read_bool(&mut self) -> Option<bool> {
        self.read_u8().map(|v| v != 0)
    }

    pub fn read_optional_string(&mut self, max_len: usize) -> Option<String> {
        self.read_cstring(max_len).filter(|s| !s.is_empty())
    }

    pub fn read_string_or_default(&mut self, max_len: usize) -> String {
        self.read_cstring(max_len).unwrap_or_default()
    }

    // Skip and discard - advances position by reading and discarding
    pub fn discard_cstring(&mut self, max_len: usize) {
        let _ = self.read_cstring(max_len);
    }

    // Read multiple booleans at once
    pub fn read_bools<const N: usize>(&mut self) -> Option<[bool; N]> {
        let mut result = [false; N];
        for item in &mut result {
            *item = self.read_bool()?;
        }
        Some(result)
    }


}

// Structure layout definitions for calculating sizes
pub fn signal_mask_spec_layout_size() -> usize {
    // Packed structure from struct kapi_signal_mask_spec
    sizes::NAME + // mask_name
    4 * sizes::MAX_SIGNALS + // signals array
    4 + // signal_count
    sizes::DESC // description
}

pub fn struct_field_layout_size() -> usize {
    // Packed structure from struct kapi_struct_field
    sizes::NAME + // name
    4 + // type (enum)
    sizes::NAME + // type_name
    8 + // offset (size_t)
    8 + // size (size_t)
    4 + // flags
    4 + // constraint_type (enum)
    8 + // min_value (s64)
    8 + // max_value (s64)
    8 + // valid_mask (u64)
    sizes::DESC + // enum_values
    sizes::DESC // description
}

pub fn socket_state_spec_layout_size() -> usize {
    // struct kapi_socket_state_spec
    sizes::NAME * sizes::MAX_CONSTRAINTS + // required_states array
    sizes::NAME * sizes::MAX_CONSTRAINTS + // forbidden_states array
    sizes::NAME + // resulting_state
    sizes::DESC + // condition
    sizes::NAME + // applicable_protocols
    4 + // required_count
    4 // forbidden_count
}

pub fn protocol_behavior_spec_layout_size() -> usize {
    // struct kapi_protocol_behavior
    sizes::NAME + // applicable_protocols
    sizes::DESC + // behavior
    sizes::NAME + // protocol_flags
    sizes::DESC // flag_description
}

pub fn buffer_spec_layout_size() -> usize {
    // struct kapi_buffer_spec
    sizes::DESC + // buffer_behaviors
    8 + // min_buffer_size (size_t)
    8 + // max_buffer_size (size_t)
    8 // optimal_buffer_size (size_t)
}

pub fn async_spec_layout_size() -> usize {
    // struct kapi_async_spec
    sizes::NAME + // supported_modes
    4 // nonblock_errno (int)
}

pub fn addr_family_spec_layout_size() -> usize {
    // struct kapi_addr_family_spec
    4 + // family (int)
    sizes::NAME + // family_name
    8 + // addr_struct_size (size_t)
    8 + // min_addr_len (size_t)
    8 + // max_addr_len (size_t)
    sizes::DESC + // addr_format
    1 + // supports_wildcard (bool)
    1 + // supports_multicast (bool)
    1 + // supports_broadcast (bool)
    sizes::DESC + // special_addresses
    4 + // port_range_min (u32)
    4 // port_range_max (u32)
}
