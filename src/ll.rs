/* automatically generated by rust-bindgen */

pub type size_t = ::std::os::raw::c_ulong;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Struct_GNUNET_CRYPTO_EddsaPublicKey {
    pub q_y: [u8; 32],
}
impl ::std::default::Default for Struct_GNUNET_CRYPTO_EddsaPublicKey {
    fn default() -> Self {
        Self { q_y: [0; 32] }
    }
}
#[derive(Copy, Clone)]
#[repr(u32)]
pub enum Enum_GNUNET_GNSRECORD_Flags {
    GNUNET_GNSRECORD_RF_NONE = 0,
    GNUNET_GNSRECORD_RF_PRIVATE = 2,
    GNUNET_GNSRECORD_RF_PENDING = 4,
    GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION = 8,
    GNUNET_GNSRECORD_RF_SHADOW_RECORD = 16,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Struct_GNUNET_GNSRECORD_Data {
    pub data: *const ::std::os::raw::c_void,
    pub expiration_time: u64,
    pub data_size: usize,
    pub record_type: u32,
    pub flags: Enum_GNUNET_GNSRECORD_Flags,
}
impl ::std::default::Default for Struct_GNUNET_GNSRECORD_Data {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

pub const GNUNET_DNSPARSER_MAX_NAME_LENGTH: u16 = 253;
