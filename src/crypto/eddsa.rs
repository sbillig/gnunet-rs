#[repr(C)]
#[derive(Copy, Clone)]
pub struct EddsaPublicKey {
    pub q_y: [u8; 32],
}
impl std::default::Default for EddsaPublicKey {
    fn default() -> Self {
        Self { q_y: [0; 32] }
    }
}
