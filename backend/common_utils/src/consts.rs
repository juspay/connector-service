pub const ID_LENGTH: usize = 20;
/// Characters to use for generating NanoID
pub(crate) const ALPHABETS: [char; 62] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];

/// Max Length for MerchantReferenceId
pub const MAX_ALLOWED_MERCHANT_REFERENCE_ID_LENGTH: u8 = 64;
/// Minimum allowed length for MerchantReferenceId
pub const MIN_REQUIRED_MERCHANT_REFERENCE_ID_LENGTH: u8 = 1;
/// Length of a cell identifier in a distributed system
pub const CELL_IDENTIFIER_LENGTH: u8 = 5;
/// Minimum length required for a global id
pub const MAX_GLOBAL_ID_LENGTH: u8 = 64;
/// Maximum length allowed for a global id
pub const MIN_GLOBAL_ID_LENGTH: u8 = 32;
