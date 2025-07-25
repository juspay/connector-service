use hyperswitch_masking::{ExposeInterface, Secret};

fn apply_mask(val: &str, unmasked_char_count: usize, min_masked_char_count: usize) -> String {
    let len = val.len();
    if len <= unmasked_char_count {
        return val.to_string();
    }

    let mask_start_index =
    // For showing only last `unmasked_char_count` characters
    if len < (unmasked_char_count * 2 + min_masked_char_count) {
        0
    // For showing first and last `unmasked_char_count` characters
    } else {
        unmasked_char_count
    };
    let mask_end_index = len - unmasked_char_count - 1;
    let range = mask_start_index..=mask_end_index;

    val.chars()
        .enumerate()
        .fold(String::new(), |mut acc, (index, ch)| {
            if ch.is_alphanumeric() && range.contains(&index) {
                acc.push('*');
            } else {
                acc.push(ch);
            }
            acc
        })
}

/// Masked bank account
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MaskedBankAccount(Secret<String>);
impl From<String> for MaskedBankAccount {
    fn from(src: String) -> Self {
        let masked_value = apply_mask(src.as_ref(), 4, 4);
        Self(Secret::from(masked_value))
    }
}
impl From<Secret<String>> for MaskedBankAccount {
    fn from(secret: Secret<String>) -> Self {
        Self::from(secret.expose())
    }
}
