//! `catalog.foldSearchDiacritics`, which must agree with the SQL function
//! `public.fold_search_diacritics` so queries fold like the stored titles they are compared with.

use crate::contentid::{nfc, nfd};

/// `foldSearchDiacritics`.
pub fn fold_search_diacritics(input: &str) -> String {
    if input.is_ascii() {
        return input.to_owned();
    }
    let stripped: String = nfd(input)
        .chars()
        .filter(|c| !('\u{300}'..='\u{36f}').contains(c))
        .collect();
    let mut out = String::with_capacity(stripped.len());
    for c in nfc(&stripped).chars() {
        match c {
            'Ø' => out.push('O'),
            'ø' => out.push('o'),
            'Đ' | 'Ð' => out.push('D'),
            'đ' | 'ð' => out.push('d'),
            'Ł' => out.push('L'),
            'ł' => out.push('l'),
            'Ħ' => out.push('H'),
            'ħ' => out.push('h'),
            'ı' => out.push('i'),
            'Ŧ' => out.push('T'),
            'ŧ' => out.push('t'),
            'Ŀ' => out.push('L'),
            'ŀ' => out.push('l'),
            'ß' => out.push_str("ss"),
            'ẞ' => out.push_str("SS"),
            'æ' => out.push_str("ae"),
            'Æ' => out.push_str("AE"),
            'œ' => out.push_str("oe"),
            'Œ' => out.push_str("OE"),
            other => out.push(other),
        }
    }
    out
}
