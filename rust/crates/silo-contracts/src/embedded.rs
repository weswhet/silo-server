//! The embedded `contracts/` and `migrations/sql/` trees.

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

/// A contract file by its path under `contracts/`, byte for byte.
pub fn contract(path: &str) -> Option<&'static [u8]> {
    CONTRACT_FILES
        .binary_search_by(|(name, _)| (*name).cmp(path))
        .ok()
        .map(|i| CONTRACT_FILES[i].1)
}

/// The contract files directly under `dir`, with their names relative to `dir`.
pub fn contract_dir(dir: &str) -> impl Iterator<Item = (&'static str, &'static [u8])> + use<'_> {
    let prefix = format!("{dir}/");
    CONTRACT_FILES.iter().filter_map(move |(name, bytes)| {
        let rest = name.strip_prefix(prefix.as_str())?;
        (!rest.contains('/')).then_some((rest, *bytes))
    })
}

/// `contracts/api/v2/openapi.json`, which the server serves and digests byte for byte.
pub fn openapi_v2() -> &'static [u8] {
    contract("api/v2/openapi.json").expect("embedded openapi.json")
}
