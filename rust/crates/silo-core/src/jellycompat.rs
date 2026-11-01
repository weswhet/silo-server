//! `internal/jellycompat`: the IDs and image tags Jellyfin clients persist. There is no spec, so these
//! bytes are the only contract.

use silo_gocompat::strings::{to_lower, trim_space};

use crate::contentid;
use crate::goid::{NAMESPACE_OID, NAMESPACE_URL, Uuid};
use crate::hexgo::{encode as hex_encode, hmac_sha256};

/// `EncodedIDType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Kind {
    Library = 1,
    Item = 2,
    MediaSource = 3,
    Season = 4,
    PlaySession = 5,
    Genre = 6,
    Studio = 7,
    Person = 8,
    ImageProxy = 9,
    Collection = 10,
    ThemeSong = 11,
}

impl Kind {
    /// The kind for a byte value, if any.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Library,
            2 => Self::Item,
            3 => Self::MediaSource,
            4 => Self::Season,
            5 => Self::PlaySession,
            6 => Self::Genre,
            7 => Self::Studio,
            8 => Self::Person,
            9 => Self::ImageProxy,
            10 => Self::Collection,
            11 => Self::ThemeSong,
            _ => return None,
        })
    }

    fn namespace(self) -> Uuid {
        let text = match self {
            Self::Item => "0b6716ca-1f61-5987-b17b-f592f04fd6b3",
            Self::Season => "29831b2b-dad5-5a85-b506-4d1fb2da01ed",
            Self::PlaySession => "75a69ca8-f95f-5e9d-ac0a-d34a37b93eb4",
            Self::Genre => "c0cbb8ea-8331-52c0-b160-15e7cf899fb0",
            Self::Studio => "23712982-b769-592d-9360-b4d3f39654db",
            Self::Person => "a4e7c1d6-3b8f-5a2e-9c01-7d6f4e8b2a13",
            Self::Collection => "7f3c2a91-5b64-5c1d-8e07-9a2f4d6b1c35",
            _ => return NAMESPACE_URL,
        };
        Uuid::parse(text).expect("namespace constants parse")
    }

    fn carries_content_id(self) -> bool {
        matches!(self, Self::Item | Self::Season)
    }
}

/// `PseudoUserID`.
pub fn pseudo_user_id(user_id: i64, profile_id: &str) -> Uuid {
    let namespace =
        Uuid::parse("3dfcc388-bf95-5572-bc16-7f1a375992dd").expect("namespace constant parses");
    Uuid::new_sha1(namespace, format!("{user_id}:{profile_id}"))
}

/// `EncodeNumericID`.
pub fn encode_numeric_id(kind: Kind, value: u64) -> Uuid {
    let mut raw = [0u8; 16];
    raw[0] = kind as u8;
    raw[8..].copy_from_slice(&value.to_be_bytes());
    Uuid(raw)
}

/// `packContentIDUUID`.
pub fn pack_content_id_uuid(kind: Kind, content_id: &str) -> Option<Uuid> {
    let payload = contentid::pack(content_id)?;
    if payload.len() > 15 {
        return None;
    }
    let mut raw = [0u8; 16];
    raw[0] = kind as u8;
    raw[1..=payload.len()].copy_from_slice(&payload);
    Some(Uuid(raw))
}

/// `unpackContentIDUUID`: re-packs to confirm the UUID really came from the packer.
pub fn unpack_content_id_uuid(kind: Kind, raw: &str) -> Option<String> {
    let parsed = Uuid::parse(raw)?;
    if parsed.0[0] != kind as u8 || parsed.0[1] == 0 {
        return None;
    }
    let id = contentid::unpack(&parsed.0[1..])?;
    (pack_content_id_uuid(kind, &id)? == parsed).then_some(id)
}

/// What `ResourceIDCodec.EncodeStringID` produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedId {
    pub id: Uuid,
    /// Whether Go records this in its process-local reverse map, without which it cannot be decoded.
    pub needs_reverse_map: bool,
}

/// `ResourceIDCodec.EncodeStringID`, without the map: a numeric value packs statelessly, a content ID
/// packs reversibly, and anything else hashes.
pub fn encode_string_id(kind: Kind, value: &str) -> EncodedId {
    if let Some(numeric) = parse_uint(value) {
        return EncodedId {
            id: encode_numeric_id(kind, numeric),
            needs_reverse_map: false,
        };
    }
    if kind.carries_content_id()
        && let Some(packed) = pack_content_id_uuid(kind, value)
    {
        return EncodedId {
            id: packed,
            needs_reverse_map: false,
        };
    }
    EncodedId {
        id: Uuid::new_sha1(kind.namespace(), value),
        needs_reverse_map: kind != Kind::PlaySession,
    }
}

/// `ResourceIDCodec.DecodeStringID`. `reverse` looks a hashed ID up in the process-local map, which is
/// lost on restart and absent on other nodes.
pub fn decode_string_id(
    kind: Kind,
    raw: &str,
    reverse: impl Fn(&str) -> Option<(Kind, String)>,
) -> Option<String> {
    if kind.carries_content_id()
        && let Some(id) = unpack_content_id_uuid(kind, raw)
    {
        return Some(id);
    }
    if let Some((decoded_kind, value)) = decode_id(raw)
        && decoded_kind == kind as u8
    {
        return Some(value.to_string());
    }
    let (registered_kind, value) = reverse(raw)?;
    (registered_kind == kind).then_some(value)
}

/// `strconv.ParseUint(value, 10, 64)`: digits only, no sign.
fn parse_uint(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// `DecodeID`: only `EncodeNumericID` leaves bytes 1..7 zero.
pub fn decode_id(raw: &str) -> Option<(u8, u64)> {
    let parsed = Uuid::parse(raw)?;
    if parsed.0[1..8].iter().any(|b| *b != 0) {
        return None;
    }
    Some((
        parsed.0[0],
        u64::from_be_bytes(parsed.0[8..].try_into().expect("8 bytes")),
    ))
}

/// `uuid.NewSHA1(uuid.NameSpaceOID, name)` for the recommendation row IDs.
pub fn oid_name_id(name: &str) -> Uuid {
    Uuid::new_sha1(NAMESPACE_OID, name)
}

const IMAGE_TAG_DOMAIN: &str = "silo:jellycompat:image-tag:v1";

/// `tagValue`: the unsigned fallback tag.
pub fn tag_value(raw: &str) -> String {
    use sha1::{Digest, Sha1};
    if raw.is_empty() {
        return String::new();
    }
    hex_encode(&Sha1::digest(raw.as_bytes())[..8])
}

/// `imageTagSigner.Tag`.
pub fn image_tag(secret: &str, seed: &str, fallback_url: &str) -> String {
    if trim_space(seed).is_empty() {
        return tag_value(fallback_url);
    }
    if trim_space(secret).is_empty() {
        return tag_value(seed);
    }
    let sum = hmac_sha256(
        secret.as_bytes(),
        &[IMAGE_TAG_DOMAIN.as_bytes(), &[0], seed.as_bytes()],
    );
    hex_encode(&sum[..8])
}

/// `compatCardImageSize`.
pub const CARD_IMAGE_SIZE: &str = "small";

/// `normalizeImageCacheSize`.
pub fn normalize_image_cache_size(size: &str) -> String {
    let normalized = to_lower(trim_space(size));
    if normalized.is_empty() {
        CARD_IMAGE_SIZE.to_owned()
    } else {
        normalized
    }
}

/// `imageTagSeed`. `updated_at` is the RFC3339Nano text of a non-zero time.
pub fn image_tag_seed(
    route_id: &str,
    image_type: &str,
    size: &str,
    raw_path: &str,
    thumbhash: &str,
    updated_at: Option<&str>,
) -> String {
    let raw_path = trim_space(raw_path);
    let thumbhash = trim_space(thumbhash);
    if raw_path.is_empty() && thumbhash.is_empty() && updated_at.is_none() {
        return String::new();
    }
    let lowered = to_lower(trim_space(image_type));
    let size = normalize_image_cache_size(size);
    let mut parts = vec![trim_space(route_id), &lowered, &size, raw_path, thumbhash];
    if let Some(at) = updated_at {
        parts.push(at);
    }
    parts.join("\0")
}

/// `collageImageTag`: the 16-hex collage key, then the signature over it and the BoxSet route.
pub fn collage_image_tag(secret: &str, route_id: &str, key: &str) -> String {
    let seed = image_tag_seed(
        route_id,
        "Primary",
        CARD_IMAGE_SIZE,
        &format!("collage:{key}"),
        "",
        None,
    );
    format!("{key}{}", image_tag(secret, &seed, ""))
}

/// `compatImageProxyTagSuffix`.
pub const IMAGE_PROXY_TAG_SUFFIX: &str = "-p";

/// `canonicalCompatImageTag`.
pub fn canonical_image_tag(tag: &str) -> &str {
    let tag = trim_space(tag);
    tag.strip_suffix(IMAGE_PROXY_TAG_SUFFIX).unwrap_or(tag)
}

/// The default `jellyfin_compat.server_id`.
pub fn default_server_id() -> Uuid {
    Uuid::new_sha1(NAMESPACE_URL, "https://silo.local/jellycompat")
}
