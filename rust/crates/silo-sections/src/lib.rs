//! Port of the pure parts of Go's `internal/sections`: `defaults.go`, `continue_type.go`, and the
//! config builders and title helpers of `generated.go`.

pub mod continue_type;
pub mod defaults;
pub mod generated;

pub use continue_type::ContinueType;
pub use defaults::{
    DEFAULT_ITEM_LIMIT, MAX_ITEM_LIMIT, MediaFolder, PageSection, clamp_item_limit,
    default_home_sections, default_library_sections, default_library_sections_for_type,
    is_video_library_type,
};
