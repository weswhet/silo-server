//! The frozen `/api/v1` alpha contract (`internal/api`, 102,780 Go LOC per the port plan).
//!
//! Nothing is ported here yet. V1 feature development is frozen (only critical fixes land on
//! `/api/v1`; see `docs/architecture/api-contract.md`), and this session's time went to the v2
//! wire kit (`silo-api-v2`) and to confirming no v1 or v2 row could be flipped to native this
//! session (see that work's notes on `silo-front`'s row table). Every `/api/v1` row stays
//! `GoProxy`. This crate exists so the workspace layout matches the port plan's crate list and
//! so a later session has a place to start without re-deciding where v1 code lives.

#![doc(hidden)]
