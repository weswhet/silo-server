#!/usr/bin/env python3
"""Regenerates crates/silo-gate/src/mw/route_tables.rs from the Go allowlists.

Run from the repository root: python3 rust/conformance/vectors/generators/mwroutes/gen.py
"""
import re

SCOPES = {
    "ScopeAdminSessionsSummaryRead": "admin:sessions:summary:read",
    "ScopeLibrariesRead": "libraries:read",
    "ScopeAdminUsers": "admin:users",
    "ScopeAdminMonitorRead": "admin:monitor:read",
    "ScopeAdminSessionsControl": "admin:sessions:control",
    "ScopeAdminAccessGroupsRead": "admin:access-groups:read",
}
ROUTE = re.compile(r"http\.Method(\w+), regexp\.MustCompile\(`([^`]+)`")
scopes = open("internal/api/middleware/api_key_scopes.go").read()
playback = open("internal/api/middleware/remote_playback.go").read()
out = [
    "//! Generated from `internal/api/middleware/api_key_scopes.go` and `remote_playback.go` by",
    "//! `rust/conformance/vectors/generators/mwroutes/gen.py`: (method, Go regexp).",
    "",
    "pub const API_KEY_SCOPE_ROUTES: &[(&str, &str, &str)] = &[",
]
current = None
for line in scopes.split("var apiKeyScopeRoutes")[1].split("\n"):
    match = re.match(r"\s*auth\.(Scope\w+): \{", line)
    if match:
        current = SCOPES[match.group(1)]
    match = ROUTE.search(line)
    if match:
        out.append(f'    ("{current}", "{match.group(1).upper()}", r"{match.group(2)}"),')
out += ["];", "", "pub const REMOTE_PLAYBACK_ROUTES: &[(&str, &str)] = &["]
for line in playback.split("var remotePlaybackRoutes")[1].split("func remote")[0].split("\n"):
    match = ROUTE.search(line)
    if match:
        out.append(f'    ("{match.group(1).upper()}", r"{match.group(2)}"),')
out.append("];")
open("rust/crates/silo-gate/src/mw/route_tables.rs", "w").write("\n".join(out) + "\n")
