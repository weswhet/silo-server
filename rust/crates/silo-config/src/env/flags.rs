//! The `silo` command line: Go's `flag` package and the flags and subcommands `cmd/silo` defines.

use crate::config::{DEFAULT_JELLYFIN_WEB_INSTALL_DIR, DEFAULT_JELLYFIN_WEB_VERSION};
use crate::goparse::{parse_bool, parse_int};
use silo_gocompat::strconv::quote;
use silo_gocompat::strings::trim_space;

enum Target<'a> {
    Str(&'a mut String),
    Bool(&'a mut bool),
    Int64(&'a mut i64),
}

/// What `FlagSet.Parse` returned in place of success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagError {
    /// `flag.ErrHelp`: `-h` or `-help`, which no flag here defines.
    Help,
    /// Any other parse failure, with Go's message.
    Invalid(String),
}

impl std::fmt::Display for FlagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlagError::Help => f.write_str("flag: help requested"),
            FlagError::Invalid(m) => f.write_str(m),
        }
    }
}

// flag.FlagSet.Parse: returns the positional arguments left after the flags.
fn parse_flags(defs: &mut [(&str, Target<'_>)], args: &[String]) -> Result<Vec<String>, FlagError> {
    let mut rest = args;
    loop {
        let Some(s) = rest.first() else {
            return Ok(Vec::new());
        };
        if s.len() < 2 || !s.starts_with('-') {
            return Ok(rest.to_vec());
        }
        let mut num_minuses = 1;
        if s.as_bytes()[1] == b'-' {
            num_minuses += 1;
            if s.len() == 2 {
                return Ok(rest[1..].to_vec());
            }
        }
        let name_all = &s[num_minuses..];
        if name_all.is_empty() || name_all.starts_with('-') || name_all.starts_with('=') {
            return Err(FlagError::Invalid(format!("bad flag syntax: {s}")));
        }
        rest = &rest[1..];
        let (name, value) = match name_all.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (name_all, None),
        };
        let Some((_, target)) = defs.iter_mut().find(|(n, _)| *n == name) else {
            if name == "help" || name == "h" {
                return Err(FlagError::Help);
            }
            return Err(FlagError::Invalid(format!(
                "flag provided but not defined: -{name}"
            )));
        };
        match target {
            Target::Bool(b) => {
                if let Some(v) = value {
                    match parse_bool(&v) {
                        Ok(x) => **b = x,
                        Err(_) => {
                            return Err(FlagError::Invalid(format!(
                                "invalid boolean value {} for -{name}: parse error",
                                quote(&v)
                            )));
                        }
                    }
                } else {
                    **b = true;
                }
            }
            other => {
                let v = match value {
                    Some(v) => v,
                    None => {
                        let Some(next) = rest.first() else {
                            return Err(FlagError::Invalid(format!(
                                "flag needs an argument: -{name}"
                            )));
                        };
                        rest = &rest[1..];
                        next.clone()
                    }
                };
                match other {
                    Target::Str(t) => **t = v,
                    Target::Int64(t) => match parse_int(&v, 0, 64) {
                        Ok(x) => **t = x,
                        Err(e) => {
                            let why = match e.kind {
                                crate::goparse::NumErrorKind::Syntax => "parse error",
                                crate::goparse::NumErrorKind::Range => "value out of range",
                            };
                            return Err(FlagError::Invalid(format!(
                                "invalid value {} for flag -{name}: {why}",
                                quote(&v)
                            )));
                        }
                    },
                    Target::Bool(_) => {}
                }
            }
        }
    }
}

/// The flags of the `silo` server command.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServerFlags {
    pub env: String,
    pub migrate_only: bool,
    pub migrate_status: bool,
    /// The version to keep; -1 means no rollback was asked for.
    pub migrate_down_to: i64,
    pub args: Vec<String>,
}

/// Parses `-env`, `-migrate-only`, `-migrate-status`, and `-migrate-down-to`.
pub fn parse_server_flags(args: &[String]) -> Result<ServerFlags, FlagError> {
    let mut env = ".env".to_owned();
    let mut migrate_only = false;
    let mut migrate_status = false;
    let mut migrate_down_to = -1i64;
    let rest = parse_flags(
        &mut [
            ("env", Target::Str(&mut env)),
            ("migrate-only", Target::Bool(&mut migrate_only)),
            ("migrate-status", Target::Bool(&mut migrate_status)),
            ("migrate-down-to", Target::Int64(&mut migrate_down_to)),
        ],
        args,
    )?;
    Ok(ServerFlags {
        env,
        migrate_only,
        migrate_status,
        migrate_down_to,
        args: rest,
    })
}

/// `silo compat-web <command> [-dir] [-version] [-source]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CompatWebCommand {
    pub command: String,
    pub dir: String,
    pub version: String,
    pub source: String,
}

/// `jellycompat.DefaultWebSourceURL`.
pub const DEFAULT_WEB_SOURCE_URL: &str = "https://github.com/jellyfin/jellyfin-web.git";

/// Parses the arguments after `compat-web`.
pub fn parse_compat_web_command(args: &[String]) -> Result<CompatWebCommand, String> {
    let Some(command) = args.first() else {
        return Err("usage: silo compat-web {status|install|update|remove}".to_owned());
    };
    let mut dir = DEFAULT_JELLYFIN_WEB_INSTALL_DIR.to_owned();
    let mut version = DEFAULT_JELLYFIN_WEB_VERSION.to_owned();
    let mut source = DEFAULT_WEB_SOURCE_URL.to_owned();
    parse_flags(
        &mut [
            ("dir", Target::Str(&mut dir)),
            ("version", Target::Str(&mut version)),
            ("source", Target::Str(&mut source)),
        ],
        &args[1..],
    )
    .map_err(|e| e.to_string())?;
    if !matches!(command.as_str(), "status" | "install" | "update" | "remove") {
        return Err(format!("unknown compat-web command {}", quote(command)));
    }
    Ok(CompatWebCommand {
        command: command.clone(),
        dir,
        version,
        source,
    })
}

pub const AUTH_COMMAND_USAGE: &str =
    "usage: silo auth local-login enable [-user <name or email> [-temporary-password]] [-env .env]";
pub const OWNER_COMMAND_USAGE: &str = "usage: silo owner set [-env .env] <username>";

/// `silo auth local-login enable`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuthCommand {
    pub env_file: String,
    pub user: String,
    pub temporary_password: bool,
}

/// `parseAuthCommand`.
pub fn parse_auth_command(args: &[String]) -> Result<AuthCommand, String> {
    if args.len() < 2 || args[0] != "local-login" || args[1] != "enable" {
        return Err(AUTH_COMMAND_USAGE.to_owned());
    }
    let mut env = ".env".to_owned();
    let mut user = String::new();
    let mut temporary = false;
    let rest = parse_flags(
        &mut [
            ("env", Target::Str(&mut env)),
            ("user", Target::Str(&mut user)),
            ("temporary-password", Target::Bool(&mut temporary)),
        ],
        &args[2..],
    )
    .map_err(|_| AUTH_COMMAND_USAGE.to_owned())?;
    if !rest.is_empty() {
        return Err(AUTH_COMMAND_USAGE.to_owned());
    }
    let user = trim_space(&user).to_owned();
    if temporary && user.is_empty() {
        return Err(AUTH_COMMAND_USAGE.to_owned());
    }
    Ok(AuthCommand {
        env_file: env,
        user,
        temporary_password: temporary,
    })
}

/// `parseOwnerCommand`: `(env file, username)`.
pub fn parse_owner_command(args: &[String]) -> Result<(String, String), String> {
    if args.first().map(String::as_str) != Some("set") {
        return Err(OWNER_COMMAND_USAGE.to_owned());
    }
    let mut env = ".env".to_owned();
    let rest = parse_flags(&mut [("env", Target::Str(&mut env))], &args[1..])
        .map_err(|_| OWNER_COMMAND_USAGE.to_owned())?;
    if rest.len() != 1 || rest[0].is_empty() {
        return Err(OWNER_COMMAND_USAGE.to_owned());
    }
    Ok((env, rest[0].clone()))
}
