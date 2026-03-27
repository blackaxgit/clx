//! Trust mode management command.
//!
//! Enables/disables trust mode (auto-allow all commands) with time-limited
//! JSON tokens for safety.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Result, bail};
use chrono::{DateTime, Duration, Utc};
use clap::Subcommand;
use colored::Colorize;

use clx_core::config::Config;
use clx_core::types::TrustToken;

use crate::Cli;

/// Trust mode subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum TrustAction {
    /// Enable trust mode (auto-allow all commands)
    On {
        /// Duration string: 5m, 30m, 1h, 2h, 4h, 8h, 24h (default: from config)
        #[arg(short, long)]
        duration: Option<String>,

        /// Bind trust to the current Claude Code session
        #[arg(long)]
        session: bool,
    },

    /// Disable trust mode immediately
    Off,

    /// Show current trust mode status
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Parse a duration string like "5m", "30m", "1h", "2h" into seconds.
fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("Duration string is empty");
    }

    let (num_part, suffix) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));

    let num: u64 = num_part
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid duration number: '{num_part}'"))?;

    let secs = match suffix {
        "m" | "min" => num.checked_mul(60),
        "h" | "hr" => num.checked_mul(3600),
        "s" | "sec" => Some(num),
        "" => {
            // Bare number: assume minutes
            num.checked_mul(60)
        }
        _ => bail!("Unknown duration suffix: '{suffix}'. Use m (minutes) or h (hours)"),
    };

    secs.ok_or_else(|| anyhow::anyhow!("Duration overflow"))
}

/// Format remaining seconds as a human-readable string.
fn format_remaining(secs: i64) -> String {
    if secs <= 0 {
        return "expired".to_string();
    }
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

/// Token file path.
fn token_path() -> std::path::PathBuf {
    clx_core::paths::clx_dir().join(".trust_mode_token")
}

/// Read and validate a trust token. Returns `None` if missing, expired, or invalid.
fn read_valid_token() -> Option<TrustToken> {
    let path = token_path();
    let content = fs::read_to_string(&path).ok()?;
    let token: TrustToken = serde_json::from_str(&content).ok()?;

    let expires = DateTime::parse_from_rfc3339(&token.expires_at)
        .ok()?
        .with_timezone(&Utc);
    if Utc::now() < expires {
        Some(token)
    } else {
        // Expired — clean up
        let _ = fs::remove_file(&path);
        None
    }
}

/// Handle `clx trust` command.
pub async fn cmd_trust(cli: &Cli, action: TrustAction) -> Result<()> {
    match action {
        TrustAction::On { duration, session } => handle_on(cli, duration.as_ref(), session),
        TrustAction::Off => handle_off(cli),
        TrustAction::Status { json } => handle_status(cli, json),
    }
}

fn handle_on(cli: &Cli, duration_str: Option<&String>, session: bool) -> Result<()> {
    let config = Config::load().unwrap_or_default();
    let max_secs = config.validator.trust_mode_max_duration;
    let default_secs = config.validator.trust_mode_default_duration;
    let min_secs: u64 = 300; // 5 minutes

    let duration_secs = match duration_str {
        Some(s) => parse_duration(s)?,
        None => default_secs,
    };

    if duration_secs < min_secs {
        bail!(
            "Duration too short: minimum is {}",
            format_remaining(i64::try_from(min_secs).unwrap_or(i64::MAX))
        );
    }
    if duration_secs > max_secs {
        bail!(
            "Duration too long: maximum is {} (configurable via trust_mode_max_duration)",
            format_remaining(i64::try_from(max_secs).unwrap_or(i64::MAX))
        );
    }

    let now = Utc::now();
    let expires = now + Duration::seconds(i64::try_from(duration_secs).unwrap_or(i64::MAX));

    let session_id = if session {
        std::env::var("CLAUDE_CODE_SESSION_ID").ok()
    } else {
        None
    };

    let token = TrustToken {
        enabled_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        duration_secs,
        session_id: session_id.clone(),
        enabled_by: "cli".to_string(),
    };

    let path = token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json_content = serde_json::to_string_pretty(&token)?;
    fs::write(&path, &json_content)?;

    // Set file permissions to 0600
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    if cli.json {
        let output = serde_json::json!({
            "status": "enabled",
            "expires_at": token.expires_at,
            "duration_secs": duration_secs,
            "session_bound": session_id.is_some(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "{} Trust mode {} for {}",
            "\u{2713}".green().bold(),
            "enabled".green().bold(),
            format_remaining(i64::try_from(duration_secs).unwrap_or(i64::MAX)),
        );
        println!("  Expires: {}", expires.format("%Y-%m-%d %H:%M:%S UTC"));
        if session_id.is_some() {
            println!("  Bound to current session");
        }
        println!(
            "  {}",
            "All commands will be auto-allowed without validation.".yellow()
        );
    }

    Ok(())
}

fn handle_off(cli: &Cli) -> Result<()> {
    let path = token_path();
    let existed = path.exists();

    if existed {
        fs::remove_file(&path)?;
    }

    if cli.json {
        let output = serde_json::json!({
            "status": "disabled",
            "was_active": existed,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if existed {
        println!(
            "{} Trust mode {}",
            "\u{2713}".green().bold(),
            "disabled".green(),
        );
    } else {
        println!("Trust mode was not active.");
    }

    Ok(())
}

fn handle_status(cli: &Cli, json_flag: bool) -> Result<()> {
    let use_json = json_flag || cli.json;
    let token = read_valid_token();

    if use_json {
        let output = match &token {
            Some(t) => {
                let expires = DateTime::parse_from_rfc3339(&t.expires_at)
                    .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));
                let remaining = (expires - Utc::now()).num_seconds().max(0);
                serde_json::json!({
                    "active": true,
                    "enabled_at": t.enabled_at,
                    "expires_at": t.expires_at,
                    "remaining_secs": remaining,
                    "duration_secs": t.duration_secs,
                    "session_bound": t.session_id.is_some(),
                    "enabled_by": t.enabled_by,
                })
            }
            None => {
                serde_json::json!({
                    "active": false,
                })
            }
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        match &token {
            Some(t) => {
                let expires = DateTime::parse_from_rfc3339(&t.expires_at)
                    .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));
                let remaining = (expires - Utc::now()).num_seconds().max(0);

                println!(
                    "{} Trust mode is {}",
                    "\u{2713}".green().bold(),
                    "ACTIVE".green().bold(),
                );
                println!("  Remaining: {}", format_remaining(remaining).yellow());
                println!("  Expires:   {}", expires.format("%Y-%m-%d %H:%M:%S UTC"));
                if t.session_id.is_some() {
                    println!("  Session:   bound to current session");
                }
            }
            None => {
                println!(
                    "{} Trust mode is {}",
                    "\u{2717}".dimmed(),
                    "inactive".dimmed(),
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert_eq!(parse_duration("24h").unwrap(), 86400);
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("300s").unwrap(), 300);
    }

    #[test]
    fn parse_duration_bare_number_is_minutes() {
        assert_eq!(parse_duration("10").unwrap(), 600);
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn parse_duration_empty() {
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn format_remaining_hours_and_minutes() {
        assert_eq!(format_remaining(3661), "1h 1m");
        assert_eq!(format_remaining(1800), "30m");
    }

    #[test]
    fn format_remaining_expired() {
        assert_eq!(format_remaining(0), "expired");
        assert_eq!(format_remaining(-10), "expired");
    }
}
