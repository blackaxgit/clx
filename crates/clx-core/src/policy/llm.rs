//! LLM-based command validation (Layer 1).
//!
//! Uses Ollama to assess the risk of unknown commands when Layer 0
//! (deterministic rules) returns Ask.

use std::fs;
use tracing::{debug, warn};

use crate::ollama::OllamaClient;

use super::PolicyEngine;
use super::cache::{ValidationCache, compute_cache_key};
use super::types::{LlmValidationResponse, PolicyDecision};

/// Default prompt template for LLM-based command validation
pub const DEFAULT_VALIDATOR_PROMPT: &str = r#"You are a command safety validator. Evaluate WHAT a command DOES, not WHO runs it.

Working directory: {{working_dir}}
Command: {{command}}

Respond in JSON only:
{"risk_score": 1-10, "reasoning": "brief explanation", "category": "safe|caution|dangerous|critical"}

Scoring:
- 1-3 (safe): Read-only, informational, no side effects
- 4-7 (caution): Modifies state but reversible, or unclear intent
- 8-10 (dangerous): Destructive, irreversible, or data loss risk

CRITICAL: Evaluate the ACTION, ignore access level.
- User (root, admin, etc.) is IRRELEVANT. The developer already has authorized access.
- "ssh root@host read-command" is SAFE. The risk is in WHAT runs, not WHERE or AS WHOM.

SSH commands: evaluate the REMOTE command only.
- Read-only remote (list, info, show, status, get, describe, view, check, version, log, cat, ls, grep, tail, df, free, uptime, ps) = safe (1-3)
- Destructive remote (rm, kill, stop, restart, reboot, dd, mkfs, drop, delete, truncate) = dangerous (8-10)
- No remote command (interactive session) = caution (4)

Command name heuristics: if a command name contains "list", "info", "show", "status", "get", "check", "view", "version", "describe", "search" — it is almost certainly read-only (1-2).

Security patterns to scan for (score 8-10):
- Supply chain: `curl|bash`, `wget|sh`, custom registry URLs (--index-url, --registry), typosquatted package names
- Credential exposure: API keys in arguments, printing .env files, exporting secrets via env vars
- Container escapes: `docker run --privileged`, `--pid=host`, `--net=host`, mounting host root (`-v /:/`)
- Network exfiltration: curl/wget posting sensitive files, `nc -e` reverse shells, DNS tunneling
- Destructive ops: `rm -rf /`, `dd if=/dev/zero`, `mkfs` on mounted volumes, recursive `chmod 777`

Only evaluate the command itself. Do not consider intent."#;

impl PolicyEngine {
    /// Evaluate a command using Layer 1 LLM-based validation
    ///
    /// This method should only be called when Layer 0 returns Ask (unknown command).
    /// It uses Ollama to assess the risk of the command and returns a decision.
    ///
    /// # Arguments
    ///
    /// * `tool_name` - The tool being invoked (e.g., "Bash")
    /// * `command` - The command to evaluate
    /// * `working_dir` - The working directory for command execution
    /// * `ollama` - The Ollama client for LLM inference
    /// * `cache` - Optional cache for storing/retrieving results
    ///
    /// # Returns
    ///
    /// A policy decision based on LLM risk assessment:
    /// - Risk score 1-3: Allow
    /// - Risk score 4-7: Ask (with reasoning)
    /// - Risk score 8-10: Deny (with reasoning)
    /// - On error/timeout: Ask with "LLM unavailable" reason
    pub async fn evaluate_with_llm(
        &self,
        _tool_name: &str,
        command: &str,
        working_dir: &str,
        ollama: &OllamaClient,
        cache: Option<&ValidationCache>,
    ) -> PolicyDecision {
        // Check rate limit first
        if !self.rate_limiter.check() {
            warn!("L1 rate limit exceeded");
            return PolicyDecision::Ask {
                reason: "Rate limit exceeded \u{2014} manual confirmation required".to_string(),
            };
        }

        // Check cache
        let cache_key = compute_cache_key(command, working_dir);
        if let Some(cache) = cache
            && let Some(cached_decision) = cache.get(&cache_key)
        {
            debug!("L1 cache hit for command: {}", command);
            return cached_decision;
        }

        // Load prompt template
        let prompt_template = load_validator_prompt();

        // JSON-encode both command and working_dir to prevent prompt injection
        let escaped_command = serde_json::to_string(command).unwrap_or_else(|_| {
            format!("\"{}\"", command.replace('\\', "\\\\").replace('"', "\\\""))
        });
        let escaped_working_dir = serde_json::to_string(working_dir).unwrap_or_else(|_| {
            format!(
                "\"{}\"",
                working_dir.replace('\\', "\\\\").replace('"', "\\\"")
            )
        });

        // Substitute template variables with escaped values
        let prompt = prompt_template
            .replace("{{working_dir}}", &escaped_working_dir)
            .replace("{{command}}", &escaped_command);

        debug!("L1 evaluating command: {} in {}", command, working_dir);

        // Call Ollama for LLM inference
        let result = ollama.generate(&prompt, None).await;

        let decision = match result {
            Ok(response) => {
                // Parse the JSON response
                match parse_llm_response(&response) {
                    Ok(validation) => {
                        // Check for prompt injection markers in the response
                        if is_suspicious_llm_response(&validation.reasoning) {
                            warn!("Potential prompt injection detected in LLM response");
                            PolicyDecision::Ask {
                                reason: "Suspicious LLM response detected \u{2014} manual review required"
                                    .to_string(),
                            }
                        } else {
                            let decision = risk_score_to_decision(
                                validation.risk_score,
                                &validation.reasoning,
                                &validation.category,
                            );
                            debug!(
                                "L1 decision: {:?} (score={}, category={})",
                                decision, validation.risk_score, validation.category
                            );
                            decision
                        }
                    }
                    Err(e) => {
                        warn!(
                            "L1 failed to parse LLM response: {} - response: {}",
                            e, response
                        );
                        PolicyDecision::Ask {
                            reason: "LLM response parsing failed".to_string(),
                        }
                    }
                }
            }
            Err(e) => {
                warn!("L1 LLM unavailable: {}", e);
                PolicyDecision::Ask {
                    reason: "LLM unavailable".to_string(),
                }
            }
        };

        // Store in cache
        if let Some(cache) = cache {
            cache.insert(cache_key, decision.clone());
        }

        decision
    }
}

/// Maximum allowed size for a prompt template (50 KB).
const MAX_PROMPT_TEMPLATE_SIZE: usize = 50 * 1024;

/// Map common Unicode homoglyph characters to their ASCII equivalents.
///
/// Returns `Some(ascii_char)` if the character is a known homoglyph, or `None`
/// if it should be stripped (zero-width chars, combining accents, other non-ASCII).
/// This prevents attackers from using Cyrillic, full-width, or other lookalike
/// characters to evade pattern detection.
fn homoglyph_to_ascii(c: char) -> Option<char> {
    match c {
        // Cyrillic lowercase homoglyphs (already lowercased by caller)
        '\u{0430}' => Some('a'), // а → a
        '\u{0435}' => Some('e'), // е → e
        '\u{0456}' => Some('i'), // і → i
        '\u{043E}' => Some('o'), // о → o
        '\u{0440}' => Some('p'), // р → p
        '\u{0441}' => Some('c'), // с → c
        '\u{0443}' => Some('y'), // у → y
        '\u{0445}' => Some('x'), // х → x
        '\u{044A}' => Some('b'), // ъ → not really, skip
        '\u{0455}' => Some('s'), // ѕ → s
        '\u{0458}' => Some('j'), // ј → j
        '\u{04BB}' => Some('h'), // һ → h

        // Full-width Latin lowercase (U+FF41..U+FF5A)
        '\u{FF41}'..='\u{FF5A}' => Some((b'a' + (c as u32 - 0xFF41) as u8) as char),

        // Full-width Latin uppercase (U+FF21..U+FF3A) — lowercased input means
        // these rarely appear, but handle for completeness
        '\u{FF21}'..='\u{FF3A}' => Some((b'a' + (c as u32 - 0xFF21) as u8) as char),

        // Full-width digits (U+FF10..U+FF19)
        '\u{FF10}'..='\u{FF19}' => Some((b'0' + (c as u32 - 0xFF10) as u8) as char),

        // Zero-width and invisible characters — strip (return None)
        '\u{200B}' | // Zero-width space
        '\u{200C}' | // Zero-width non-joiner
        '\u{200D}' | // Zero-width joiner
        '\u{FEFF}' | // BOM / zero-width no-break space
        '\u{00AD}'   // Soft hyphen
            => None,

        // Combining diacritical marks (U+0300..U+036F) — strip
        '\u{0300}'..='\u{036F}' => None,

        // Everything else non-ASCII — strip
        _ => None,
    }
}

/// Validate a prompt template for safety and correctness.
///
/// Returns `Ok(())` if the template passes all checks, or `Err(reason)` describing
/// why the template was rejected. This prevents prompt template injection attacks
/// where an attacker modifies the user-writable template file to bypass security.
///
/// # Checks
///
/// 1. **Size limit** - Template must not exceed 50 KB (denial-of-service prevention).
/// 2. **Required placeholders** - Must contain `{{command}}` and `{{working_dir}}`.
/// 3. **JSON output requirement** - Must contain the word "JSON" (case-insensitive).
/// 4. **Bypass pattern detection** - Rejects templates containing injection patterns.
pub(crate) fn validate_prompt_template(content: &str) -> Result<(), String> {
    // 1. Size limit
    if content.len() > MAX_PROMPT_TEMPLATE_SIZE {
        return Err(format!(
            "Template exceeds maximum size ({} bytes > {} bytes)",
            content.len(),
            MAX_PROMPT_TEMPLATE_SIZE
        ));
    }

    // 2. Required placeholders
    if !content.contains("{{command}}") {
        return Err("Template missing required placeholder: {{command}}".to_string());
    }
    if !content.contains("{{working_dir}}") {
        return Err("Template missing required placeholder: {{working_dir}}".to_string());
    }

    // 3. JSON output requirement (case-insensitive)
    let lower = content.to_lowercase();
    if !lower.contains("json") {
        return Err("Template must contain 'JSON' keyword for structured output".to_string());
    }

    // 4. Bypass pattern detection (case-insensitive)
    //
    // Normalize the text before pattern matching to prevent bypass attacks:
    // - Map common Unicode homoglyphs to ASCII equivalents (Cyrillic а→a, і→i, etc.)
    // - Strip remaining non-ASCII chars (zero-width spaces, combining accents, etc.)
    // - Collapse whitespace to single spaces to block word-splitting attacks
    //   (e.g., "ignore\n\nprevious" or "ignore     previous").
    let ascii_only: String = lower
        .chars()
        .filter_map(|c| {
            if c.is_ascii() {
                Some(c)
            } else {
                homoglyph_to_ascii(c)
            }
        })
        .collect();
    let normalized: String = ascii_only.split_whitespace().collect::<Vec<_>>().join(" ");

    let bypass_patterns: &[&str] = &[
        // Original patterns
        "ignore previous",
        "ignore above",
        "always safe",
        "always allow",
        "always approve",
        "always return",
        "all commands are safe",
        "everything is safe",
        "every command is safe",
        "no command is dangerous",
        // F2: Semantic variations
        "disregard prior",
        "disregard previous",
        "skip previous",
        "forget earlier",
        "forget previous",
        "permit everything",
        "accept all",
        "approve all",
        "disable checks",
        "disable validation",
        "bypass rules",
        "bypass checks",
        "remove restrictions",
        "override rules",
        "skip validation",
    ];

    for pattern in bypass_patterns {
        if normalized.contains(pattern) {
            return Err(format!(
                "Template contains suspicious bypass pattern: '{pattern}'"
            ));
        }
    }

    // Negation compound detection: "never" + a security verb anywhere in the text.
    // Catches patterns like "never deny a command" or "never reject requests".
    let negation_verbs: &[&str] = &["deny", "reject", "block", "refuse", "flag", "restrict"];

    if normalized.contains("never") {
        for verb in negation_verbs {
            if normalized.contains(verb) {
                return Err(format!(
                    "Template contains suspicious negation pattern: 'never' + '{verb}'"
                ));
            }
        }
    }

    // Detect hardcoded JSON responses that fix the outcome.
    // We check for patterns like "risk_score": 0, "safe": true, etc.
    // with optional whitespace around the colon.
    // Uses normalized text to catch whitespace-padded evasions.
    let hardcoded_patterns: &[(&str, &[&str])] = &[
        // ("key to find", &["value suffixes that are suspicious"])
        ("\"risk_score\"", &[": 0", ":0"]),
        ("\"safe\"", &[": true", ":true"]),
        // F4: Expanded hardcoded value patterns
        ("\"dangerous\"", &[": false", ":false"]),
        ("\"risky\"", &[": false", ":false"]),
        ("\"threat\"", &[": false", ":false"]),
        ("\"danger\"", &[": 0", ":0", ": false", ":false"]),
    ];

    for &(key, values) in hardcoded_patterns {
        let key_lower = key.to_lowercase();
        if let Some(key_pos) = normalized.find(&key_lower) {
            let after_key = &normalized[key_pos + key_lower.len()..];
            // Check within a small window after the key (allow for whitespace)
            let window = &after_key[..after_key.len().min(20)];
            for &val in values {
                if window.contains(val) {
                    return Err(format!(
                        "Template contains hardcoded response pattern: {key} {val}"
                    ));
                }
            }
        }
    }

    // Detect patterns like "score": 0 or score followed by 0 (various spacings)
    // that attempt to fix risk assessment at zero
    let score_zero_patterns: &[&str] = &[
        "\"score\": 0",
        "\"score\":0",
        "risk_score: 0",
        "risk_score:0",
    ];
    for pattern in score_zero_patterns {
        if normalized.contains(pattern) {
            return Err(format!(
                "Template contains hardcoded score pattern: '{pattern}'"
            ));
        }
    }

    Ok(())
}

/// Load the validator prompt template from ~/.clx/prompts/validator.txt or use default
pub(crate) fn load_validator_prompt() -> String {
    let prompt_path = crate::paths::validator_prompt_path();
    if prompt_path.exists() {
        if !is_file_safe(&prompt_path) {
            warn!(
                "Validator prompt file {} has unsafe permissions (world-writable), using default prompt",
                prompt_path.display()
            );
            return DEFAULT_VALIDATOR_PROMPT.to_string();
        }
        if let Ok(content) = fs::read_to_string(&prompt_path) {
            if let Err(reason) = validate_prompt_template(&content) {
                warn!(
                    "Validator prompt file {} failed validation: {}, using default prompt",
                    prompt_path.display(),
                    reason
                );
                return DEFAULT_VALIDATOR_PROMPT.to_string();
            }
            debug!("Loaded validator prompt from {}", prompt_path.display());
            return content;
        }
    }
    debug!("Using default validator prompt");
    DEFAULT_VALIDATOR_PROMPT.to_string()
}

/// Check if a file has safe permissions (not world-writable).
///
/// On Unix, verifies the file is not world-writable (mode & 0o002 == 0).
/// On non-Unix platforms, always returns true (check skipped).
#[cfg(unix)]
fn is_file_safe(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(metadata) = path.metadata() {
        let mode = metadata.permissions().mode();
        // Must not be world-writable
        (mode & 0o002) == 0
    } else {
        false
    }
}

#[cfg(not(unix))]
fn is_file_safe(_path: &std::path::Path) -> bool {
    true // Skip permission check on non-Unix platforms
}

/// Detect prompt injection markers in an LLM reasoning response.
///
/// Returns `true` if the response text contains patterns commonly associated with
/// prompt injection attacks (e.g., "ignore previous instructions", "jailbreak", etc.).
pub(crate) fn is_suspicious_llm_response(reasoning: &str) -> bool {
    let lower = reasoning.to_lowercase();

    // Compound patterns: both words must appear anywhere in the text
    let compound_patterns: &[(&str, &str)] = &[
        ("ignore", "instruction"),
        ("disregard", "instruction"),
        ("override", "instruction"),
        ("ignore", "previous"),
        ("forget", "prompt"),
        ("forget", "rules"),
        ("bypass", "safety"),
        ("bypass", "security"),
    ];

    // Single patterns: substring match
    let single_patterns: &[&str] = &[
        "previous instruction",
        "system prompt",
        "you are now",
        "new instructions",
        "ignore above",
        "ignore everything",
        "pretend you",
        "act as if",
        "jailbreak",
        "dan mode",
    ];

    compound_patterns
        .iter()
        .any(|(w1, w2)| lower.contains(w1) && lower.contains(w2))
        || single_patterns.iter().any(|p| lower.contains(p))
}

/// Parse the LLM response JSON into a validation response
pub(crate) fn parse_llm_response(response: &str) -> Result<LlmValidationResponse, String> {
    // Try to find JSON in the response (LLM might include extra text)
    let json_start = response
        .find('{')
        .ok_or("No JSON object found in response")?;
    let json_end = response
        .rfind('}')
        .ok_or("No closing brace found in response")?;

    if json_end <= json_start {
        return Err("Invalid JSON structure".to_string());
    }

    let json_str = &response[json_start..=json_end];

    // Parse the JSON
    serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {e}"))
}

/// Convert a risk score to a policy decision
pub(crate) fn risk_score_to_decision(
    risk_score: u8,
    reasoning: &str,
    category: &str,
) -> PolicyDecision {
    match risk_score {
        1..=3 => PolicyDecision::Allow,
        // L1 (LLM) never hard-denies — only L0 blacklist can hard-deny.
        // LLM can be wrong, so the user always gets final say via confirmation dialog.
        _ => PolicyDecision::Ask {
            reason: format!("[{category}] {reasoning}"),
        },
    }
}
