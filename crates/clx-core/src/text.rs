//! Text parsing utilities for CLAUDE.md and other configuration files.

/// Extract sections from a CLAUDE.md file that contain critical/strict markers.
///
/// Looks for lines containing markers like `[CRITICAL]`, `[MUST]`, `[STRICT]`, `(STRICT)`,
/// `IMPORTANT:`, `MANDATORY`, or headings containing "non-negotiable".
///
/// Returns a `Vec<String>` where each element is either a full section (heading + body)
/// that was marked as critical, or an individual critical line found outside a section.
#[must_use]
pub fn extract_critical_sections(content: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut in_critical_section = false;
    let mut current_section = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Check for critical section markers
        let is_critical_marker = trimmed.contains("[CRITICAL]")
            || trimmed.contains("[MUST]")
            || trimmed.contains("[STRICT]")
            || trimmed.contains("(STRICT)")
            || trimmed.contains("IMPORTANT:")
            || trimmed.contains("MANDATORY")
            || (trimmed.starts_with('#') && trimmed.to_lowercase().contains("non-negotiable"));

        // Start of a new heading
        if trimmed.starts_with('#') {
            // Save previous critical section if any
            if in_critical_section && !current_section.is_empty() {
                sections.push(current_section.clone());
            }

            in_critical_section = is_critical_marker;
            current_section = if in_critical_section {
                format!("{line}\n")
            } else {
                String::new()
            };
        } else if in_critical_section {
            // Continue building critical section
            current_section.push_str(line);
            current_section.push('\n');
        } else if is_critical_marker {
            // Individual critical line outside a section
            sections.push(line.to_string());
        }
    }

    // Don't forget the last section
    if in_critical_section && !current_section.is_empty() {
        sections.push(current_section);
    }

    sections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_empty_content() {
        let result = extract_critical_sections("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_no_critical_markers() {
        let content = "# Normal heading\nSome text\n## Another heading\nMore text\n";
        let result = extract_critical_sections(content);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_critical_heading() {
        let content = "# Rules [CRITICAL]\nMust do X\nMust do Y\n# Other\nNon-critical\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("[CRITICAL]"));
        assert!(result[0].contains("Must do X"));
        assert!(result[0].contains("Must do Y"));
    }

    #[test]
    fn test_extract_strict_heading() {
        let content = "## Scope [STRICT]\nRule 1\nRule 2\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("[STRICT]"));
    }

    #[test]
    fn test_extract_parenthetical_strict() {
        let content = "## Policy (STRICT)\nDo this\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("(STRICT)"));
    }

    #[test]
    fn test_extract_important_line_outside_section() {
        let content = "Some intro\nIMPORTANT: Do not skip this\nMore text\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("IMPORTANT:"));
    }

    #[test]
    fn test_extract_mandatory_line() {
        let content = "Intro\nThis is MANDATORY for all agents\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("MANDATORY"));
    }

    #[test]
    fn test_extract_non_negotiable_heading() {
        let content = "# Non-Negotiable Rules\nRule A\nRule B\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("Non-Negotiable"));
    }

    #[test]
    fn test_extract_must_heading() {
        let content = "## Requirements [MUST]\nDo X\n## Other\nNon-critical\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("[MUST]"));
        assert!(result[0].contains("Do X"));
    }

    #[test]
    fn test_extract_multiple_critical_sections() {
        let content = "# A [CRITICAL]\nText A\n# B\nNormal\n# C [STRICT]\nText C\n";
        let result = extract_critical_sections(content);
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("[CRITICAL]"));
        assert!(result[1].contains("[STRICT]"));
    }
}
