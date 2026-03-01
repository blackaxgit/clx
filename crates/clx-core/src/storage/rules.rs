//! Learned rules operations
//!
//! Add, query, update counts, and delete learned rules.

use rusqlite::{OptionalExtension, Row, params};
use tracing::{debug, warn};

use super::Storage;
use super::util::parse_datetime;
use crate::types::{LearnedRule, RuleType};

impl Storage {
    /// Add or update a learned rule
    ///
    /// If a rule with the same pattern exists, it will be updated.
    pub fn add_rule(&self, rule: &LearnedRule) -> crate::Result<i64> {
        self.conn.execute(
            "INSERT INTO learned_rules (pattern, rule_type, learned_at, source, confirmation_count, denial_count, project_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(pattern) DO UPDATE SET
                 rule_type = excluded.rule_type,
                 source = excluded.source,
                 confirmation_count = excluded.confirmation_count,
                 denial_count = excluded.denial_count,
                 project_path = excluded.project_path",
            params![
                rule.pattern,
                rule.rule_type.as_str(),
                rule.learned_at.to_rfc3339(),
                rule.source,
                rule.confirmation_count,
                rule.denial_count,
                rule.project_path,
            ],
        )?;

        // Get the rule ID (either newly inserted or existing)
        let id: i64 = self.conn.query_row(
            "SELECT id FROM learned_rules WHERE pattern = ?1",
            [&rule.pattern],
            |row| row.get(0),
        )?;

        debug!("Added/updated rule {} for pattern: {}", id, rule.pattern);
        Ok(id)
    }

    /// Get all learned rules
    pub fn get_rules(&self) -> crate::Result<Vec<LearnedRule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pattern, rule_type, learned_at, source, confirmation_count, denial_count, project_path
             FROM learned_rules ORDER BY learned_at DESC",
        )?;
        let rules = stmt
            .query_map([], Self::row_to_learned_rule)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(rules)
    }

    /// Get rules for a specific project (including global rules)
    pub fn get_rules_for_project(&self, project_path: &str) -> crate::Result<Vec<LearnedRule>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pattern, rule_type, learned_at, source, confirmation_count, denial_count, project_path
             FROM learned_rules WHERE project_path IS NULL OR project_path = ?1 ORDER BY learned_at DESC",
        )?;
        let rules = stmt
            .query_map([project_path], Self::row_to_learned_rule)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(rules)
    }

    /// Get a rule by pattern
    pub fn get_rule_by_pattern(&self, pattern: &str) -> crate::Result<Option<LearnedRule>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, pattern, rule_type, learned_at, source, confirmation_count, denial_count, project_path
                 FROM learned_rules WHERE pattern = ?1",
                [pattern],
                Self::row_to_learned_rule,
            )
            .optional()?;
        Ok(result)
    }

    /// Increment confirmation count for a rule
    pub fn increment_confirmation_count(&self, pattern: &str) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE learned_rules SET confirmation_count = confirmation_count + 1 WHERE pattern = ?1",
            [pattern],
        )?;
        debug!("Incremented confirmation count for pattern: {}", pattern);
        Ok(())
    }

    /// Increment denial count for a rule
    pub fn increment_denial_count(&self, pattern: &str) -> crate::Result<()> {
        self.conn.execute(
            "UPDATE learned_rules SET denial_count = denial_count + 1 WHERE pattern = ?1",
            [pattern],
        )?;
        debug!("Incremented denial count for pattern: {}", pattern);
        Ok(())
    }

    /// Delete a learned rule by pattern
    pub fn delete_rule(&self, pattern: &str) -> crate::Result<()> {
        self.conn
            .execute("DELETE FROM learned_rules WHERE pattern = ?1", [pattern])?;
        debug!("Deleted rule for pattern: {}", pattern);
        Ok(())
    }

    fn row_to_learned_rule(row: &Row) -> rusqlite::Result<LearnedRule> {
        let learned_at_str: String = row.get(3)?;
        let rule_type_str: String = row.get(2)?;

        Ok(LearnedRule {
            id: Some(row.get(0)?),
            pattern: row.get(1)?,
            rule_type: RuleType::parse(&rule_type_str),
            learned_at: parse_datetime(&learned_at_str),
            source: row.get(4)?,
            confirmation_count: row.get(5)?,
            denial_count: row.get(6)?,
            project_path: row.get(7)?,
        })
    }
}
