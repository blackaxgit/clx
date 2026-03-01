//! Analytics operations
//!
//! Record, query, and aggregate analytics metrics.

use chrono::NaiveDate;
use rusqlite::{Row, params};
use tracing::{debug, warn};

use super::Storage;
use crate::types::AnalyticsEntry;

impl Storage {
    /// Record an analytics metric
    ///
    /// Uses UPSERT to add to existing value if the metric already exists for
    /// the date/project combination.
    pub fn record_metric(&self, entry: &AnalyticsEntry) -> crate::Result<()> {
        // Use empty string for global metrics (None project_path)
        let project_path = entry.project_path.as_deref().unwrap_or("");

        self.conn.execute(
            "INSERT INTO analytics (date, project_path, metric_name, metric_value)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(date, project_path, metric_name) DO UPDATE SET
                 metric_value = metric_value + excluded.metric_value",
            params![
                entry.date.to_string(),
                project_path,
                entry.metric_name,
                entry.metric_value,
            ],
        )?;
        debug!(
            "Recorded metric {} = {} for date {}",
            entry.metric_name, entry.metric_value, entry.date
        );
        Ok(())
    }

    /// Get analytics for a date range
    pub fn get_analytics(
        &self,
        start_date: NaiveDate,
        end_date: NaiveDate,
        project_path: Option<&str>,
    ) -> crate::Result<Vec<AnalyticsEntry>> {
        let mut entries = Vec::new();

        // When filtering by project, include both project-specific and global (empty string) metrics
        let query = if project_path.is_some() {
            "SELECT id, date, project_path, metric_name, metric_value
             FROM analytics WHERE date >= ?1 AND date <= ?2 AND (project_path = ?3 OR project_path = '')
             ORDER BY date DESC"
        } else {
            "SELECT id, date, project_path, metric_name, metric_value
             FROM analytics WHERE date >= ?1 AND date <= ?2
             ORDER BY date DESC"
        };

        let mut stmt = self.conn.prepare(query)?;

        let rows: Box<dyn Iterator<Item = rusqlite::Result<AnalyticsEntry>>> =
            if let Some(pp) = project_path {
                Box::new(stmt.query_map(
                    params![start_date.to_string(), end_date.to_string(), pp],
                    Self::row_to_analytics,
                )?)
            } else {
                Box::new(stmt.query_map(
                    params![start_date.to_string(), end_date.to_string()],
                    Self::row_to_analytics,
                )?)
            };

        for entry in rows {
            match entry {
                Ok(e) => entries.push(e),
                Err(e) => {
                    warn!("Row deserialization error in analytics (skipped): {}", e);
                }
            }
        }

        Ok(entries)
    }

    /// Get aggregate value for a metric over a date range
    pub fn get_metric_sum(
        &self,
        metric_name: &str,
        start_date: NaiveDate,
        end_date: NaiveDate,
        project_path: Option<&str>,
    ) -> crate::Result<i64> {
        // When filtering by project, include both project-specific and global (empty string) metrics
        let sum: i64 = if let Some(pp) = project_path {
            self.conn.query_row(
                "SELECT COALESCE(SUM(metric_value), 0) FROM analytics
                 WHERE metric_name = ?1 AND date >= ?2 AND date <= ?3 AND (project_path = ?4 OR project_path = '')",
                params![metric_name, start_date.to_string(), end_date.to_string(), pp],
                |row| row.get(0),
            )?
        } else {
            self.conn.query_row(
                "SELECT COALESCE(SUM(metric_value), 0) FROM analytics
                 WHERE metric_name = ?1 AND date >= ?2 AND date <= ?3",
                params![metric_name, start_date.to_string(), end_date.to_string()],
                |row| row.get(0),
            )?
        };
        Ok(sum)
    }

    fn row_to_analytics(row: &Row) -> rusqlite::Result<AnalyticsEntry> {
        let date_str: String = row.get(1)?;
        let date = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d").unwrap_or_default();
        let project_path: String = row.get(2)?;

        Ok(AnalyticsEntry {
            id: Some(row.get(0)?),
            date,
            // Convert empty string back to None for the Rust type
            project_path: if project_path.is_empty() {
                None
            } else {
                Some(project_path)
            },
            metric_name: row.get(3)?,
            metric_value: row.get(4)?,
        })
    }
}
