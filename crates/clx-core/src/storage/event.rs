//! Event operations
//!
//! Append, query, and count session events.

use rusqlite::{Row, params};
use tracing::{debug, warn};

use super::Storage;
use super::util::parse_datetime;
use crate::types::{Event, EventType};

impl Storage {
    /// Append an event to the session
    pub fn append_event(&self, event: &Event) -> crate::Result<i64> {
        self.conn.execute(
            "INSERT INTO events (session_id, timestamp, event_type, tool_name, tool_use_id, tool_input, tool_output)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.session_id,
                event.timestamp.to_rfc3339(),
                event.event_type.as_str(),
                event.tool_name,
                event.tool_use_id,
                event.tool_input,
                event.tool_output,
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        debug!(
            "Appended event {} ({}) for session {}",
            id,
            event.event_type.as_str(),
            event.session_id
        );
        Ok(id)
    }

    /// Get all events for a session
    pub fn get_events_by_session(&self, session_id: &str) -> crate::Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, event_type, tool_name, tool_use_id, tool_input, tool_output
             FROM events WHERE session_id = ?1 ORDER BY timestamp ASC",
        )?;
        let events = stmt
            .query_map([session_id], Self::row_to_event)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(events)
    }

    /// Get events for a session with pagination
    pub fn get_events_paginated(
        &self,
        session_id: &str,
        limit: i64,
        offset: i64,
    ) -> crate::Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, session_id, timestamp, event_type, tool_name, tool_use_id, tool_input, tool_output
             FROM events WHERE session_id = ?1 ORDER BY timestamp ASC LIMIT ?2 OFFSET ?3",
        )?;
        let events = stmt
            .query_map(params![session_id, limit, offset], Self::row_to_event)?
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!("Row deserialization error (skipped): {}", e);
                    None
                }
            })
            .collect();
        Ok(events)
    }

    /// Count events for a session
    pub fn count_events(&self, session_id: &str) -> crate::Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    fn row_to_event(row: &Row) -> rusqlite::Result<Event> {
        let timestamp_str: String = row.get(2)?;
        let event_type_str: String = row.get(3)?;

        Ok(Event {
            id: Some(row.get(0)?),
            session_id: row.get(1)?,
            timestamp: parse_datetime(&timestamp_str),
            event_type: EventType::parse(&event_type_str),
            tool_name: row.get(4)?,
            tool_use_id: row.get(5)?,
            tool_input: row.get(6)?,
            tool_output: row.get(7)?,
        })
    }
}
