use ratatui::prelude::*;
use ratatui::widgets::{Block, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table};

use super::config_bridge::{get_default_value, get_field_value};
use super::fields::fields_for_section;
use super::sections::SECTIONS;
use crate::dashboard::app::App;

/// Render the Settings tab with a two-panel layout.
///
/// Left panel: section list (22 columns).
/// Right panel: field table showing name, value, and default.
pub fn render_settings_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let panels = Layout::horizontal([Constraint::Length(22), Constraint::Min(40)]).split(area);

    render_section_list(frame, app, panels[0]);
    render_field_table(frame, app, panels[1]);
}

/// Render the section list in the left panel.
fn render_section_list(frame: &mut Frame, app: &App, area: Rect) {
    let rows: Vec<Row> = SECTIONS
        .iter()
        .enumerate()
        .map(|(i, section)| {
            let marker = if i == app.settings_section_idx {
                "> "
            } else {
                "  "
            };
            let style = if i == app.settings_section_idx {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default()
            };
            Row::new(vec![Cell::from(format!("{marker}{}", section.title))]).style(style)
        })
        .collect();

    let table = Table::new(rows, [Constraint::Fill(1)])
        .block(Block::bordered().title(" Sections "));

    frame.render_widget(table, area);
}

/// Render the field table in the right panel.
fn render_field_table(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(config) = &app.settings_editing_config else {
        // No config loaded yet — show placeholder
        let block = Block::bordered().title(" Fields ");
        frame.render_widget(block, area);
        return;
    };

    let fields = fields_for_section(app.settings_section_idx);
    let section_title = SECTIONS
        .get(app.settings_section_idx)
        .map_or("Fields", |s| s.title);

    let header = Row::new(vec![
        Cell::from("Field").style(Style::default().bold()),
        Cell::from("Value").style(Style::default().bold()),
        Cell::from("Default").style(Style::default().bold()),
    ])
    .bottom_margin(1);

    let rows: Vec<Row> = if fields.is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            "No fields",
            Style::default().fg(Color::DarkGray).italic(),
        ))])]
    } else {
        fields
            .iter()
            .enumerate()
            .map(|(i, field_def)| {
                let value = get_field_value(config, app.settings_section_idx, i);
                let default = get_default_value(app.settings_section_idx, i);

                let value_style = if value == default {
                    Style::default()
                } else {
                    Style::default().fg(Color::Yellow)
                };

                Row::new(vec![
                    Cell::from(field_def.label),
                    Cell::from(value).style(value_style),
                    Cell::from(default).style(Style::default().fg(Color::DarkGray)),
                ])
            })
            .collect()
    };

    let widths = [
        Constraint::Length(24),
        Constraint::Min(20),
        Constraint::Length(24),
    ];

    let title = format!(" {section_title} ");
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    frame.render_stateful_widget(table, area, &mut app.settings_field_table_state);

    // Scrollbar for field list
    let total_rows = fields.len();
    let selected = app.settings_field_table_state.selected().unwrap_or(0);
    let mut scrollbar_state = ScrollbarState::new(total_rows).position(selected);
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(Some("\u{2191}"))
        .end_symbol(Some("\u{2193}"));
    frame.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}
