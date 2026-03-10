use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    Wrap,
};

use super::config_bridge::{get_default_value, get_field_value};
use super::fields::{fields_for_section, FieldWidget};
use super::sections::SECTIONS;
use crate::dashboard::app::{App, InputMode};

/// Render the Settings tab with a two-panel layout.
///
/// Left panel: section list (22 columns).
/// Right panel: field table showing name, value, and default.
/// Overlays: edit popup when in `SettingsEdit` mode, confirm dialog for reset.
pub fn render_settings_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    let panels = Layout::horizontal([Constraint::Length(22), Constraint::Min(40)]).split(area);

    render_section_list(frame, app, panels[0]);
    render_field_table(frame, app, panels[1]);

    // Overlay: edit popup
    if app.input_mode == InputMode::SettingsEdit {
        render_edit_popup(frame, app, area);
    }

    // Overlay: reset confirmation dialog
    if app.settings_confirm_reset {
        render_confirm_reset(frame, area);
    }
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

/// Create a centered `Rect` within `area`.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect::new(x, y, w, h)
}

/// Render the edit popup for text/number fields.
fn render_edit_popup(frame: &mut Frame, app: &App, area: Rect) {
    let fields = fields_for_section(app.settings_section_idx);
    let Some(field_def) = fields.get(app.settings_field_idx) else {
        return;
    };

    let popup_width = 50u16;
    let popup_height = 12u16;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let title = format!(" Edit: {} ", field_def.label);
    let block = Block::bordered()
        .title(title)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Build popup content lines
    let mut lines: Vec<Line> = Vec::new();

    // Description
    lines.push(Line::from(Span::styled(
        field_def.description,
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));

    // Edit buffer with cursor indicator
    let buffer_display = format!("Value: [{}|]", app.settings_edit_buffer);
    lines.push(Line::from(Span::styled(
        buffer_display,
        Style::default().fg(Color::White).bold(),
    )));
    lines.push(Line::from(""));

    // Range / constraint info
    let range_info = match &field_def.widget {
        FieldWidget::NumberU64 { min, max } => Some(format!("Range: {min} - {max}")),
        FieldWidget::NumberU32 { min, max } => Some(format!("Range: {min} - {max}")),
        FieldWidget::NumberI64 { min, max } => Some(format!("Range: {min} - {max}")),
        FieldWidget::NumberF64 { min, max, .. } => Some(format!("Range: {min} - {max}")),
        FieldWidget::NumberF32 { min, max, .. } => Some(format!("Range: {min} - {max}")),
        FieldWidget::NumberUsize { min, max } => Some(format!("Range: {min} - {max}")),
        FieldWidget::TextInput { .. } => Some("Non-empty string".to_owned()),
        _ => None,
    };
    if let Some(info) = range_info {
        lines.push(Line::from(Span::styled(
            info,
            Style::default().fg(Color::DarkGray),
        )));
    }

    // Default value
    let default_val = get_default_value(app.settings_section_idx, app.settings_field_idx);
    lines.push(Line::from(Span::styled(
        format!("Default: {default_val}"),
        Style::default().fg(Color::DarkGray),
    )));
    lines.push(Line::from(""));

    // Validation error
    if let Some(err) = &app.settings_edit_error {
        lines.push(Line::from(Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red).bold(),
        )));
    } else {
        lines.push(Line::from(""));
    }

    // Key hints
    lines.push(Line::from(Span::styled(
        "[Enter] Confirm   [Esc] Cancel",
        Style::default().fg(Color::DarkGray),
    )));

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, inner);
}

/// Render the reset confirmation dialog.
fn render_confirm_reset(frame: &mut Frame, area: Rect) {
    let popup_width = 40u16;
    let popup_height = 5u16;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::bordered()
        .title(" Reset All Changes ")
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines = vec![
        Line::from("Revert all changes to last saved?"),
        Line::from(""),
        Line::from(Span::styled(
            "[y] Yes   [n/Esc] No",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}
