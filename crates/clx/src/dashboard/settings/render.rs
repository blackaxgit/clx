use clx_core::config::{Config, ProviderConfig};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
    Wrap,
};

use super::config_bridge::{get_default_value, get_field_value};
use super::fields::{FieldWidget, fields_for_section};
use super::sections::SECTIONS;
use crate::dashboard::app::{App, InputMode};

/// Truncate a string to fit within `max_width`, appending "..." if truncated.
fn truncate_value(s: &str, max_width: usize) -> String {
    if s.len() <= max_width {
        s.to_owned()
    } else if max_width <= 3 {
        ".".repeat(max_width)
    } else {
        format!("{}...", &s[..max_width - 3])
    }
}

/// Render the Settings tab with a two-panel layout.
///
/// Left panel: section list (22 columns).
/// Right panel: field table showing name, value, and default.
/// Overlays: edit popup when in `SettingsEdit` mode, confirm dialog for reset.
pub fn render_settings_tab(frame: &mut Frame, app: &mut App, area: Rect) {
    // Show load error if config failed to load
    if let Some(err) = &app.settings_load_error {
        let panels = Layout::horizontal([Constraint::Length(22), Constraint::Min(40)]).split(area);
        render_section_list(frame, app, panels[0]);

        let config_path_display = Config::config_file_path().map_or_else(
            |_| "~/.clx/config.yaml".to_owned(),
            |p| p.display().to_string(),
        );
        let block = Block::bordered().title(format!(" Settings - {config_path_display} "));
        let inner = block.inner(panels[1]);
        frame.render_widget(block, panels[1]);

        let lines = vec![
            Line::from(Span::styled(
                "Failed to load configuration",
                Style::default().fg(Color::Red).bold(),
            )),
            Line::from(""),
            Line::from(Span::styled(err.as_str(), Style::default().fg(Color::Red))),
            Line::from(""),
            Line::from(Span::styled(
                "Editing is disabled. Fix the config file manually or press [r] to retry.",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
        frame.render_widget(paragraph, inner);
        return;
    }

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

    // Overlay: reload confirmation dialog
    if app.settings_reload_confirm {
        render_reload_confirm(frame, area);
    }

    // Overlay: dirty-exit guard prompt
    if app.settings_exit_pending.is_some() {
        render_exit_guard(frame, area);
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

    let table =
        Table::new(rows, [Constraint::Fill(1)]).block(Block::bordered().title(" Sections "));

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

    // Config file path in panel title
    let config_path_display = Config::config_file_path().map_or_else(
        |_| "~/.clx/config.yaml".to_owned(),
        |p| p.display().to_string(),
    );

    let header = Row::new(vec![
        Cell::from("Field").style(Style::default().bold()),
        Cell::from("Value").style(Style::default().bold()),
        Cell::from("Default").style(Style::default().bold()),
    ])
    .bottom_margin(1);

    // Compute max value column width for truncation (area minus label and default columns, borders, padding)
    let value_max_width = area.width.saturating_sub(24 + 24 + 6) as usize;
    let value_max_width = value_max_width.max(10);

    let mut rows: Vec<Row> = if fields.is_empty() {
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

                let truncated_value = truncate_value(&value, value_max_width);
                let truncated_default = truncate_value(&default, 24);

                Row::new(vec![
                    Cell::from(field_def.label),
                    Cell::from(truncated_value).style(value_style),
                    Cell::from(truncated_default).style(Style::default().fg(Color::DarkGray)),
                ])
            })
            .collect()
    };

    // For LLM section (section 2), append per-provider rows and routing summary
    if app.settings_section_idx == 2 {
        append_provider_rows(config, &mut rows, value_max_width);
    }

    // For MCP Tools section (section 7), append command_tools entries as read-only rows
    if app.settings_section_idx == 7 {
        let command_tools = &config.mcp_tools.command_tools;
        if !command_tools.is_empty() {
            // Separator row
            rows.push(Row::new(vec![Cell::from(Span::styled(
                "--- command_tools [read-only] ---",
                Style::default().fg(Color::DarkGray).italic(),
            ))]));

            for tool in command_tools {
                let pattern_display = truncate_value(&tool.tool_pattern, value_max_width);
                rows.push(Row::new(vec![
                    Cell::from("  pattern").style(Style::default().fg(Color::DarkGray)),
                    Cell::from(pattern_display).style(Style::default().fg(Color::DarkGray)),
                    Cell::from("").style(Style::default().fg(Color::DarkGray)),
                ]));
                let command_display = truncate_value(&tool.command_field, value_max_width);
                rows.push(Row::new(vec![
                    Cell::from("  command_field").style(Style::default().fg(Color::DarkGray)),
                    Cell::from(command_display).style(Style::default().fg(Color::DarkGray)),
                    Cell::from("").style(Style::default().fg(Color::DarkGray)),
                ]));
            }
        }
    }

    let widths = [
        Constraint::Length(24),
        Constraint::Min(20),
        Constraint::Length(24),
    ];

    let title = format!(" {section_title} - {config_path_display} ");
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

/// Infer the credential source label for an Azure provider without calling
/// keychain APIs.  Returns `"Env (<VAR>)"` when the named env var is set and
/// non-empty, otherwise `"Keychain/file"` when an env var name is configured
/// but the var is absent, or `"Not configured"` when no env var is set.
///
/// The secret value is never read here — only the env var *name* is inspected.
fn azure_credential_source(cfg: &clx_core::config::AzureOpenAIConfig) -> String {
    match cfg.api_key_env.as_deref() {
        Some(var) if !var.is_empty() => {
            if std::env::var(var).is_ok_and(|v| !v.is_empty()) {
                format!("Env ({var})")
            } else {
                "Keychain/file".to_owned()
            }
        }
        _ => {
            // No env var configured; credential comes from keychain or file
            // if api_key_file is set, indicate that — otherwise "Not configured"
            if cfg.api_key_file.is_some() {
                "File".to_owned()
            } else {
                "Not configured".to_owned()
            }
        }
    }
}

/// Append per-provider and routing read-only rows to the LLM section field list.
fn append_provider_rows(config: &Config, rows: &mut Vec<Row<'_>>, value_max_width: usize) {
    // ── Providers ───────────────────────────────────────────────────────────
    rows.push(Row::new(vec![Cell::from(Span::styled(
        "── Providers ──",
        Style::default().fg(Color::Blue).bold(),
    ))]));

    if config.providers.is_empty() {
        rows.push(Row::new(vec![
            Cell::from(Span::styled(
                "  (none)",
                Style::default().fg(Color::DarkGray).italic(),
            )),
            Cell::from(""),
            Cell::from(""),
        ]));
    } else {
        for (name, provider) in &config.providers {
            let (kind_label, endpoint_val) = match provider {
                ProviderConfig::Ollama(c) => ("ollama".to_owned(), c.host.clone()),
                ProviderConfig::AzureOpenai(c) => ("azure_openai".to_owned(), c.endpoint.clone()),
            };

            let endpoint_display = truncate_value(&endpoint_val, value_max_width);
            rows.push(Row::new(vec![
                Cell::from(format!("  {name}")).style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{kind_label}  {endpoint_display}"))
                    .style(Style::default().fg(Color::White)),
                Cell::from(""),
            ]));

            // For Azure: show credential source (never the secret value)
            if let ProviderConfig::AzureOpenai(c) = provider {
                let cred = azure_credential_source(c);
                rows.push(Row::new(vec![
                    Cell::from("    credential").style(Style::default().fg(Color::DarkGray)),
                    Cell::from(cred).style(Style::default().fg(Color::DarkGray)),
                    Cell::from(""),
                ]));
            }
        }
    }

    // ── Routing ─────────────────────────────────────────────────────────────
    rows.push(Row::new(vec![Cell::from(Span::styled(
        "── Routing ──",
        Style::default().fg(Color::Blue).bold(),
    ))]));

    match &config.llm {
        None => {
            rows.push(Row::new(vec![
                Cell::from(Span::styled(
                    "  (no llm: section)",
                    Style::default().fg(Color::DarkGray).italic(),
                )),
                Cell::from(""),
                Cell::from(""),
            ]));
        }
        Some(llm) => {
            let chat_val = truncate_value(
                &format!("{}/{}", llm.chat.provider, llm.chat.model),
                value_max_width,
            );
            rows.push(Row::new(vec![
                Cell::from("  chat").style(Style::default().fg(Color::DarkGray)),
                Cell::from(chat_val).style(Style::default().fg(Color::White)),
                Cell::from(""),
            ]));

            let emb_val = truncate_value(
                &format!("{}/{}", llm.embeddings.provider, llm.embeddings.model),
                value_max_width,
            );
            rows.push(Row::new(vec![
                Cell::from("  embeddings").style(Style::default().fg(Color::DarkGray)),
                Cell::from(emb_val).style(Style::default().fg(Color::White)),
                Cell::from(""),
            ]));
        }
    }
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

/// Render the dirty-exit guard prompt.
fn render_exit_guard(frame: &mut Frame, area: Rect) {
    let popup_width = 52u16;
    let popup_height = 5u16;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::bordered()
        .title(" Unsaved Changes ")
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines = vec![
        Line::from("You have unsaved changes."),
        Line::from(""),
        Line::from(Span::styled(
            "[s] Save   [x] Discard   [Esc] Stay",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

/// Render the reload confirmation dialog (when dirty).
fn render_reload_confirm(frame: &mut Frame, area: Rect) {
    let popup_width = 48u16;
    let popup_height = 5u16;
    let popup_area = centered_rect(popup_width, popup_height, area);

    frame.render_widget(Clear, popup_area);

    let block = Block::bordered()
        .title(" Reload from Disk ")
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    let lines = vec![
        Line::from("Unsaved changes will be lost. Reload?"),
        Line::from(""),
        Line::from(Span::styled(
            "[y] Yes   [n/Esc] No",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(lines);
    frame.render_widget(paragraph, inner);
}

// ── E1.W4: TestBackend + insta snapshots for the Settings tab ───────────────
//
// These snapshots pin the rendered output of `render_settings_tab` against
// deterministic AppState + Config fixtures. The TestBackend dimensions are
// 100x40 (wider than the list view to match detail.rs snapshots and to keep
// the two-panel layout from clipping field labels).
//
// Volatile content (the config-file path embedded in panel titles, and the
// user's home directory path) is replaced with `<CONFIG_PATH>` and `<HOME>`
// tokens via a `redact_volatile` helper, mirroring the pattern used by
// `crate::dashboard::ui::tests::redact_volatile`.
//
// Determinism rules: no system clock, no DB, no filesystem reads beyond
// `Config::config_file_path()` (which is path-derivation only, no I/O).
#[cfg(test)]
mod render_snapshots {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::dashboard::app::{App, DashboardTab, InputMode};

    const COLS: u16 = 100;
    const ROWS: u16 = 40;

    /// Redact volatile content from settings snapshots: replace the resolved
    /// config-file path and the user's home directory with stable tokens so
    /// the snapshot is portable across machines and CI runners. Re-pads each
    /// modified line to exactly `COLS` characters so ratatui box-drawing
    /// borders stay aligned.
    fn redact_volatile(s: &str) -> String {
        let config_path = clx_core::config::Config::config_file_path()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let home = dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let mut out_lines: Vec<String> = Vec::new();
        for line in s.lines() {
            // The panel title embeds the absolute config-file path, which
            // ratatui clips to the panel width: only a *prefix* of the path
            // survives in the buffer, so a full-string match is not portable
            // across machines (it matched only on the original dev HOME).
            // Redact the longest prefix of the known path present on the
            // line and canonicalize the volatile tail to a fixed width.
            // Non-title lines never contain this prefix, so they fall through
            // unchanged (every other snapshot stays byte-identical).
            if let Some(title) = redact_title_config_path(line, &config_path, COLS as usize) {
                out_lines.push(title);
                continue;
            }
            let mut replaced = line.to_string();
            if !home.is_empty() && replaced.contains(&home) {
                replaced = replaced.replace(&home, "<HOME>");
            }
            let vis_len = replaced.chars().count();
            if vis_len < COLS as usize {
                let trimmed = replaced.trim_end();
                if trimmed.ends_with('┐') {
                    let base = trimmed.trim_end_matches('┐');
                    let mut padded = base.to_string();
                    let needed = COLS as usize - base.chars().count() - 1;
                    for _ in 0..needed {
                        padded.push('─');
                    }
                    padded.push('┐');
                    out_lines.push(padded);
                } else {
                    let mut padded = replaced;
                    for _ in 0..(COLS as usize - vis_len) {
                        padded.push(' ');
                    }
                    out_lines.push(padded);
                }
            } else {
                out_lines.push(replaced.chars().take(COLS as usize).collect());
            }
        }
        out_lines.join("\n")
    }

    /// If `line` contains a (possibly ratatui-truncated) prefix of the
    /// absolute `config_path`, return the line with that path region replaced
    /// by the stable `<CONFIG_PATH>` token and the volatile tail truncated
    /// then space-padded to exactly `width` columns. Returns `None` when the
    /// line does not contain the path, so callers leave non-title lines
    /// byte-identical (zero collateral on sessions/audit/rules snapshots).
    fn redact_title_config_path(line: &str, config_path: &str, width: usize) -> Option<String> {
        const MIN: usize = 12;
        if config_path.len() < MIN {
            return None;
        }
        let mut end = config_path.len();
        loop {
            if config_path.is_char_boundary(end)
                && let Some(pos) = line.find(&config_path[..end])
            {
                let mut head = String::with_capacity(width);
                head.push_str(&line[..pos]);
                head.push_str("<CONFIG_PATH>");
                let mut canon: String = head.chars().take(width).collect();
                while canon.chars().count() < width {
                    canon.push(' ');
                }
                return Some(canon);
            }
            if end <= MIN {
                return None;
            }
            end -= 1;
        }
    }

    /// Render the Settings tab (entire `area = frame.area()`) and return the
    /// buffer as a redacted, trimmed-per-row string.
    fn render_settings_to_string(app: &mut App) -> String {
        let backend = TestBackend::new(COLS, ROWS);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                super::render_settings_tab(frame, app, area);
            })
            .unwrap();
        let buffer = terminal.backend().buffer().clone();
        let raw = (0..ROWS)
            .map(|y| {
                let row: String = (0..COLS)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol().to_string())
                    .collect();
                row.trim_end().to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        redact_volatile(&raw)
    }

    fn make_settings_app() -> App {
        let mut app = App::new(7, 5);
        app.current_tab = DashboardTab::Settings;
        app.input_mode = InputMode::Normal;
        app
    }

    // ── Empty / error fixtures ──────────────────────────────────────────────

    /// No config loaded and no error — renders the bordered " Fields "
    /// placeholder in the right panel.
    #[test]
    fn snapshot_settings_no_config_no_error() {
        let mut app = make_settings_app();
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_no_config_no_error", rendered);
    }

    /// Load error path — renders the red "Failed to load configuration"
    /// message and the embedded error text.
    #[test]
    fn snapshot_settings_load_error() {
        let mut app = make_settings_app();
        app.settings_load_error = Some("permission denied (os error 13)".to_string());
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_load_error", rendered);
    }

    // ── Loaded-config fixtures ──────────────────────────────────────────────

    fn make_default_config() -> clx_core::config::Config {
        clx_core::config::Config::default()
    }

    /// Default config, first section selected — exercises the field table
    /// happy path with both value and default columns populated.
    #[test]
    fn snapshot_settings_default_config_section_0() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 0;
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_default_section_0", rendered);
    }

    /// LLM section (index 2) — exercises `append_provider_rows` empty path
    /// and the routing summary panel.
    #[test]
    fn snapshot_settings_default_config_llm_section() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 2;
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_default_llm_section", rendered);
    }

    /// Edit-mode popup overlay — exercises `render_edit_popup` with a
    /// pre-populated edit buffer and no validation error.
    #[test]
    fn snapshot_settings_edit_mode_popup() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 0;
        app.settings_field_idx = 0;
        app.input_mode = InputMode::SettingsEdit;
        app.settings_edit_buffer = "42".to_string();
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_edit_mode_popup", rendered);
    }

    /// Reset confirmation dialog overlay.
    #[test]
    fn snapshot_settings_confirm_reset_dialog() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_confirm_reset = true;
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_confirm_reset", rendered);
    }

    /// Reload-from-disk confirmation dialog overlay.
    #[test]
    fn snapshot_settings_reload_confirm_dialog() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_reload_confirm = true;
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_reload_confirm", rendered);
    }

    /// Dirty-exit guard prompt overlay.
    #[test]
    fn snapshot_settings_exit_guard_dialog() {
        use crate::dashboard::app::ExitTarget;
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_is_dirty = true;
        app.settings_exit_pending = Some(ExitTarget::Quit);
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_exit_guard", rendered);
    }

    // ── H2: previously-unrendered branches ──────────────────────────────────

    use clx_core::config::{AzureOpenAIConfig, McpCommandTool, OllamaConfig, ProviderConfig};

    /// `truncate_value` unit contract: the three branches (fits, max<=3
    /// dot-fill, normal ellipsis) are pure and asserted directly so a
    /// mutation to the off-by-one (`max_width - 3`) or the `<=` guard fails
    /// here, not just visually.
    #[test]
    fn truncate_value_branches() {
        // fits unchanged
        assert_eq!(super::truncate_value("short", 10), "short");
        assert_eq!(super::truncate_value("exactly10!", 10), "exactly10!");
        // max_width <= 3 → dot fill of exactly max_width dots
        assert_eq!(super::truncate_value("anything", 3), "...");
        assert_eq!(super::truncate_value("anything", 1), ".");
        assert_eq!(super::truncate_value("anything", 0), "");
        // normal truncation: head of len max_width-3 then "..."
        assert_eq!(super::truncate_value("abcdefghij", 8), "abcde...");
    }

    /// LLM section with two configured providers (ollama + azure) and a
    /// populated `llm:` routing block. Exercises `append_provider_rows`
    /// non-empty path, the azure credential row, and both routing arms.
    #[test]
    fn snapshot_settings_llm_populated_providers_and_routing() {
        let mut app = make_settings_app();
        let mut cfg = make_default_config();
        cfg.providers.insert(
            "local-ollama".to_string(),
            ProviderConfig::Ollama(OllamaConfig {
                host: "http://127.0.0.1:11434".to_string(),
                ..OllamaConfig::default()
            }),
        );
        cfg.providers.insert(
            "azure-prod".to_string(),
            ProviderConfig::AzureOpenai(AzureOpenAIConfig {
                endpoint: "https://example.openai.azure.com".to_string(),
                api_key_env: Some("CLX_TEST_AZURE_KEY_UNSET".to_string()),
                api_key_file: None,
                api_version: None,
                timeout_ms: 30_000,
                retry: clx_core::llm::RetryConfig::default(),
            }),
        );
        cfg.llm = Some(clx_core::config::LlmRouting {
            chat: clx_core::config::CapabilityRoute {
                provider: "local-ollama".to_string(),
                model: "qwen3:1.7b".to_string(),
                fallback: None,
            },
            embeddings: clx_core::config::CapabilityRoute {
                provider: "local-ollama".to_string(),
                model: "qwen3-embedding:0.6b".to_string(),
                fallback: None,
            },
        });
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 2;
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_llm_populated", rendered);
    }

    /// `azure_credential_source` pure contract. The crate denies
    /// `unsafe-code`, so we cannot mutate the environment; instead we use
    /// `PATH` (guaranteed present & non-empty in any test process) for the
    /// "Env" arm and a name guaranteed absent for the "Keychain/file" arm.
    #[test]
    fn azure_credential_source_arms() {
        let base = AzureOpenAIConfig {
            endpoint: "https://x".to_string(),
            api_key_env: None,
            api_key_file: None,
            api_version: None,
            timeout_ms: 1,
            retry: clx_core::llm::RetryConfig::default(),
        };

        // env var present & non-empty → "Env (PATH)"
        assert!(std::env::var("PATH").is_ok_and(|v| !v.is_empty()));
        let with_env = AzureOpenAIConfig {
            api_key_env: Some("PATH".to_string()),
            ..base.clone()
        };
        assert_eq!(super::azure_credential_source(&with_env), "Env (PATH)");

        // env var name configured but absent → "Keychain/file"
        let with_absent_env = AzureOpenAIConfig {
            api_key_env: Some("CLX_DEFINITELY_UNSET_ENV_VAR_FOR_TESTS".to_string()),
            ..base.clone()
        };
        assert_eq!(
            super::azure_credential_source(&with_absent_env),
            "Keychain/file"
        );

        // empty env var name → falls to the no-env branch; file set → "File"
        let with_file = AzureOpenAIConfig {
            api_key_env: Some(String::new()),
            api_key_file: Some(std::path::PathBuf::from("/tmp/k")),
            ..base.clone()
        };
        assert_eq!(super::azure_credential_source(&with_file), "File");

        // nothing configured → "Not configured"
        assert_eq!(super::azure_credential_source(&base), "Not configured");
    }

    /// MCP Tools section (index 7) with a populated `command_tools` registry
    /// → the read-only separator + pattern/`command_field` rows render.
    #[test]
    fn snapshot_settings_mcp_command_tools_populated() {
        let mut app = make_settings_app();
        let mut cfg = make_default_config();
        cfg.mcp_tools.command_tools = vec![
            McpCommandTool {
                tool_pattern: "mcp__ssh__execute".to_string(),
                command_field: "command".to_string(),
            },
            McpCommandTool {
                tool_pattern: "mcp__docker__run".to_string(),
                command_field: "cmd".to_string(),
            },
        ];
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 7;
        let rendered = render_settings_to_string(&mut app);
        insta::assert_snapshot!("dashboard_ui_settings_mcp_tools_populated", rendered);
    }

    /// A field whose value differs from its default → the value cell uses
    /// the Yellow "modified" style. Snapshot proves the modified row renders
    /// (color is not captured by the symbol buffer, so we also assert the
    /// changed value text is present and the default column still shows the
    /// original).
    #[test]
    fn snapshot_settings_modified_value_yellow() {
        let mut app = make_settings_app();
        let mut cfg = make_default_config();
        // validator.layer1_timeout_ms default is 30000 — change it.
        cfg.validator.layer1_timeout_ms = 12345;
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 0;
        let rendered = render_settings_to_string(&mut app);
        assert!(
            rendered.contains("12345"),
            "modified value must be rendered"
        );
        insta::assert_snapshot!("dashboard_ui_settings_modified_value", rendered);
    }

    /// Edit-popup `range_info` for a `NumberU64` field (validator
    /// `layer1_timeout_ms`, section 0 field 2) → "Range: 100 - 300000".
    #[test]
    fn snapshot_settings_edit_popup_number_u64_range() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 0;
        app.settings_field_idx = 2; // layer1_timeout_ms : NumberU64
        app.input_mode = InputMode::SettingsEdit;
        app.settings_edit_buffer = "5000".to_string();
        let rendered = render_settings_to_string(&mut app);
        assert!(rendered.contains("Range: 100 - 300000"));
        insta::assert_snapshot!("dashboard_ui_settings_edit_u64_range", rendered);
    }

    /// Edit-popup `range_info` for a `TextInput` field
    /// (`context.embedding_model`, section 1 field 2) → "Non-empty string",
    /// plus a validation error so
    /// the red error line in the popup renders.
    #[test]
    fn snapshot_settings_edit_popup_text_input_with_error() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 1;
        app.settings_field_idx = 2; // embedding_model : TextInput
        app.input_mode = InputMode::SettingsEdit;
        app.settings_edit_buffer = String::new();
        app.settings_edit_error = Some("must not be empty".to_string());
        let rendered = render_settings_to_string(&mut app);
        assert!(rendered.contains("Non-empty string"));
        assert!(rendered.contains("must not be empty"));
        insta::assert_snapshot!("dashboard_ui_settings_edit_text_error", rendered);
    }

    /// Edit-popup `range_info` for a `NumberF32` field
    /// (`ollama.retry_backoff`, section 2 field with `NumberF32`) →
    /// "Range: <min> - <max>".
    #[test]
    fn snapshot_settings_edit_popup_number_f32_range() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        // section 2 (LLM/Ollama) has a NumberF32 field (retry_backoff).
        app.settings_section_idx = 2;
        // find the F32 field index dynamically to stay robust to reorder.
        let fields = super::fields_for_section(2);
        let idx = fields
            .iter()
            .position(|f| matches!(f.widget, super::FieldWidget::NumberF32 { .. }))
            .expect("ollama section has a NumberF32 field");
        app.settings_field_idx = idx;
        app.input_mode = InputMode::SettingsEdit;
        app.settings_edit_buffer = "2.0".to_string();
        let rendered = render_settings_to_string(&mut app);
        assert!(rendered.contains("Range: "));
        insta::assert_snapshot!("dashboard_ui_settings_edit_f32_range", rendered);
    }

    /// Edit-popup for a field index that is out of range → `render_edit_popup`
    /// returns early (no popup). The base field table still renders. This
    /// covers the `fields.get(idx)` None early-return guard.
    #[test]
    fn snapshot_settings_edit_popup_field_out_of_range_noop() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 0;
        app.settings_field_idx = 999; // out of range → early return
        app.input_mode = InputMode::SettingsEdit;
        let rendered = render_settings_to_string(&mut app);
        // No " Edit: " popup title is drawn.
        assert!(
            !rendered.contains("Edit:"),
            "out-of-range field must not draw an edit popup"
        );
        insta::assert_snapshot!("dashboard_ui_settings_edit_oob_noop", rendered);
    }

    /// Section with a config loaded but the section index out of range →
    /// `fields_for_section` returns empty and the "No fields" row renders.
    #[test]
    fn snapshot_settings_section_out_of_range_no_fields() {
        let mut app = make_settings_app();
        let cfg = make_default_config();
        app.settings_editing_config = Some(cfg.clone());
        app.settings_original_config = Some(cfg);
        app.settings_section_idx = 99; // beyond SECTIONS → empty fields
        let rendered = render_settings_to_string(&mut app);
        assert!(rendered.contains("No fields"));
        insta::assert_snapshot!("dashboard_ui_settings_no_fields", rendered);
    }
}
