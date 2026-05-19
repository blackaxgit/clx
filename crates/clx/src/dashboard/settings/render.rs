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
}
