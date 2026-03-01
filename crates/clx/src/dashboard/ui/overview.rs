use ratatui::prelude::*;
use ratatui::widgets::{Paragraph, Wrap};

use crate::dashboard::app::App;
use clx_core::types::estimate_cost;

/// Format a token count as human-readable (e.g. "1.2M", "45.2K", or raw number).
fn format_tokens(tokens: i64) -> String {
    if tokens >= 1_000_000 {
        format!("{:.1}M", tokens as f64 / 1_000_000.0)
    } else if tokens >= 1_000 {
        format!("{:.1}K", tokens as f64 / 1_000.0)
    } else {
        tokens.to_string()
    }
}

/// Render a compact text-based gauge bar as a series of styled spans.
fn gauge_bar(ratio: f64, width: usize, label: &str, color: Color) -> Vec<Span<'static>> {
    let filled = ((ratio * width as f64).round() as usize).min(width);
    let empty = width - filled;
    vec![
        Span::styled("█".repeat(filled), Style::default().fg(color)),
        Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(" {}% {}", (ratio * 100.0) as u16, label),
            Style::default().fg(color),
        ),
    ]
}

/// Height required for the overview header (2 lines of stats).
pub(crate) const HEADER_HEIGHT: u16 = 2;

/// Render overview stats as a compact header into the given area.
pub(crate) fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let cost = estimate_cost(app.data.total_input_tokens, app.data.total_output_tokens);
    let total = app.data.total_commands.max(1) as f64;

    let mut lines: Vec<Line> = Vec::new();

    // Line 1: Summary stats
    let allowed_ratio = (app.data.allowed_commands as f64 / total).clamp(0.0, 1.0);
    let denied_ratio = (app.data.denied_commands as f64 / total).clamp(0.0, 1.0);
    let prompted_ratio = (app.data.prompted_commands as f64 / total).clamp(0.0, 1.0);

    lines.push(Line::from(vec![
        Span::styled("Sessions: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", app.data.total_sessions),
            Style::default().bold(),
        ),
        Span::styled(
            format!(" ({} active)", app.data.active_sessions),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  │  "),
        Span::styled("Tokens: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{} in", format_tokens(app.data.total_input_tokens)),
            Style::default().bold(),
        ),
        Span::raw("/"),
        Span::styled(
            format!("{} out", format_tokens(app.data.total_output_tokens)),
            Style::default().bold(),
        ),
        Span::raw("  │  "),
        Span::styled("Cost: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("${cost:.2}"),
            Style::default().bold().fg(Color::Yellow),
        ),
        Span::raw("  │  "),
        Span::styled("Cmds: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{}", app.data.total_commands),
            Style::default().bold(),
        ),
    ]));

    // Line 2: Gauge bars + risk on same line
    let bar_width: usize = 10;
    let mut spans = gauge_bar(allowed_ratio, bar_width, "allow", Color::Green);
    spans.push(Span::raw("  "));
    spans.extend(gauge_bar(denied_ratio, bar_width, "deny", Color::Red));
    spans.push(Span::raw("  "));
    spans.extend(gauge_bar(
        prompted_ratio,
        bar_width,
        "prompt",
        Color::Yellow,
    ));
    spans.push(Span::raw("  │  "));
    spans.push(Span::styled("Risk ", Style::default().fg(Color::DarkGray)));
    spans.push(Span::styled(
        format!("L:{}", app.data.risk_low),
        Style::default().fg(Color::Green),
    ));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        format!("M:{}", app.data.risk_medium),
        Style::default().fg(Color::Yellow),
    ));
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        format!("H:{}", app.data.risk_high),
        Style::default().fg(Color::Red),
    ));
    lines.push(Line::from(spans));

    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
}
