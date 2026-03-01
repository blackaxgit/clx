use ratatui::prelude::*;
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::dashboard::app::App;
use crate::dashboard::data::BuiltinRuleRow;

pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    let filter = app.filter_text.to_lowercase();

    let mut lines: Vec<Line> = Vec::new();

    // Builtin Whitelist
    render_builtin_section(
        &mut lines,
        "Builtin Whitelist",
        &app.data.builtin_whitelist,
        Color::Green,
        "+ ",
        &filter,
    );

    lines.push(Line::from(""));

    // Builtin Blacklist
    render_builtin_section(
        &mut lines,
        "Builtin Blacklist",
        &app.data.builtin_blacklist,
        Color::Red,
        "- ",
        &filter,
    );

    lines.push(Line::from(""));

    // Config Whitelist
    render_builtin_section(
        &mut lines,
        "Config Whitelist",
        &app.data.config_whitelist,
        Color::Green,
        "+ ",
        &filter,
    );

    lines.push(Line::from(""));

    // Config Blacklist
    render_builtin_section(
        &mut lines,
        "Config Blacklist",
        &app.data.config_blacklist,
        Color::Red,
        "- ",
        &filter,
    );

    lines.push(Line::from(""));

    // Learned Rules
    let filtered_learned: Vec<_> = app
        .data
        .learned_rules
        .iter()
        .filter(|r| filter.is_empty() || r.pattern.to_lowercase().contains(&filter))
        .collect();

    lines.push(Line::from(Span::styled(
        format!("Learned Rules ({})", filtered_learned.len()),
        Style::default().fg(Color::Cyan).bold(),
    )));
    lines.push(Line::from(""));

    if filtered_learned.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No learned rules",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        for rule in &filtered_learned {
            let type_style = match rule.rule_type.as_str() {
                "allow" => Style::default().fg(Color::Green),
                "deny" => Style::default().fg(Color::Red),
                _ => Style::default().fg(Color::Yellow),
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {} ", rule.rule_type), type_style),
                Span::raw(&rule.pattern),
            ]));
            lines.push(Line::from(vec![
                Span::styled("       scope: ", Style::default().fg(Color::DarkGray)),
                Span::raw(&rule.scope),
                Span::styled(
                    format!("  +{}/-{}", rule.confirmations, rule.denials),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }
    }

    let block = Block::bordered().title(" Rules ");
    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.rules_scroll_offset, 0));

    frame.render_widget(paragraph, area);
}

fn render_builtin_section<'a>(
    lines: &mut Vec<Line<'a>>,
    title: &str,
    rules: &'a [BuiltinRuleRow],
    color: Color,
    prefix: &str,
    filter: &str,
) {
    let filtered: Vec<_> = rules
        .iter()
        .filter(|r| filter.is_empty() || r.pattern.to_lowercase().contains(filter))
        .collect();

    lines.push(Line::from(Span::styled(
        format!("{} ({})", title, filtered.len()),
        Style::default().fg(color).bold(),
    )));
    lines.push(Line::from(""));

    if filtered.is_empty() {
        lines.push(Line::from(Span::styled(
            "  None",
            Style::default().fg(Color::DarkGray).italic(),
        )));
    } else {
        for rule in &filtered {
            let desc = rule
                .description
                .as_deref()
                .map(|d| format!("  {d}"))
                .unwrap_or_default();
            lines.push(Line::from(vec![
                Span::styled(format!("  {prefix}"), Style::default().fg(color)),
                Span::raw(&rule.pattern),
                Span::styled(desc, Style::default().fg(Color::DarkGray)),
            ]));
        }
    }
}
