use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use ratatui::DefaultTerminal;

use super::app::{App, DashboardTab, InputMode};
use super::ui;

pub fn run_event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> io::Result<()> {
    loop {
        terminal.draw(|frame| ui::render(frame, app))?;

        let timeout = app
            .refresh_interval
            .checked_sub(app.last_refresh.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout)?
            && let Event::Key(key) = event::read()?
        {
            handle_key_event(app, key);
        }

        if app.last_refresh.elapsed() >= app.refresh_interval {
            app.refresh_data();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key_event(app: &mut App, key: KeyEvent) {
    match app.input_mode {
        InputMode::Normal => match key.code {
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc => app.should_quit = true,
            KeyCode::Tab => app.next_tab(),
            KeyCode::BackTab => app.prev_tab(),
            KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
            KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
            KeyCode::PageDown => app.page_down(),
            KeyCode::PageUp => app.page_up(),
            KeyCode::Char('g') | KeyCode::Home => app.scroll_to_top(),
            KeyCode::Char('G') | KeyCode::End => app.scroll_to_bottom(),
            KeyCode::Char('r') => app.refresh_data(),
            KeyCode::Char('s') => app.cycle_sort_column(),
            KeyCode::Char('S') => app.toggle_sort_direction(),
            KeyCode::Char('/') => {
                app.input_mode = InputMode::Filter;
                app.filter_text.clear();
            }
            KeyCode::Char('1') => app.current_tab = DashboardTab::Sessions,
            KeyCode::Char('2') => app.current_tab = DashboardTab::AuditLog,
            KeyCode::Char('3') => app.current_tab = DashboardTab::Rules,
            _ => {}
        },
        InputMode::Filter => match key.code {
            KeyCode::Esc => {
                app.input_mode = InputMode::Normal;
                app.filter_text.clear();
            }
            KeyCode::Enter => app.input_mode = InputMode::Normal,
            KeyCode::Backspace => {
                app.filter_text.pop();
            }
            KeyCode::Char(c) => app.filter_text.push(c),
            _ => {}
        },
    }
}
