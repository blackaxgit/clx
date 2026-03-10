mod app;
mod data;
mod event;
pub(crate) mod settings;
mod ui;

use std::io;

pub fn run_dashboard(days: u32, refresh_secs: u64) -> io::Result<()> {
    // Install panic hook to restore terminal on crash
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let () = ratatui::restore();
        original_hook(panic_info);
    }));

    let mut terminal = ratatui::init();
    let mut app = app::App::new(days, refresh_secs);

    // Initial data load
    app.refresh_data();

    let result = event::run_event_loop(&mut terminal, &mut app);

    ratatui::restore();
    result
}
