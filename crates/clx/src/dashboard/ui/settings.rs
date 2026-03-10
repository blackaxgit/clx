use ratatui::prelude::*;

use crate::dashboard::app::App;
use crate::dashboard::settings::render;

/// Thin render shim — delegates to the settings module.
pub fn render(frame: &mut Frame, app: &mut App, area: Rect) {
    render::render_settings_tab(frame, app, area);
}
