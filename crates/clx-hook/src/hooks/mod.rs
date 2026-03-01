//! Hook event handlers.

mod post_tool_use;
mod pre_compact;
mod pre_tool_use;
mod session_end;
mod session_start;
mod subagent;

pub(crate) use post_tool_use::handle_post_tool_use;
pub(crate) use pre_compact::handle_pre_compact;
pub(crate) use pre_tool_use::handle_pre_tool_use;
pub(crate) use session_end::handle_session_end;
pub(crate) use session_start::handle_session_start;
pub(crate) use subagent::{handle_subagent_start, handle_user_prompt_submit};
