//! Hook event handlers.

pub(crate) mod aggregator;
mod permission_request;
mod post_compact;
mod post_tool_use;
mod pre_compact;
mod pre_tool_use;
mod session_end;
mod session_start;
mod stop_auto_summary;
mod subagent;

pub(crate) use permission_request::handle_permission_request;
pub(crate) use post_compact::handle_post_compact;
pub(crate) use post_tool_use::handle_post_tool_use;
pub(crate) use pre_compact::handle_pre_compact;
pub(crate) use pre_tool_use::handle_pre_tool_use;
pub(crate) use session_end::handle_session_end;
pub(crate) use session_start::handle_session_start;
pub(crate) use stop_auto_summary::handle_stop_auto_summary;
pub(crate) use subagent::{handle_subagent_start, handle_user_prompt_submit};
