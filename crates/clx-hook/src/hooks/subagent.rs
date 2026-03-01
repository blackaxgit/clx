//! `SubagentStart` and `UserPromptSubmit` hook handlers.

use anyhow::Result;
use tracing::debug;

use crate::output::output_generic;
use crate::types::HookInput;

/// Handle `SubagentStart` hook - inject specialist rules into subagent context
pub(crate) async fn handle_subagent_start(input: HookInput) -> Result<()> {
    debug!(
        "SubagentStart: session_id={}, cwd={}",
        input.session_id, input.cwd
    );

    const SPECIALIST_CONTEXT: &str = "[SPECIALIST RULES] Execute task directly. Do NOT delegate. Follow CLAUDE.md rules. Output format: Summary, Changes, Verification, Risks.";

    output_generic("SubagentStart", Some(SPECIALIST_CONTEXT), None);
    Ok(())
}

/// Handle `UserPromptSubmit` hook - inject orchestrator reminder on user prompts
pub(crate) async fn handle_user_prompt_submit(input: HookInput) -> Result<()> {
    debug!(
        "UserPromptSubmit: session_id={}, cwd={}",
        input.session_id, input.cwd
    );

    const ORCHESTRATOR_CONTEXT: &str = "You are the Orchestrator. Delegate via Task tool. Check agent descriptions. Maximize parallelization.";

    output_generic("UserPromptSubmit", Some(ORCHESTRATOR_CONTEXT), None);
    Ok(())
}
