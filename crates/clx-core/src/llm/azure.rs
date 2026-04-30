// Stub. Task 7 fills this in.

use crate::llm::{LlmError, LocalLlmBackend};

pub struct AzureOpenAIBackend;

impl LocalLlmBackend for AzureOpenAIBackend {
    async fn generate(&self, _prompt: &str, _model: Option<&str>) -> Result<String, LlmError> {
        Err(LlmError::Connection("AzureOpenAIBackend not yet implemented".to_string()))
    }
    async fn embed(&self, _text: &str, _model: Option<&str>) -> Result<Vec<f32>, LlmError> {
        Err(LlmError::Connection("AzureOpenAIBackend not yet implemented".to_string()))
    }
    async fn is_available(&self) -> bool {
        false
    }
}
