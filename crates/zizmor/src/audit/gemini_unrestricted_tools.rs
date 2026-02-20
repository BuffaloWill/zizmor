use std::sync::LazyLock;

use github_actions_models::common::Uses;

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Severity},
    models::{
        StepBodyCommon, StepCommon, action::CompositeStep, uses::RepositoryUsesPattern,
        workflow::Step,
    },
    state::AuditState,
    utils::ExtractedExpr,
};

#[allow(clippy::unwrap_used)]
static GEMINI_ACTIONS: LazyLock<Vec<(RepositoryUsesPattern, &'static str)>> = LazyLock::new(|| {
    vec![
        // https://github.com/google-github-actions/run-gemini-cli
        (
            "google-github-actions/run-gemini-cli".parse().unwrap(),
            "settings",
        ),
        // https://github.com/google-gemini/gemini-cli-action (archived)
        (
            "google-gemini/gemini-cli-action".parse().unwrap(),
            "settings_json",
        ),
    ]
});

pub(crate) struct GeminiUnrestrictedTools;

audit_meta!(
    GeminiUnrestrictedTools,
    "gemini-unrestricted-tools",
    "Gemini CLI action with unrestricted tools"
);

impl GeminiUnrestrictedTools {
    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        let StepBodyCommon::Uses {
            uses: Uses::Repository(uses),
            with,
        } = step.body()
        else {
            return Ok(vec![]);
        };

        let Some((_pattern, settings_key)) = GEMINI_ACTIONS
            .iter()
            .find(|(pattern, _)| pattern.matches(uses))
        else {
            return Ok(vec![]);
        };

        let settings_val = with.get(*settings_key).map(|v| v.to_string());

        let Some(raw) = settings_val else {
            // Settings input absent entirely: all tools unrestricted.
            return Ok(vec![
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::High)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(["uses".into()])
                            .annotated(
                                "no settings input \
                             \u{2014} all Gemini built-in tools \
                             are unrestricted",
                            ),
                    )
                    .build(step)?,
            ]);
        };

        let trimmed = raw.trim();

        // Skip dynamic expressions that cannot be analyzed statically.
        if ExtractedExpr::from_fenced(trimmed).is_some() {
            return Ok(vec![]);
        }

        // Parse as JSON; skip malformed values silently.
        let parsed: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => return Ok(vec![]),
        };

        // Accept either flat "coreTools" or nested "tools.core".
        let has_core_tools = parsed.get("coreTools").is_some()
            || parsed.get("tools").and_then(|t| t.get("core")).is_some();

        if has_core_tools {
            return Ok(vec![]);
        }

        // Settings present but no tool restriction found.
        Ok(vec![
            Self::finding()
                .severity(Severity::Medium)
                .confidence(Confidence::High)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(["with".into(), (*settings_key).into()])
                        .annotated(
                            "settings JSON does not restrict \
                         built-in tools via coreTools",
                        ),
                )
                .build(step)?,
        ])
    }
}

#[async_trait::async_trait]
impl Audit for GeminiUnrestrictedTools {
    fn new(_state: &AuditState) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    async fn audit_step<'doc>(
        &self,
        step: &Step<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }

    async fn audit_composite_step<'doc>(
        &self,
        step: &CompositeStep<'doc>,
        _config: &Config,
    ) -> Result<Vec<Finding<'doc>>, AuditError> {
        self.process_step(step)
    }
}
