use std::sync::LazyLock;

use github_actions_models::common::{EnvValue, Uses};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Severity},
    models::{
        StepBodyCommon, StepCommon, action::CompositeStep, uses::RepositoryUsesPattern,
        workflow::Step,
    },
    state::AuditState,
};

/// Known AI-powered GitHub Actions and their prompt sink input fields.
#[allow(clippy::unwrap_used)]
static AI_PROMPT_SINKS: LazyLock<Vec<(RepositoryUsesPattern, Vec<&'static str>)>> =
    LazyLock::new(|| {
        vec![
            (
                "anthropics/claude-code-action".parse().unwrap(),
                vec!["prompt", "direct_prompt"],
            ),
            (
                "google-github-actions/run-gemini-cli".parse().unwrap(),
                vec!["prompt"],
            ),
            ("openai/codex-action".parse().unwrap(), vec!["prompt"]),
            (
                "google-gemini/gemini-cli-action".parse().unwrap(),
                vec!["prompt"],
            ),
        ]
    });

/// Generic field names that commonly accept prompt text in AI actions.
const GENERIC_PROMPT_FIELDS: &[&str] = &["prompt", "direct_prompt"];

/// Look up the known AI action prompt sinks for a given `uses:`.
fn known_ai_sinks(
    uses: &github_actions_models::common::RepositoryUses,
) -> Option<&'static [&'static str]> {
    AI_PROMPT_SINKS
        .iter()
        .find(|(pattern, _)| pattern.matches(uses))
        .map(|(_, sinks)| sinks.as_slice())
}

/// Attacker-controlled `gh` CLI subcommands that cause the LLM to
/// read content submitted by external contributors.
const ATTACKER_CONTROLLED_GH_PATTERNS: &[&str] = &[
    "gh issue view",
    "gh pr view",
    "gh pr diff",
    "gh issue list",
    "gh pr list",
];

pub(crate) struct IndirectPromptInjection;

audit_meta!(
    IndirectPromptInjection,
    "indirect-prompt-injection",
    "prompt instructs LLM to fetch attacker-controlled data via gh CLI"
);

impl IndirectPromptInjection {
    /// Check a single input field value for attacker-controlled `gh`
    /// CLI patterns. Returns at most one finding per field.
    fn check_field_for_ipi<'doc>(
        &self,
        field_value: &str,
        field_name: &'doc str,
        step: &impl StepCommon<'doc>,
        confidence: Confidence,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let matched = ATTACKER_CONTROLLED_GH_PATTERNS
            .iter()
            .find(|&&pattern| field_value.contains(pattern));

        let Some(_pattern) = matched else {
            return Ok(None);
        };

        Ok(Some(
            Self::finding()
                .severity(Severity::Medium)
                .confidence(confidence)
                .add_location(step.location().hidden())
                .add_location(
                    step.location()
                        .with_keys(["with".into(), field_name.into()])
                        .primary()
                        .annotated(
                            "prompt instructs LLM to fetch \
                             attacker-controlled data via gh CLI",
                        ),
                )
                .add_location(
                    step.location()
                        .with_keys(["uses".into()])
                        .annotated("action with AI prompt field"),
                )
                .build(step)?,
        ))
    }

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

        let mut findings = vec![];

        // Stage 1: Known AI actions -- check registered prompt sink
        // fields.
        if let Some(sinks) = known_ai_sinks(uses) {
            for sink_field in sinks {
                let Some(EnvValue::String(field_value)) = with.get(*sink_field) else {
                    continue;
                };
                if let Some(finding) =
                    self.check_field_for_ipi(field_value, sink_field, step, Confidence::High)?
                {
                    findings.push(finding);
                }
            }
            return Ok(findings);
        }

        // Stage 2: Generic any-action -- check prompt/direct_prompt
        // fields. Only fires for actions NOT in the known list
        // (avoids double-reporting).
        for field_name in GENERIC_PROMPT_FIELDS {
            let Some(EnvValue::String(field_value)) = with.get(*field_name) else {
                continue;
            };
            if let Some(finding) =
                self.check_field_for_ipi(field_value, field_name, step, Confidence::Medium)?
            {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for IndirectPromptInjection {
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
