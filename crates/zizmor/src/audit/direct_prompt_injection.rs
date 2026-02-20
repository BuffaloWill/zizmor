use std::sync::LazyLock;

use fst::Map;
use github_actions_expressions::Expr;
use github_actions_models::common::{EnvValue, Uses};

use crate::{
    audit::{Audit, AuditError, AuditLoadError, audit_meta},
    config::Config,
    finding::{Confidence, Finding, Severity},
    models::{
        StepBodyCommon, StepCommon, action::CompositeStep, inputs::Capability,
        uses::RepositoryUsesPattern, workflow::Step,
    },
    state::AuditState,
    utils::extract_fenced_expressions,
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

static CONTEXT_CAPABILITIES_FST: LazyLock<Map<&[u8]>> = LazyLock::new(|| {
    fst::Map::new(
        include_bytes!(concat!(env!("OUT_DIR"), "/context-capabilities.fst"))
            .as_slice(),
    )
    .expect("couldn't initialize context capabilities FST")
});

/// Look up the known AI action prompt sinks for a given `uses:`.
fn known_ai_sinks(
    uses: &github_actions_models::common::RepositoryUses,
) -> Option<&'static [&'static str]> {
    AI_PROMPT_SINKS
        .iter()
        .find(|(pattern, _)| pattern.matches(uses))
        .map(|(_, sinks)| sinks.as_slice())
}

/// Map a GitHub expression context to its capability level.
fn capability_from_context(context: &str) -> Option<Capability> {
    match CONTEXT_CAPABILITIES_FST.get(context) {
        Some(0) => Some(Capability::Arbitrary),
        Some(1) => Some(Capability::Structured),
        Some(2) => Some(Capability::Fixed),
        Some(_) => unreachable!("unexpected context capability"),
        _ => None,
    }
}

pub(crate) struct DirectPromptInjection;

audit_meta!(
    DirectPromptInjection,
    "direct-prompt-injection",
    "direct prompt injection via template expansion in AI action"
);

impl DirectPromptInjection {
    /// Check a single input field value for untrusted expression
    /// contexts. Returns at most one finding per field, using the
    /// highest severity encountered across all expressions.
    fn check_field_for_injection<'doc>(
        &self,
        field_value: &'doc str,
        field_name: &'doc str,
        step: &impl StepCommon<'doc>,
        confidence: Confidence,
        annotation: &'doc str,
    ) -> Result<Option<Finding<'doc>>, AuditError> {
        let mut worst_severity: Option<Severity> = None;

        for (expr, _expr_span) in extract_fenced_expressions(field_value) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                continue;
            };

            for (context, _origin) in parsed.dataflow_contexts() {
                let Some(context_pattern) = context.as_pattern() else {
                    continue;
                };

                let severity = match capability_from_context(&context_pattern) {
                    Some(Capability::Fixed) => continue,
                    Some(Capability::Structured) => Severity::Medium,
                    Some(Capability::Arbitrary) => Severity::High,
                    None => {
                        // Heuristics for contexts not in the FST:
                        // secrets.* are not exploitable via prompt
                        // injection
                        if context.child_of("secrets") {
                            continue;
                        }
                        // Unknown github.* contexts are likely
                        // attacker-controlled
                        if context.child_of("github") {
                            Severity::High
                        } else {
                            // Other unknown contexts (matrix, env,
                            // etc.): skip to avoid false positives in
                            // this audit. template-injection already
                            // covers these.
                            continue;
                        }
                    }
                };

                worst_severity = Some(match worst_severity {
                    Some(prev) if prev >= severity => prev,
                    _ => severity,
                });
            }
        }

        match worst_severity {
            Some(severity) => Ok(Some(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .add_location(step.location().hidden())
                    .add_location(
                        step.location()
                            .with_keys(["with".into(), field_name.into()])
                            .primary()
                            .annotated(annotation),
                    )
                    .add_location(
                        step.location()
                            .with_keys(["uses".into()])
                            .annotated("action with AI prompt field"),
                    )
                    .build(step)?,
            )),
            None => Ok(None),
        }
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
                if let Some(finding) = self.check_field_for_injection(
                    field_value,
                    sink_field,
                    step,
                    Confidence::High,
                    "untrusted input in AI action prompt",
                )? {
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
            if let Some(finding) = self.check_field_for_injection(
                field_value,
                field_name,
                step,
                Confidence::Medium,
                "untrusted input in action prompt field",
            )? {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

#[async_trait::async_trait]
impl Audit for DirectPromptInjection {
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
