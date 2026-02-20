//! Per-audit integrationt tests, including snapshots.

mod anonymous_definition;
mod archived_uses;
mod artipacked;
mod bot_conditions;
mod cache_poisoning;
mod concurrency_limits;
// mod dangerous_triggers; // TODO
mod dependabot_cooldown;
mod dependabot_execution;
mod direct_prompt_injection;
mod excessive_permissions;
mod forbidden_uses;
mod gemini_unrestricted_tools;
mod github_env;
// mod hardcoded_container_credentials; // TODO
mod impostor_commit;
mod indirect_prompt_injection;
mod insecure_commands;
// mod known_vulnerable_actions; // TODO
mod misfeature;
mod obfuscation;
mod overprovisioned_secrets;
mod ref_confusion;
mod ref_version_mismatch;
mod secrets_inherit;
mod secrets_outside_env;
mod self_hosted_runner;
mod stale_action_refs;
mod superfluous_actions;
mod template_injection;
mod undocumented_permissions;
mod unpinned_images;
mod unpinned_uses;
mod unredacted_secrets;
mod unsound_condition;
mod unsound_contains;
mod use_trusted_publishing;
