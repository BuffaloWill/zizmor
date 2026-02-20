use crate::common::{input_under_test, zizmor};

#[test]
fn test_claude_arbitrary_context() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/claude-arbitrary-context.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:14:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    14 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |         -------------------------------------- action with AI prompt field
    12 |         with:
    13 |           prompt: "Review this: ${{ github.event.comment.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in AI action prompt
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_claude_structured_context() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/claude-structured-context.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:14:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    14 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |         -------------------------------------- action with AI prompt field
    12 |         with:
    13 |           prompt: "Review PR: ${{ github.event.pull_request.html_url }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in AI action prompt
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "#
    );
    Ok(())
}

#[test]
fn test_claude_safe_context() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/claude-safe-context.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:14:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    14 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "#
    );
    Ok(())
}

#[test]
fn test_claude_direct_prompt_beta() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/claude-direct-prompt-beta.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@beta
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:14:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    14 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: anthropics/claude-code-action@beta
       |         ---------------------------------------- action with AI prompt field
    12 |         with:
    13 |           direct_prompt: "${{ github.event.comment.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in AI action prompt
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_gemini_cli_arbitrary() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/gemini-cli-arbitrary.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-github-actions/run-gemini-cli@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[gemini-unrestricted-tools]: Gemini CLI action with unrestricted tools
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-github-actions/run-gemini-cli@v1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ no settings input — all Gemini built-in tools are unrestricted
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: google-github-actions/run-gemini-cli@v1
       |         --------------------------------------------- action with AI prompt field
    12 |         with:
    13 |           prompt: "${{ github.event.comment.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in AI action prompt
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_codex_arbitrary() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/codex-arbitrary.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: openai/codex-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: openai/codex-action@v1
       |         ---------------------------- action with AI prompt field
    12 |         with:
    13 |           prompt: "${{ github.event.issue.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in AI action prompt
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_gemini_cli_action_arbitrary() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/gemini-cli-action-arbitrary.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-gemini/gemini-cli-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[gemini-unrestricted-tools]: Gemini CLI action with unrestricted tools
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-gemini/gemini-cli-action@v1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ no settings input — all Gemini built-in tools are unrestricted
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: google-gemini/gemini-cli-action@v1
       |         ---------------------------------------- action with AI prompt field
    12 |         with:
    13 |           prompt: "${{ github.event.comment.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in AI action prompt
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_generic_prompt_arbitrary() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/generic-prompt-arbitrary.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: some-org/unknown-ai-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: some-org/unknown-ai-action@v1
       |         ----------------------------------- action with AI prompt field
    12 |         with:
    13 |           prompt: "${{ github.event.issue.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in action prompt field
       |
       = note: audit confidence → Medium

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_generic_direct_prompt_field() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/generic-direct-prompt-field.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: another-org/custom-action@v2
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[direct-prompt-injection]: direct prompt injection via template expansion in AI action
      --> @@INPUT@@:13:11
       |
    11 |       - uses: another-org/custom-action@v2
       |         ---------------------------------- action with AI prompt field
    12 |         with:
    13 |           direct_prompt: "Process: ${{ github.event.comment.body }}"
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ untrusted input in action prompt field
       |
       = note: audit confidence → Medium

    4 findings (2 suppressed): 0 informational, 0 low, 0 medium, 2 high
    "#
    );
    Ok(())
}

#[test]
fn test_safe_contexts_no_finding() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "direct-prompt-injection/safe-contexts-no-finding.yml",
            ))
            .run()?,
        @r#"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:15:15
       |
    15 |       - uses: openai/codex-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:14:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    14 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 1 medium, 2 high
    "#
    );
    Ok(())
}
