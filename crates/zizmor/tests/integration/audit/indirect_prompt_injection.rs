use crate::common::{input_under_test, zizmor};

#[test]
fn test_claude_gh_issue_view() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/claude-gh-issue-view.yml",
            ))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:15:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    15 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[indirect-prompt-injection]: prompt instructs LLM to fetch attacker-controlled data via gh CLI
      --> @@INPUT@@:13:11
       |
    11 |         - uses: anthropics/claude-code-action@v1
       |           -------------------------------------- action with AI prompt field
    12 |           with:
    13 | /           prompt: |
    14 | |             Please run gh issue view ${{ github.event.issue.number }} and summarize it.
       | |_______________________________________________________________________________________^ prompt instructs LLM to fetch attacker-controlled data via gh CLI
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_claude_gh_pr_view() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/claude-gh-pr-view.yml",
            ))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:15:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    15 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[indirect-prompt-injection]: prompt instructs LLM to fetch attacker-controlled data via gh CLI
      --> @@INPUT@@:13:11
       |
    11 |         - uses: anthropics/claude-code-action@v1
       |           -------------------------------------- action with AI prompt field
    12 |           with:
    13 | /           prompt: |
    14 | |             Run gh pr view ${{ github.event.pull_request.number }} and review it.
       | |_________________________________________________________________________________^ prompt instructs LLM to fetch attacker-controlled data via gh CLI
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_claude_gh_pr_diff() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/claude-gh-pr-diff.yml",
            ))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:15:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    15 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[indirect-prompt-injection]: prompt instructs LLM to fetch attacker-controlled data via gh CLI
      --> @@INPUT@@:13:11
       |
    11 |         - uses: anthropics/claude-code-action@v1
       |           -------------------------------------- action with AI prompt field
    12 |           with:
    13 | /           prompt: |
    14 | |             Run gh pr diff ${{ github.event.pull_request.number }} and analyze the changes.
       | |___________________________________________________________________________________________^ prompt instructs LLM to fetch attacker-controlled data via gh CLI
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_claude_gh_issue_list() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/claude-gh-issue-list.yml",
            ))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:15:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    15 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[indirect-prompt-injection]: prompt instructs LLM to fetch attacker-controlled data via gh CLI
      --> @@INPUT@@:13:11
       |
    11 |         - uses: anthropics/claude-code-action@v1
       |           -------------------------------------- action with AI prompt field
    12 |           with:
    13 | /           prompt: |
    14 | |             Run gh issue list and triage the open issues.
       | |_________________________________________________________^ prompt instructs LLM to fetch attacker-controlled data via gh CLI
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_claude_gh_pr_list() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/claude-gh-pr-list.yml",
            ))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: anthropics/claude-code-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[secrets-outside-env]: secrets referenced without a dedicated environment
      --> @@INPUT@@:15:34
       |
     8 |   run-ai:
       |   ------ this job
    ...
    15 |           anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
       |                                  ^^^^^^^^^^^^^^^^^^^^^^^^^ secret is accessed outside of a dedicated environment
       |
       = note: audit confidence → High

    warning[indirect-prompt-injection]: prompt instructs LLM to fetch attacker-controlled data via gh CLI
      --> @@INPUT@@:13:11
       |
    11 |         - uses: anthropics/claude-code-action@v1
       |           -------------------------------------- action with AI prompt field
    12 |           with:
    13 | /           prompt: |
    14 | |             Run gh pr list and summarize the open pull requests.
       | |________________________________________________________________^ prompt instructs LLM to fetch attacker-controlled data via gh CLI
       |
       = note: audit confidence → High

    5 findings (2 suppressed): 0 informational, 0 low, 2 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_generic_action_gh_issue_view() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/generic-action-gh-issue-view.yml",
            ))
            .run()?,
        @"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: some-org/unknown-ai-action@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[indirect-prompt-injection]: prompt instructs LLM to fetch attacker-controlled data via gh CLI
      --> @@INPUT@@:13:11
       |
    11 |         - uses: some-org/unknown-ai-action@v1
       |           ----------------------------------- action with AI prompt field
    12 |           with:
    13 | /           prompt: |
    14 | |             Run gh issue view ${{ github.event.issue.number }} and summarize it.
       | |_________________________________________________________________________________^ prompt instructs LLM to fetch attacker-controlled data via gh CLI
       |
       = note: audit confidence → Medium

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_safe_gh_run_view() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/safe-gh-run-view.yml",
            ))
            .run()?,
        @"
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
    "
    );
    Ok(())
}

#[test]
fn test_no_gh_commands() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "indirect-prompt-injection/no-gh-commands.yml",
            ))
            .run()?,
        @"
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
    "
    );
    Ok(())
}
