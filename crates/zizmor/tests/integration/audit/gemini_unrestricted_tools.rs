use crate::common::{input_under_test, zizmor};

#[test]
fn test_no_settings_run_gemini_cli() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/no-settings-run-gemini-cli.yml",
            ))
            .run()?,
        @r"
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

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_no_settings_gemini_cli_action() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/no-settings-gemini-cli-action.yml",
            ))
            .run()?,
        @r"
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

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_settings_missing_tools_core() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/settings-missing-tools-core.yml",
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
      --> @@INPUT@@:15:11
       |
    15 |           settings: '{"theme": "dark"}'
       |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ settings JSON does not restrict built-in tools via coreTools
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "#
    );
    Ok(())
}

#[test]
fn test_settings_empty_tools_core() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/settings-empty-tools-core.yml",
            ))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-github-actions/run-gemini-cli@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_settings_nonempty_tools_core() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/settings-nonempty-tools-core.yml",
            ))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-github-actions/run-gemini-cli@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_settings_expression() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/settings-expression.yml",
            ))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-github-actions/run-gemini-cli@v1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_settings_malformed_json() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/settings-malformed-json.yml",
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

    3 findings (2 suppressed): 0 informational, 0 low, 0 medium, 1 high
    "#
    );
    Ok(())
}

#[test]
fn test_sha_pinned() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/sha-pinned.yml",
            ))
            .run()?,
        @r"
    warning[gemini-unrestricted-tools]: Gemini CLI action with unrestricted tools
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-github-actions/run-gemini-cli@abcdef1234567890abcdef1234567890abcdef12
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ no settings input — all Gemini built-in tools are unrestricted
       |
       = note: audit confidence → High

    3 findings (2 suppressed): 0 informational, 0 low, 1 medium, 0 high
    "
    );
    Ok(())
}

#[test]
fn test_tag_pinned() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/tag-pinned.yml",
            ))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-gemini/gemini-cli-action@v0.2.1
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[gemini-unrestricted-tools]: Gemini CLI action with unrestricted tools
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-gemini/gemini-cli-action@v0.2.1
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ no settings input — all Gemini built-in tools are unrestricted
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );
    Ok(())
}

#[test]
fn test_branch_pinned() -> anyhow::Result<()> {
    insta::assert_snapshot!(
        zizmor()
            .input(input_under_test(
                "gemini-unrestricted-tools/branch-pinned.yml",
            ))
            .run()?,
        @r"
    error[unpinned-uses]: unpinned action reference
      --> @@INPUT@@:11:15
       |
    11 |       - uses: google-github-actions/run-gemini-cli@main
       |               ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ action is not pinned to a hash (required by blanket policy)
       |
       = note: audit confidence → High

    warning[gemini-unrestricted-tools]: Gemini CLI action with unrestricted tools
      --> @@INPUT@@:11:9
       |
    11 |       - uses: google-github-actions/run-gemini-cli@main
       |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ no settings input — all Gemini built-in tools are unrestricted
       |
       = note: audit confidence → High

    4 findings (2 suppressed): 0 informational, 0 low, 1 medium, 1 high
    "
    );
    Ok(())
}
