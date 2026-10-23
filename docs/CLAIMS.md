# Claims and their evidence

Every protective claim in the [README](../README.md) is listed here with the tests that prove it, or with the stated limit that bounds it. `tests/test_repo.py` checks that every test named here exists, and that every row of the README's "What you get" table has a section here. A claim with neither a test nor a limit doesn't belong in the README.

Test references are `file::Class::test`.

## Reader agents

| Claim | Evidence |
|---|---|
| The readers' tool lists are narrow: search and fetch only, or Read, Grep and Glob only. | `tests/test_repo.py::RepoTests::test_reader_agents_keep_narrow_tools` |
| The gate treats a reader whose definition has grown as an ordinary agent: no web, no untrusted or quarantine folders. | `tests/test_reader_gate.py::IdentityTests::test_plugin_agent_with_bash_added`, `tests/test_reader_gate.py::IdentityTests::test_plugin_agent_block_list_with_write`, `tests/test_reader_gate.py::IdentityTests::test_plugin_agent_without_tools_inherits_everything`, `tests/test_reader_gate.py::IdentityTests::test_plugin_agent_with_mcp_servers` |
| Another agent can't pass as a reader. | `tests/test_reader_gate.py::IdentityTests::test_project_agent_claiming_the_reserved_name`, `tests/test_reader_gate.py::GenerativeShadowTests::test_mutated_shadow_files_keep_the_readers_off`, `tests/test_reader_gate.py::GenerativeIdentityTests::test_mutated_reader_names` |
| A reader uses only its own tools, even if it got another some other way (a tool loaded on demand, a changed definition). | `tests/test_reader_tools.py::ReaderToolsTests::test_a_reader_is_refused_any_tool_but_its_own`, `tests/test_reader_tools.py::ReaderToolsTests::test_hooks_json_runs_it_for_every_tool`, `tests/test_launch_gate.py::MainTests::test_a_reader_never_gets_a_shell`. Live: VERIFY row 31. Limits: it lets every reader use the tool Claude Code gives background subagents to hand back a report (`SubagentHandback`), and a new tool of that kind would be refused until it's added; any agent named like a reader, from any plugin or folder, gets the same limit. |
| A fooled reader can still report false things. | Limit: README, "It doesn't make a hijacked reader harmless". |

## Reader gate

| Claim | Evidence |
|---|---|
| Only the web reader reaches the web. | `tests/test_reader_gate.py::WebTests::test_websearch_only_for_the_web_reader`, `tests/test_reader_gate.py::WebTests::test_webfetch_only_for_the_web_reader` |
| Never local or private hosts. | `tests/test_reader_gate.py::WebTests::test_private_resolutions_are_refused`, `tests/test_reader_gate.py::WebTests::test_host_tricks_are_refused_for_everyone`, `tests/test_reader_gate.py::GenerativeHostTests::test_bad_hosts_stay_refused`. Limit: README, "DNS can change". |
| Untrusted folders are read only by the document reader, quarantine folders only by the quarantine reviewer. | `tests/test_reader_gate.py::ReadTests::test_untrusted_folder_only_for_the_document_reader`, `tests/test_reader_gate.py::ReadTests::test_quarantine_only_for_the_reviewer`, `tests/test_reader_gate.py::GrepTests::test_grep_into_untrusted_and_quarantine`, `tests/test_reader_gate.py::GlobTests::test_glob_in_untrusted_is_for_the_document_reader` |
| Readers stay inside their folders. | `tests/test_reader_gate.py::ReadTests::test_readers_are_confined`, `tests/test_reader_gate.py::GrepTests::test_readers_grep_only_their_folders`, `tests/test_reader_gate.py::GlobTests::test_readers_glob_only_their_folders` |
| Secret paths are closed to every agent. | `tests/test_reader_gate.py::ReadTests::test_secrets_denied_for_everyone`, `tests/test_reader_gate.py::GrepTests::test_grep_globs_aimed_at_secrets`, `tests/test_reader_gate.py::GapFixTests::test_m1_grep_globs_aimed_at_folder_and_name_secrets`, `tests/test_reader_gate.py::GapFixTests::test_m1_grep_rooted_at_a_named_secret_folder`, `tests/test_reader_gate.py::GenerativePathTests::test_bad_paths_stay_denied`, `tests/test_reader_gate.py::GapFixTests::test_a_home_paths_are_denied`, `tests/test_reader_gate.py::GapFixTests::test_a_project_credential_files_are_denied_anywhere`, `tests/test_reader_gate.py::GapFixTests::test_b_symlinked_secret_root`, `tests/test_reader_gate.py::GapFixTests::test_e_glob_in_a_secret_folder`. Limit: README, "Paths are judged by name", "Grep can still print lines from a secret file, in two ways" and "Bash isn't covered by the reader gate". |
| The transcript folder is closed, except an agent's own saved output. | `tests/test_reader_gate.py::TranscriptTests::test_transcripts_and_saved_outputs_are_closed`, `tests/test_reader_gate.py::TranscriptTests::test_an_agent_opens_its_own_saved_output`, `tests/test_reader_gate.py::TranscriptTests::test_no_agent_opens_another_agents_saved_output`, `tests/test_reader_gate.py::TranscriptTests::test_glob_lists_no_names_in_transcripts`, `tests/test_reader_gate.py::GapFixTests::test_h_claude_code_state_is_closed`, `tests/test_reader_gate.py::GapFixTests::test_h_claude_config_dir_state_is_closed_too`. Limit: README, "Saved tool output trusts the transcript". |
| It never allows or asks; any error or timeout blocks. | `tests/test_reader_gate.py::MainTests::test_pass_is_exit_0_and_silent`, `tests/test_reader_gate.py::MainTests::test_timeout_fails_closed`, `tests/test_reader_gate.py::MainTests::test_internal_error_fails_closed`, `tests/test_reader_gate.py::MainTests::test_bad_json_and_bad_shapes_fail_closed`. Limit: README, "Hook timeouts". |
| The log holds paths and hosts only. | `tests/test_reader_gate.py::WebTests::test_log_holds_host_only`, `tests/test_reader_gate.py::WebTests::test_search_query_never_logged` |
| The launch gate and the reader-tools hook log a code, the tool and the agent's name, never command text or file contents. | `tests/test_launch_gate.py::MainTests::test_a_deny_is_logged_with_a_code_and_no_command_text`, `tests/test_reader_tools.py::LogTests::test_a_refusal_is_logged_with_the_tool_and_agent_only`, `tests/test_reader_tools.py::LogTests::test_only_a_short_code_reaches_the_log` |
| A crafted input can't stall it. | `tests/test_regex_linear_time.py::LinearRegexes::test_every_pattern_and_check_is_linear_on_hostile_input`, `tests/test_regex_linear_time.py::StaticLint::test_no_pattern_has_repeats_that_trade_characters` |
| MCP, connector and browser tools aren't gated. | Limit: README, "MCP, connector and browser tools aren't gated". |

## Launch gate

| Claim | Evidence |
|---|---|
| Fetch-and-run launchers, downloads piped into an interpreter, `sudo` and agents launched with permissions off are denied. | `tests/test_launch_gate.py::CheckTests::test_denies`, `tests/test_launch_gate.py::CheckTests::test_passes`. Limit: README, "The launch gate is a tripwire, not a security boundary". |
| `ssh`, `scp` and `sftp` are kept to plain remote access, and `ssh_hosts` limits the hosts. | `tests/test_launch_gate.py::SshTests::test_other_hosts_are_denied`, `tests/test_launch_gate.py::SshTests::test_allow_prefixes_never_relax_ssh`, `tests/test_launch_gate.py::SshTests::test_option_parsing`. Limit: README, "Servers are out of its reach". |
| Text that names the ssh family and that the parser could misread (a second line, `<<`, `$((`, `$[`, or no parse) is refused. | `tests/test_launch_gate.py::TrickyTextTests::test_each_is_refused_as_tricky_text`, `tests/test_launch_gate.py::TrickyTextTests::test_name_norm`. Limit: names built at run time (README, "The launch gate is a tripwire"). |
| An ssh-family word that bash would expand before ssh sees it is refused. | `tests/test_launch_gate.py::ExpansionTests`. Limit: names built at run time (README, "The launch gate is a tripwire"). |
| A redirect that names its file descriptor with a variable is read as a redirect, so it can't hide the command after it; words are brace-expanded as bash does before they're checked, and an expansion too large to check is refused. | `tests/test_launch_gate.py::CheckTests::test_denies` (the "fd variable" and "brace" rows), `tests/test_launch_gate.py::CheckTests::test_passes`, `tests/test_launch_gate.py::BraceExpansionTests`. |
| Monitor commands get the same checks as Bash; unknown Monitor fields, WebSocket watches and watches whose text names a downloader or network client are refused. | `tests/test_launch_gate.py::MonitorTests`. Limit: that Claude Code runs the hook for Monitor is [VERIFY](VERIFY.md) row M1, run by hand on a main-session call in default mode and passed on Claude Code 2.1.301; step M1b alone repeated on 2.1.309 ([results](verify/RESULTS-2026-10-22-cc2.1.301-2.1.309.md)); the settings template denies Monitor until it passes on your version (`tests/test_doctor.py::DoctorTests::test_monitor_deny_passes_where_it_is_and_warns_where_it_isnt`). The name scan is a tripwire: a name built some other way can get through. Other watches can still carry outside text (README, "Monitor is denied until checked"). |
| A Bash or Monitor call that asks for extra network hosts (`allowed_domains`) is handed to Claude Code's permission prompt naming each host, or refused with `launch_gate.ask_for_domains` set to `false`, from a subagent, where nobody can be asked, or for a name outside the host grammar. Limit: the ask is a request for a prompt, not a block; that you see it and nothing approves it for you is VERIFY row M2, run by hand and passed on Claude Code 2.1.309 only, for Bash, with the sandbox on and in auto mode, with allow rules up to `Bash(*)` (Monitor calls, other modes, another plugin's hook, a PermissionRequest hook and SDK callbacks weren't tested, nor whether Claude Code would prompt without the gate). Where the prompt's wording was recorded, it was Claude Code's own and didn't show the gate's warning text. | `tests/test_launch_gate.py::MonitorTests::test_extra_hosts_are_asked_by_default_and_refused_when_turned_off`, `test_extra_hosts_are_asked_when_turned_on`, `test_extra_hosts_are_refused_where_nobody_can_be_asked`, `test_host_names_outside_the_grammar_are_refused_not_shown` |
| Any error or timeout blocks. | `tests/test_launch_gate.py::MainTests::test_bad_json_fails_closed`, `tests/test_launch_gate.py::MainTests::test_timeout_fails_closed`, `tests/test_launch_gate.py::MainTests::test_bad_config_denies_everything` |

## Settings template

| Claim | Evidence |
|---|---|
| It denies secret reads, matching the reader gate. | `tests/test_repo.py::RepoTests::test_settings_template_reads_are_also_closed_by_the_gate`. Limit: glob rules don't reach sandboxed Bash (README, Install in detail). |
| It denies agents edits to your settings, hooks, agents, MCP config, rules, gate config, the gates' log and the installed plugin. | `tests/test_repo.py::RepoTests::test_settings_template_protects_the_guardrails` |
| It asks you before the common ways of going public (repos, releases, gists, issues, PRs, `gh api`, workflows, secrets, package publishing, image pushes, the GitHub MCP server) or a browser tool runs. | `tests/test_repo.py::RepoTests::test_settings_template_asks_before_going_public_or_driving_a_browser`, `tests/test_doctor.py::DoctorTests::test_a_missing_notes_ask_rule_warns`. Limit: rules match a command's start, so other spellings, flags before the subcommand and wrappers get past them. With the sandbox on, those run without a prompt (the doctor warns about publish tokens in the environment: `tests/test_doctor.py::DoctorTests::test_a_publish_token_in_the_environment_warns_while_sandbox_commands_auto_run`), and with it off, so does anything an allow rule of yours for the whole tool covers (the doctor warns about those: `tests/test_doctor.py::DoctorTests::test_an_allow_rule_for_a_whole_publishing_tool_warns`); pushes aren't covered (README, Install in detail). |
| Plugins can't ship permissions, so you merge it. | Limit: README, "What you get". |

## Sandbox template

| Claim | Evidence |
|---|---|
| The setup turns the sandbox on. | `tests/test_apply.py::ApplyTests::test_fresh_install_in_one_step_then_nothing_to_do`, `tests/test_setup.py::SetupTests::test_commands_work_on_a_fresh_home_and_twice` |
| The network allowlist is yours to set. | Limit: README, "It doesn't take away your authority". |
| The one-command install denies sandboxed writes to the start-up paths in your home folder that exist and aren't symlinks, each a whole folder or file directly in it, leaving out caches, venvs and paths your `allowWrite` names; the doctor lists the missing ones and what a deny can't cover. | `tests/test_apply.py::ApplyTests::test_start_paths_that_exist_are_write_denied`, `tests/test_apply.py::ApplyTests::test_start_paths_never_include_whole_config_folders`, `tests/test_apply.py::ApplyTests::test_start_paths_skip_caches_venvs_and_relative_path_entries`, `tests/test_apply.py::ApplyTests::test_allow_write_keeps_a_start_path_writable_and_says_so`, `tests/test_doctor.py::DoctorTests::test_start_paths_warn_for_existing_ones_only`, `tests/test_doctor.py::DoctorTests::test_a_deep_deny_doesnt_count_and_is_noted`. Limit: it narrows the route and doesn't close it. Start files that don't exist and symlinked ones aren't covered, it matters only in a session whose writable folders include your home folder, and the Edit and Write tools aren't stopped there (README, "The launch gate is a tripwire"). |

## Rules

| Claim | Evidence |
|---|---|
| The rules are loaded in your sessions. | `tests/test_doctor.py::DoctorTests::test_rules_missing_import_or_canary`, `tests/test_doctor.py::DoctorTests::test_default_profile_import_fails_in_an_alternate_profile`; the doctor skill's canary step checks the live session. |
| They're instructions to the model, not enforcement. | Limit: README, "What you get". |

## Auto-mode rules

| Claim | Evidence |
|---|---|
| A model makes the call; it's a second opinion. | Limit: README, "The auto-mode classifier is a model". |

## Setup

| Claim | Evidence |
|---|---|
| `/stranger-danger:setup` writes nothing. | `tests/test_setup.py::SetupTests::test_prints_real_paths_and_writes_nothing` |
| Each step is safe to run twice, and keeps what you have. | `tests/test_setup.py::SetupTests::test_commands_work_on_a_fresh_home_and_twice`, `tests/test_setup.py::SetupTests::test_merge_keeps_what_is_there`, `tests/test_setup.py::SetupTests::test_copies_never_overwrite` |
| The one-command install shows a diff and writes nothing without a terminal and a "y". | `tests/test_apply.py::ApplyTests::test_it_writes_nothing_without_a_terminal_or_a_yes`, `tests/test_apply.py::ApplyTests::test_refuses_without_a_terminal_when_run_as_a_script`, `tests/test_apply.py::ApplyTests::test_merge_keeps_yours_shows_a_diff_and_keeps_a_backup` |
| A bad settings shape stops it before anything is written. | `tests/test_apply.py::ApplyTests::test_a_type_clash_stops_before_writing`, `tests/test_setup.py::SetupTests::test_merge_stops_on_an_unexpected_shape` |

## Doctor

| Claim | Evidence |
|---|---|
| It checks the setup. | `tests/test_doctor.py::DoctorTests::test_full_setup_has_no_warnings_or_failures`, `tests/test_doctor.py::DoctorTests::test_missing_deny_rules_are_listed`, `tests/test_doctor.py::DoctorTests::test_sandbox_off_warns`, `tests/test_doctor.py::DoctorTests::test_secret_files_only_glob_denied_are_listed`, `tests/test_doctor.py::DoctorTests::test_wildcard_remote_shell_allow_rules_fail` |
| It never prints a secret or the canary. | `tests/test_doctor.py::DoctorTests::test_canary_is_never_printed` |
| It proves the gates are loaded in your session. | The doctor skill's live probes (`skills/doctor/SKILL.md`); not unit-testable. |

## Report

| Claim | Evidence |
|---|---|
| It leaves out paths, hosts, the log's agent names and the doctor's details. | `tests/test_doctor.py::DoctorTests::test_the_report_leaves_out_paths_hosts_and_details`, `tests/test_doctor.py::DoctorTests::test_a_crafted_plugin_version_isnt_printed`, `tests/test_doctor.py::DoctorTests::test_a_failed_report_prints_no_paths` |
| It names only the plugin's own checks, of whether the gates run; setup checks are only counted. | `tests/test_doctor.py::DoctorTests::test_the_report_names_only_the_plugins_own_checks`. Limit: a FAIL among the named checks shows a gate isn't working. |
| Only the decisions and codes the hooks write reach it. | `tests/test_doctor.py::DoctorTests::test_the_report_shows_only_codes_the_hooks_write`, `tests/test_reader_tools.py::LogTests::test_every_code_the_hooks_write_is_known`. `tests/test_doctor.py::DoctorTests::test_the_report_gives_rough_counts`. Limit: anything that can write the log chooses which of about 230 decision-and-code rows appear and their rough size: several hundred bits, enough for a token. With the settings template's deny rules, only a process outside the sandbox, or a session run in your home folder, can write the log; if you're not sure what wrote it, leave the table out. |
| A log the hooks can't write (a link, pipe, folder or hard link in its place, a changed owner or mode, or a full log) doesn't read as "nothing logged". | `tests/test_doctor.py::DoctorTests::test_the_report_shows_a_full_or_broken_log`, `tests/test_coordinator.py::CoordinatorTests::test_a_fifo_or_link_in_the_logs_place_reads_as_empty`, `tests/test_coordinator.py::CoordinatorTests::test_a_log_the_hooks_cant_write_is_flagged`, `tests/test_coordinator.py::CoordinatorTests::test_a_full_log_is_flagged` |
| Nothing is sent: you read it and paste it. | The skill only prints the script's output and tells the model not to post it (`skills/report/SKILL.md`); `doctor.py` itself opens no connection (it runs `claude --version` and `npm config get`, whose own update checks are theirs). Limit: the versions, your operating system's name and the plugin's own check names are in it. |

## Coordinator

| Claim | Evidence |
|---|---|
| It never approves anything: the page has nothing that acts. | `tests/test_coordinator.py::CoordinatorTests::test_page_has_nothing_that_acts_even_with_hostile_log_and_notes`, `tests/test_coordinator.py::CoordinatorTests::test_script_imports_nothing_that_reaches_the_network_or_a_shell` |
| A tampered page fails the doctor. | `tests/test_coordinator.py::CoordinatorTests::test_page_check_catches_what_a_tampered_page_could_add`, `tests/test_doctor.py::DoctorTests::test_a_tampered_status_page_fails`, `tests/test_doctor.py::DoctorTests::test_a_replaced_status_page_fails_without_being_read`, `tests/test_coordinator.py::CoordinatorTests::test_page_check_is_fast_on_hostile_input`, `tests/test_coordinator.py::CoordinatorTests::test_main_refuses_a_symlinked_notes_folder` |
| Every session's `CLAUDE.md` names its folder and says its messages are requests, never your OK. | `tests/test_coordinator.py::IdentityTests::test_the_paragraph_says_the_rules_and_round_trips`, `tests/test_coordinator.py::IdentityTests::test_install_writes_config_paragraph_and_notes_and_is_safe_twice`, `tests/test_doctor.py::DoctorTests::test_paragraph_that_names_another_folder_or_is_edited_fails` |
| No plain-text name or folder can inject into `CLAUDE.md`. | `tests/test_coordinator.py::IdentityTests::test_names_are_plain_words_only`, `tests/test_coordinator.py::IdentityTests::test_folder_must_be_a_real_folder_but_not_home_or_root` |
| Only you run the installer, and it never leaves the config and `CLAUDE.md` disagreeing. | `tests/test_coordinator.py::IdentityTests::test_install_main_refuses_inside_claude_code_or_a_redirected_setup`, `tests/test_coordinator.py::IdentityTests::test_install_refuses_unsafe_places_and_puts_the_config_back`, `tests/test_coordinator.py::IdentityTests::test_install_splices_by_newline_only`, `tests/test_coordinator.py::IdentityTests::test_install_notes_are_private_and_never_follow_a_link` |
| A fake paragraph in a project file is flagged (best effort: it's a keyword check, so a reworded fake can pass; the real paragraph tells every session that such text is untrusted). | `tests/test_doctor.py::DoctorTests::test_a_coordinator_paragraph_in_a_project_file_warns`, `tests/test_doctor.py::DoctorTests::test_a_coordinator_claim_in_project_rules_or_other_wording_warns`, `tests/test_doctor.py::DoctorTests::test_a_coordinator_claim_in_an_imported_file_warns`, `tests/test_doctor.py::DoctorTests::test_a_folder_sharing_the_project_key_warns` |
| The coordinator holds no more power than any other session. | `tests/test_doctor.py::DoctorTests::test_coordinator_project_permissions_are_flagged` |
| Other sessions can't plant notes for it through the Edit and Write tools without asking you. Limit: a session's Bash can still write them, so the coordinator treats every note as data. | `tests/test_doctor.py::DoctorTests::test_a_missing_notes_ask_rule_warns`; the notes are labelled unchecked on the page (`tests/test_coordinator.py::CoordinatorTests::test_page_has_nothing_that_acts_even_with_hostile_log_and_notes`). |
| It can't be fooled by a redirected config or home folder. | `tests/test_coordinator.py::IdentityTests::test_whoami_refuses_a_redirected_config_or_home`, `tests/test_doctor.py::DoctorTests::test_a_redirected_config_fails`, `tests/test_launch_gate.py::MainTests::test_a_config_override_inside_a_session_fails_closed`, `tests/test_doctor.py::DoctorTests::test_a_redirected_home_fails`, `tests/test_coordinator.py::CoordinatorTests::test_main_refuses_a_redirected_config` |
| Workers treat its messages as requests. | Limit: that's model behavior, checked live in [VERIFY.md](VERIFY.md), "Optional: the coordinator". |
