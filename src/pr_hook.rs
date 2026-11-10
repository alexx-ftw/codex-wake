//! Extracts an *unverified candidate* from the installed Codex PostToolUse
//! contract. A candidate is never proof that a PR was created or permission to
//! register one; callers must verify it against GitHub first.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrCandidate {
    /// The invocation identifier shared by PreToolUse and PostToolUse. The
    /// observation layer also checks session, turn, and the input digest.
    pub tool_use_id: String,
    pub number: u64,
    pub url: String,
}

const GITHUB_CREATE_PR_TOOL: &str = "mcp__codex_apps__github_create_pull_request";

/// Parse a candidate only. The installed PostToolUse response omits process
/// exit status for Bash and does not certify that the URL still exists.
pub fn parse_pr_candidate(event: &Value) -> Option<PrCandidate> {
    if event.get("hook_event_name")?.as_str()? != "PostToolUse" {
        return None;
    }
    let tool_use_id = event.get("tool_use_id")?.as_str()?.trim();
    if tool_use_id.is_empty() {
        return None;
    }
    let tool_use_id = tool_use_id.to_owned();

    let candidate = match event.get("tool_name")?.as_str()? {
        "Bash" => parse_bash_candidate(event)?,
        GITHUB_CREATE_PR_TOOL => parse_mcp_candidate(event)?,
        _ => return None,
    };
    Some(PrCandidate {
        tool_use_id,
        ..candidate
    })
}

fn parse_bash_candidate(event: &Value) -> Option<PrCandidate> {
    let args = shell_words(event.get("tool_input")?.get("command")?.as_str()?)?;
    let response = event.get("tool_response")?.as_str()?;
    let response = response.trim();

    if args
        .get(0..3)
        .is_some_and(|parts| parts[0] == "gh" && parts[1] == "pr" && parts[2] == "create")
    {
        if gh_pr_has_dry_run(&args[3..]) {
            return None;
        }
        let requested_repo = gh_repo_option(&args[3..])?;
        let candidate = parse_cli_url_output(response)?;
        if let Some(repo) = requested_repo.as_deref()
            && !same_repo(repo, &repository_from_url(&candidate.url)?)
        {
            return None;
        }
        return Some(candidate);
    }

    if args.first().map(String::as_str) == Some("gh")
        && args.get(1).map(String::as_str) == Some("api")
    {
        let (expected_repo, include) = parse_gh_api_create_options(&args)?;
        return parse_api_pr_response(response, &expected_repo, include);
    }
    None
}

/// `gh pr create` may print the URL even if a later follow-up (for example
/// attaching the PR to an issue) fails. Only accept the bare URL line; Codex
/// hook output does not contain model-facing `Process exited...` headers.
fn parse_cli_url_output(output: &str) -> Option<PrCandidate> {
    let mut lines = output.lines();
    let url = lines.next()?.trim();
    if lines.any(|line| !line.trim().is_empty()) {
        return None;
    }
    parse_github_pr_url(url)
}

fn gh_repo_option(args: &[String]) -> Option<Option<String>> {
    let mut repo = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-R" | "--repo" => {
                i += 1;
                let value = args.get(i)?;
                let value = normalize_repository(value)?;
                if repo.replace(value.to_owned()).is_some() {
                    return None;
                }
            }
            arg if arg.starts_with("--repo=") => {
                let value = normalize_repository(&arg[7..])?;
                if repo.replace(value.to_owned()).is_some() {
                    return None;
                }
            }
            option if gh_pr_option_takes_value(option) => i += 1,
            _ => {}
        }
        i += 1;
    }
    Some(repo)
}

pub(crate) fn gh_pr_has_dry_run(args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let (option, inline_value) = args[i]
            .split_once('=')
            .map_or((args[i].as_str(), None), |(key, value)| (key, Some(value)));
        if option == "--dry-run" {
            return true;
        }
        if inline_value.is_none() && gh_pr_option_takes_value(option) {
            i += 1;
        }
        i += 1;
    }
    false
}

fn gh_pr_option_takes_value(option: &str) -> bool {
    matches!(
        option,
        "-R" | "--repo"
            | "-B"
            | "--base"
            | "-H"
            | "--head"
            | "-a"
            | "--assignee"
            | "-b"
            | "--body"
            | "-F"
            | "--body-file"
            | "-l"
            | "--label"
            | "-m"
            | "--milestone"
            | "--project"
            | "-p"
            | "-T"
            | "--template"
            | "--attach"
            | "-r"
            | "--reviewer"
            | "--recover"
            | "-t"
            | "--title"
    )
}

pub(crate) fn parse_gh_api_create(args: &[String]) -> Option<String> {
    parse_gh_api_create_options(args).map(|(repo, _)| repo)
}

fn parse_gh_api_create_options(args: &[String]) -> Option<(String, bool)> {
    let mut endpoint = None;
    let mut method = None;
    let mut has_field = false;
    let mut include = false;
    let mut i = 2;
    while i < args.len() {
        let arg = args[i].as_str();
        let (option, inline) = arg
            .split_once('=')
            .map_or((arg, None), |(name, value)| (name, Some(value)));
        match option {
            "-X" | "--method" => {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        i += 1;
                        args.get(i)?.as_str()
                    }
                };
                method = Some(value.to_ascii_uppercase());
            }
            "-f" | "--raw-field" | "-F" | "--field" => {
                let value = match inline {
                    Some(value) => value,
                    None => {
                        i += 1;
                        args.get(i)?.as_str()
                    }
                };
                if !value.contains('=') || value.starts_with('=') {
                    return None;
                }
                has_field = true;
            }
            "--hostname" | "-H" | "--header" | "-q" | "--jq" | "-t" | "--template" | "-p"
            | "--preview" | "--cache" => {
                if inline.is_none() {
                    i += 1;
                    args.get(i)?;
                }
            }
            "--input" => {
                has_field = true;
                if inline.is_none() {
                    i += 1;
                    args.get(i)?;
                }
            }
            "-i" | "--include" => include = true,
            "--paginate" | "--silent" | "--slurp" | "--verbose" | "--allow-escape-sequences" => {}
            _ if arg.starts_with('-') => return None,
            _ => {
                if endpoint.replace(arg).is_some() {
                    return None;
                }
            }
        }
        i += 1;
    }

    if method
        .as_deref()
        .unwrap_or(if has_field { "POST" } else { "GET" })
        != "POST"
    {
        return None;
    }
    let endpoint = endpoint?;
    let endpoint = if let Some(path) = endpoint.strip_prefix("https://api.github.com/") {
        if path.starts_with('/') {
            return None;
        }
        path
    } else {
        endpoint
    };
    let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
    let mut parts = path.split('/');
    if parts.next()? != "repos" {
        return None;
    }
    let owner = parts.next()?;
    let repo = parts.next()?;
    if parse_repo(&format!("{owner}/{repo}")).is_none()
        || parts.next()? != "pulls"
        || parts.next().is_some()
    {
        return None;
    }
    Some((format!("{owner}/{repo}"), include))
}

/// Deliberately accepts only a simple argv-like command. Shell composition,
/// substitutions and expansions could otherwise make the apparent command
/// differ from what was executed.
fn shell_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut chars = command.chars();
    let mut active = false;
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => word.push(ch),
            (Some('"'), '$' | '`') => return None,
            (Some('"'), '\\') => match chars.next()? {
                '\n' => {}
                escaped => word.push(escaped),
            },
            (Some('"'), _) => word.push(ch),
            (Some(_), _) => return None,
            (None, '\'' | '"') => {
                quote = Some(ch);
                active = true;
            }
            (None, '\\') => match chars.next()? {
                '\n' => {}
                escaped => {
                    word.push(escaped);
                    active = true;
                }
            },
            (None, '$' | '`' | ';' | '&' | '|' | '<' | '>' | '\n' | '\r') => return None,
            (None, ch) if ch.is_whitespace() => {
                if active {
                    words.push(std::mem::take(&mut word));
                    active = false;
                }
            }
            (None, _) => {
                word.push(ch);
                active = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if active {
        words.push(word);
    }
    Some(words)
}

fn parse_api_pr_response(body: &str, expected_repo: &str, include: bool) -> Option<PrCandidate> {
    let body = if include && body.starts_with("HTTP/") {
        let (headers, body) = body
            .split_once("\r\n\r\n")
            .or_else(|| body.split_once("\n\n"))?;
        let mut lines = headers.lines();
        let mut status = lines.next()?.split_whitespace();
        let version = status.next()?.strip_prefix("HTTP/")?;
        let code = status.next()?;
        if version.is_empty()
            || code.len() != 3
            || !code.bytes().all(|b| b.is_ascii_digit())
            || !code.starts_with('2')
            || lines.any(|line| !line.contains(':'))
        {
            return None;
        }
        body
    } else {
        body
    };
    let snapshot: Value = serde_json::from_str(body).ok()?;
    parse_pr_snapshot(&snapshot, expected_repo)
}

fn parse_mcp_candidate(event: &Value) -> Option<PrCandidate> {
    let expected_repo = event
        .get("tool_input")?
        .get("repository_full_name")?
        .as_str()?;
    parse_repo(expected_repo)?;
    let response = event.get("tool_response")?;
    if response.get("isError").and_then(Value::as_bool) == Some(true) {
        return None;
    }

    let mut snapshots = Vec::new();
    if let Some(snapshot) = response.get("structuredContent") {
        snapshots.push(snapshot.clone());
    }
    if let Some(content) = response.get("content").and_then(Value::as_array) {
        for text in content.iter().filter_map(|item| {
            (item.get("type")?.as_str()? == "text")
                .then(|| item.get("text")?.as_str())
                .flatten()
        }) {
            if let Ok(snapshot) = serde_json::from_str::<Value>(text) {
                snapshots.push(snapshot);
            }
        }
    }
    let candidates: Vec<_> = snapshots
        .iter()
        .filter(|snapshot| {
            snapshot.get("number").is_some()
                || snapshot.get("html_url").is_some()
                || snapshot.get("url").is_some()
        })
        .map(parse_pr_snapshot_identity)
        .collect::<Option<Vec<_>>>()?;
    let first = candidates.first()?.clone();
    candidates
        .iter()
        .all(|candidate| {
            candidate == &first
                && repository_from_url(&candidate.url)
                    .is_some_and(|repo| same_repo(expected_repo, &repo))
        })
        .then_some(first)
}

fn parse_pr_snapshot(snapshot: &Value, expected_repo: &str) -> Option<PrCandidate> {
    let candidate = parse_pr_snapshot_identity(snapshot)?;
    same_repo(expected_repo, &repository_from_url(&candidate.url)?).then_some(candidate)
}

fn parse_pr_snapshot_identity(snapshot: &Value) -> Option<PrCandidate> {
    let snapshot = snapshot.as_object()?;
    let number = snapshot.get("number")?.as_u64()?;
    let url = snapshot
        .get("html_url")
        .or_else(|| snapshot.get("url"))?
        .as_str()?;
    let candidate = parse_github_pr_url(url)?;
    (candidate.number == number).then_some(candidate)
}

fn parse_github_pr_url(url: &str) -> Option<PrCandidate> {
    let path = github_url_path(url)?;
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if parse_repo(&format!("{owner}/{repo}")).is_none() || parts.next()? != "pull" {
        return None;
    }
    let number_text = parts.next()?;
    if parts.next().is_some()
        || number_text.is_empty()
        || !number_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let number = number_text.parse::<u64>().ok()?;
    (number > 0).then(|| PrCandidate {
        tool_use_id: String::new(),
        number,
        url: url.to_owned(),
    })
}

fn parse_repo(repo: &str) -> Option<(&str, &str)> {
    let (owner, name) = repo.split_once('/')?;
    (valid_repo_part(owner) && valid_repo_part(name) && !name.contains('/'))
        .then_some((owner, name))
}

pub(crate) fn normalize_repository(repository: &str) -> Option<&str> {
    let repository = repository
        .split_once('/')
        .filter(|(host, _)| host.eq_ignore_ascii_case("github.com"))
        .map_or(repository, |(_, path)| path);
    parse_repo(repository).map(|_| repository)
}

fn valid_repo_part(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn same_repo(left: &str, right: &str) -> bool {
    normalize_repository(left)
        .zip(normalize_repository(right))
        .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn repository_from_url(url: &str) -> Option<String> {
    let path = github_url_path(url)?;
    let mut parts = path.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    parse_repo(&format!("{owner}/{repo}"))?;
    Some(format!("{owner}/{repo}"))
}

fn github_url_path(url: &str) -> Option<&str> {
    url.strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))
}

/// A PreToolUse observation linked to a PostToolUse by the observation layer.
/// `exact_call_and_result` says whether that link and the native result meet
/// the attribution gate. It does not assert the effective network host; CLI
/// configuration can route some calls through a configured API gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreToolUseObservation {
    /// UTC Unix milliseconds when this PreToolUse was observed by the caller.
    pub observed_at_unix_ms: i64,
    pub repository: String,
    pub head_ref: Option<String>,
    pub base_ref: Option<String>,
    pub author_login: Option<String>,
    /// True only when the observation layer matched session, turn, tool_use_id,
    /// and input digest exactly and parsed a direct result from an accredited host.
    pub(crate) exact_call_and_result: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPullRequest {
    pub number: u64,
    pub repository: String,
    pub url: String,
    pub created_at: Option<String>,
    pub head_ref: Option<String>,
    pub base_ref: Option<String>,
    pub author_login: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// GET matched the candidate and exactly one tracked PreToolUse was a
    /// consistent explanation, including all expected fields available there.
    Attributed(VerifiedPullRequest),
    /// GET confirmed a PR, but the call that caused it could not be identified
    /// safely. Callers must not register this as belonging to the invocation.
    ExistsButAmbiguous {
        pull_request: VerifiedPullRequest,
        reason: &'static str,
    },
    /// The GET did not provide a trustworthy snapshot for this candidate.
    Inconclusive { reason: &'static str },
}

/// Verify a candidate using an injected response from GET
/// `/repos/{owner}/{repo}/pulls/{number}`. This function performs no network
/// calls and has no registration side effects.
///
/// `outstanding_pre_tool_uses` must contain every still-plausible PR creation
/// PreToolUse for the candidate repository. Attribution also
/// requires `created_at` to fall within the caller's configured maximum delay
/// from PreToolUse; overlong calls become ambiguous.
pub fn verify_pr_candidate(
    candidate: &PrCandidate,
    outstanding_pre_tool_uses: &[PreToolUseObservation],
    max_pre_to_creation_ms: i64,
    get_status: u16,
    get_body: &Value,
    get_observed_at_unix_ms: i64,
) -> VerificationOutcome {
    if get_status != 200 {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET did not return HTTP 200",
        };
    }
    let Some(snapshot) = get_body.as_object() else {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET body is not a JSON object",
        };
    };
    let Some(number) = snapshot.get("number").and_then(Value::as_u64) else {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET body has no valid pull request number",
        };
    };
    let Some(url) = snapshot.get("html_url").and_then(Value::as_str) else {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET body has no html_url",
        };
    };
    if !url.starts_with("https://github.com/") {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET html_url is not canonical HTTPS",
        };
    }
    let Some(url_identity) = parse_github_pr_url(url) else {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET html_url is not a GitHub pull request URL",
        };
    };
    let Some(candidate_repo) = repository_from_url(&candidate.url) else {
        return VerificationOutcome::Inconclusive {
            reason: "candidate URL has no valid GitHub repository identity",
        };
    };
    let Some(candidate_identity) = parse_github_pr_url(&candidate.url) else {
        return VerificationOutcome::Inconclusive {
            reason: "candidate URL is not a GitHub pull request URL",
        };
    };
    let Some(response_repo) = repository_from_url(url) else {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET URL has no valid repository identity",
        };
    };
    if candidate_identity.number != candidate.number
        || number != candidate.number
        || url_identity.number != candidate.number
        || !same_repo(&candidate_repo, &response_repo)
    {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET identity does not match the candidate",
        };
    }

    let base_repo = snapshot
        .get("base")
        .and_then(|base| base.get("repo"))
        .and_then(|repo| repo.get("full_name"))
        .and_then(Value::as_str);
    if base_repo.is_some_and(|repo| !same_repo(repo, &candidate_repo)) {
        return VerificationOutcome::Inconclusive {
            reason: "GitHub GET base repository does not match the candidate",
        };
    }

    let head_ref = nested_str(snapshot, &["head", "ref"]).map(str::to_owned);
    let base_ref = nested_str(snapshot, &["base", "ref"]).map(str::to_owned);
    let author_login = nested_str(snapshot, &["user", "login"]).map(str::to_owned);
    let created_at = snapshot
        .get("created_at")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let verified = VerifiedPullRequest {
        number,
        repository: response_repo,
        url: url.to_owned(),
        created_at: created_at.clone(),
        head_ref: head_ref.clone(),
        base_ref: base_ref.clone(),
        author_login: author_login.clone(),
    };

    let Some(created_at_ms) = created_at.as_deref().and_then(parse_utc_timestamp_ms) else {
        return VerificationOutcome::ExistsButAmbiguous {
            pull_request: verified,
            reason: "creation timestamp is missing or not valid UTC RFC3339",
        };
    };
    if created_at_ms > get_observed_at_unix_ms {
        return VerificationOutcome::ExistsButAmbiguous {
            pull_request: verified,
            reason: "creation timestamp is later than the verification observation",
        };
    }

    let mut plausible = Vec::new();
    for pre in outstanding_pre_tool_uses {
        let creation_seconds_after_pre =
            created_at_ms.div_euclid(1000) - pre.observed_at_unix_ms.div_euclid(1000);
        if !same_repo(&pre.repository, &candidate_repo)
            || creation_seconds_after_pre < 0
            || creation_seconds_after_pre.saturating_mul(1000) > max_pre_to_creation_ms
        {
            continue;
        }
        let fields_conflict = pre
            .head_ref
            .as_deref()
            .zip(head_ref.as_deref())
            .is_some_and(|(expected, actual)| expected != actual)
            || pre
                .base_ref
                .as_deref()
                .zip(base_ref.as_deref())
                .is_some_and(|(expected, actual)| expected != actual)
            || pre
                .author_login
                .as_deref()
                .zip(author_login.as_deref())
                .is_some_and(|(expected, actual)| !expected.eq_ignore_ascii_case(actual));
        if !fields_conflict {
            plausible.push(pre);
        }
    }

    if plausible.len() != 1 {
        return VerificationOutcome::ExistsButAmbiguous {
            pull_request: verified,
            reason: if plausible.is_empty() {
                "no tracked PreToolUse matches repository, time and available fields"
            } else {
                "multiple outstanding PreToolUse calls could match; Codex provides no shared ID"
            },
        };
    }
    let pre = plausible[0];
    // Without an exact call link and an untransformed result from an
    // accredited host, timestamp proximity alone cannot attribute a PR.
    if !pre.exact_call_and_result {
        return VerificationOutcome::ExistsButAmbiguous {
            pull_request: verified,
            reason: "exact call, raw result, or GitHub host provenance is unavailable",
        };
    }
    if pre.head_ref.is_some() && head_ref.is_none()
        || pre.base_ref.is_some() && base_ref.is_none()
        || pre.author_login.is_some() && author_login.is_none()
    {
        return VerificationOutcome::ExistsButAmbiguous {
            pull_request: verified,
            reason: "a field expected from PreToolUse is absent from the GitHub snapshot",
        };
    }
    if base_repo.is_none() {
        return VerificationOutcome::ExistsButAmbiguous {
            pull_request: verified,
            reason: "GitHub snapshot omits base repository identity",
        };
    }
    VerificationOutcome::Attributed(verified)
}

fn nested_str<'a>(object: &'a serde_json::Map<String, Value>, path: &[&str]) -> Option<&'a str> {
    let mut value = object.get(*path.first()?)?;
    for key in &path[1..] {
        value = value.get(*key)?;
    }
    value.as_str()
}

/// Parse the UTC RFC3339 form returned by GitHub and retain millisecond
/// precision. Non-UTC offsets are rejected instead of compared incorrectly.
fn parse_utc_timestamp_ms(value: &str) -> Option<i64> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date_parts = date.split('-');
    let year_text = date_parts.next()?;
    let month_text = date_parts.next()?;
    let day_text = date_parts.next()?;
    if year_text.len() != 4 || month_text.len() != 2 || day_text.len() != 2 {
        return None;
    }
    let year = year_text.parse::<i64>().ok()?;
    let month = month_text.parse::<i64>().ok()?;
    let day = day_text.parse::<i64>().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour_text = time_parts.next()?;
    let minute_text = time_parts.next()?;
    let seconds = time_parts.next()?;
    if time_parts.next().is_some() {
        return None;
    }
    if hour_text.len() != 2 || minute_text.len() != 2 {
        return None;
    }
    let hour = hour_text.parse::<i64>().ok()?;
    let minute = minute_text.parse::<i64>().ok()?;
    let (second_text, fraction) = seconds
        .split_once('.')
        .map_or((seconds, None), |(whole, fraction)| (whole, Some(fraction)));
    if second_text.len() != 2 {
        return None;
    }
    let second = second_text.parse::<i64>().ok()?;
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > month_days[(month - 1) as usize] {
        return None;
    }
    let fraction_ms = match fraction {
        Some(fraction)
            if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            let mut digits = fraction.chars().take(3).collect::<String>();
            while digits.len() < 3 {
                digits.push('0');
            }
            digits.parse::<i64>().ok()?
        }
        Some(_) => return None,
        None => 0,
    };

    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146097 + day_of_era - 719468;
    Some((((days_since_epoch * 24 + hour) * 60 + minute) * 60 + second) * 1000 + fraction_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TEST_ATTRIBUTION_WINDOW_MS: i64 = 60_000;

    // Mirrors the raw PostToolUse shape in Codex rust-v0.167.0's
    // exec_command_post_tool_use_payload_uses_output... test: tool_response is
    // the output itself, without model-facing process headers/status.
    fn bash(command: &str, response: &str) -> Value {
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_use_id": "call_pr_1",
            "tool_input": { "command": command },
            "tool_response": response
        })
    }

    #[test]
    fn accepts_raw_gh_create_url_as_unverified_candidate() {
        let event = bash(
            "gh pr create --title change --body summary",
            // The gh pr create manual's example prints this HTTP URL form.
            "http://github.com/acme/widget/pull/42\n",
        );
        assert_eq!(
            parse_pr_candidate(&event),
            Some(PrCandidate {
                tool_use_id: "call_pr_1".into(),
                number: 42,
                url: "http://github.com/acme/widget/pull/42".into(),
            })
        );
    }

    #[test]
    fn option_values_that_look_like_flags_are_not_reparsed_as_options() {
        let event = bash(
            "gh pr create --title '--dry-run' --body '--repo=other/repo'",
            "https://github.com/acme/widget/pull/42\n",
        );
        assert_eq!(parse_pr_candidate(&event).unwrap().number, 42);
    }

    #[test]
    fn create_option_values_are_not_treated_as_flags() {
        for option in ["--template", "-T", "--attach", "-p"] {
            for value in ["--dry-run", "--repo=other/repo", "-R"] {
                let command = format!("gh pr create {option} '{value}' --repo acme/widget");
                let event = bash(&command, "https://github.com/acme/widget/pull/42");
                assert_eq!(parse_pr_candidate(&event).unwrap().number, 42, "{command}");
            }
        }
    }

    #[test]
    fn rejects_dry_run_headers_and_forged_or_composed_commands() {
        for (command, output) in [
            (
                "gh pr create --dry-run",
                "https://github.com/acme/widget/pull/42",
            ),
            (
                "gh pr create",
                "Process exited with code 0\nOutput:\nhttps://github.com/acme/widget/pull/42",
            ),
            (
                "echo gh pr create",
                "https://github.com/acme/widget/pull/42",
            ),
            (
                "gh pr create; printf forged",
                "https://github.com/acme/widget/pull/42",
            ),
            (
                "gh pr create",
                "https://github.com/acme/widget/pull/42\nextra forged text",
            ),
        ] {
            assert!(
                parse_pr_candidate(&bash(command, output)).is_none(),
                "{command}"
            );
        }
    }

    #[test]
    fn checks_explicit_gh_pr_create_repo_case_insensitively() {
        let good = bash(
            "gh pr create --repo Acme/Widget",
            "https://github.com/acme/widget/pull/42",
        );
        assert_eq!(parse_pr_candidate(&good).unwrap().number, 42);
        let bad = bash(
            "gh pr create --repo acme/other",
            "https://github.com/acme/widget/pull/42",
        );
        assert!(parse_pr_candidate(&bad).is_none());

        let host_qualified = bash(
            "gh pr create --repo github.com/acme/widget",
            "https://github.com/acme/widget/pull/42",
        );
        assert_eq!(parse_pr_candidate(&host_qualified).unwrap().number, 42);
        let other_host_repo = bash(
            "gh pr create --repo github.com/acme/other",
            "https://github.com/acme/widget/pull/42",
        );
        assert!(parse_pr_candidate(&other_host_repo).is_none());
    }

    #[test]
    fn accepts_gh_api_post_creation_forms_and_case_insensitive_repo() {
        let body = r#"{"number":42,"html_url":"https://github.com/acme/widget/pull/42"}"#;
        for command in [
            "gh api -X POST /repos/ACME/Widget/pulls",
            "gh api --method POST /repos/Acme/Widget/pulls",
            "gh api repos/Acme/Widget/pulls --input pr.json",
            "gh api --input=pr.json repos/Acme/Widget/pulls",
            "gh api /repos/Acme/Widget/pulls -f title=change -f head=feature -f base=main",
            "gh api --field title=change /repos/Acme/Widget/pulls",
            "gh api /repos/Acme/Widget/pulls --method=POST",
            "gh api -X POST https://api.github.com/repos/Acme/Widget/pulls",
        ] {
            assert_eq!(
                parse_pr_candidate(&bash(command, body)).unwrap().number,
                42,
                "{command}"
            );
        }
    }

    #[test]
    fn gh_api_include_extracts_only_successful_matching_pr_response() {
        let body = r#"{"number":42,"html_url":"https://github.com/acme/widget/pull/42"}"#;
        for (flag, headers) in [
            (
                "--include",
                "HTTP/2.0 201 Created\r\nContent-Type: application/json\r\n\r\n",
            ),
            (
                "-i",
                "HTTP/1.1 201 Created\nContent-Type: application/json\n\n",
            ),
        ] {
            let command = format!("gh api {flag} -X POST repos/acme/widget/pulls");
            assert_eq!(
                parse_pr_candidate(&bash(&command, &format!("{headers}{body}")))
                    .unwrap()
                    .number,
                42
            );
        }

        let command = "gh api --include -X POST repos/acme/widget/pulls";
        for response in [
            format!("HTTP/2.0 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{body}"),
            format!("HTTP/2.0 201 Created\ninvalid header\n\n{body}"),
            "HTTP/2.0 201 Created\n\n{\"number\":42,\"html_url\":\"https://github.com/acme/other/pull/42\"}".into(),
        ] {
            assert!(parse_pr_candidate(&bash(command, &response)).is_none());
        }
        let response = format!("HTTP/2.0 201 Created\n\n{body}");
        assert!(
            parse_pr_candidate(&bash(
                "gh api -H --include -X POST repos/acme/widget/pulls",
                &response
            ))
            .is_none()
        );
    }

    #[test]
    fn bash_line_continuations_are_removed_outside_single_quotes() {
        let body = r#"{"number":42,"html_url":"https://github.com/acme/widget/pull/42"}"#;
        for command in [
            "gh api \\\n -X POST /repos/acme/widget/pulls",
            "gh api --me\\\nthod POST repos/acme/widget/pulls",
            "gh api -X POST repos/acme/\\\nwidget/pulls",
            "gh api -X POST \"/repos/acme/\\\nwidget/pulls\"",
        ] {
            assert_eq!(
                parse_pr_candidate(&bash(command, body)).unwrap().number,
                42,
                "{command:?}"
            );
        }

        let continued_pr_create = "gh pr \\\n create --repo acme/widget --title change";
        assert_eq!(
            parse_pr_candidate(&bash(
                continued_pr_create,
                "https://github.com/acme/widget/pull/42"
            ))
            .unwrap()
            .number,
            42
        );

        let single_quoted = "gh api -X POST '/repos/acme/\\\nwidget/pulls'";
        assert!(parse_pr_candidate(&bash(single_quoted, body)).is_none());

        let crlf = "gh api -X POST repos/acme/\\\r\nwidget/pulls";
        assert!(parse_pr_candidate(&bash(crlf, body)).is_none());
    }

    #[test]
    fn rejects_gh_api_non_post_wrong_repo_and_non_json_response() {
        let body = r#"{"number":42,"html_url":"https://github.com/acme/widget/pull/42"}"#;
        for command in [
            "gh api /repos/acme/widget/pulls",
            "gh api -X GET /repos/acme/widget/pulls --input pr.json",
            "gh api --method=GET --input=pr.json /repos/acme/widget/pulls",
            "gh api -X GET /repos/acme/widget/pulls -f title=change",
            "gh api --method POST /repos/acme/widget/issues",
            "gh api -X POST /repos/acme/widget/pulls/42",
            "gh api -X POST /repos/{owner}/{repo}/pulls",
            "gh api -X POST https://api.github.com.evil/repos/acme/widget/pulls",
            "gh api -X POST https://ghe.example.test/repos/acme/widget/pulls",
            "gh api -X POST https://api.github.com//repos/acme/widget/pulls",
        ] {
            assert!(
                parse_pr_candidate(&bash(command, body)).is_none(),
                "{command}"
            );
        }
        assert!(
            parse_pr_candidate(&bash(
                "gh api -X POST /repos/acme/widget/pulls",
                r#"{"number":42,"html_url":"https://github.com/acme/other/pull/42"}"#
            ))
            .is_none()
        );
        assert!(
            parse_pr_candidate(&bash(
                "gh api -X POST /repos/acme/widget/pulls",
                "Process exited with code 0\nOutput:\n{}"
            ))
            .is_none()
        );
    }

    fn mcp(response: Value) -> Value {
        json!({
            "hook_event_name": "PostToolUse",
            "tool_name": GITHUB_CREATE_PR_TOOL,
            "tool_use_id": "mcp_call_7",
            "tool_input": { "repository_full_name": "Acme/Widget", "title": "change" },
            "tool_response": response
        })
    }

    #[test]
    fn accepts_mcp_structured_content_and_json_text_case_insensitively() {
        let structured = mcp(json!({
            "structuredContent": {
                "number": 42,
                "html_url": "https://github.com/acme/widget/pull/42"
            }
        }));
        assert_eq!(parse_pr_candidate(&structured).unwrap().number, 42);

        let text = mcp(json!({
            "content": [{
                "type": "text",
                "text": "{\"number\":42,\"html_url\":\"https://github.com/ACME/Widget/pull/42\"}"
            }]
        }));
        assert_eq!(parse_pr_candidate(&text).unwrap().number, 42);
    }

    #[test]
    fn rejects_mcp_errors_conflicts_prose_and_mismatched_snapshots() {
        let url = "https://github.com/acme/widget/pull/42";
        let mut error = mcp(json!({"structuredContent":{"number":42,"html_url":url}}));
        error["tool_response"]["isError"] = json!(true);
        assert!(parse_pr_candidate(&error).is_none());

        let conflict = mcp(json!({
            "structuredContent": {"number":42,"html_url":url},
            "content": [{"type":"text","text":"{\"number\":43,\"html_url\":\"https://github.com/acme/widget/pull/43\"}"}]
        }));
        assert!(parse_pr_candidate(&conflict).is_none());

        let inconsistent_secondary = mcp(json!({
            "structuredContent": {"number":42,"html_url":url},
            "content": [{"type":"text","text":"{\"number\":43,\"html_url\":\"https://github.com/acme/widget/pull/44\"}"}]
        }));
        assert!(parse_pr_candidate(&inconsistent_secondary).is_none());

        let foreign_secondary = mcp(json!({
            "structuredContent": {"number":42,"html_url":url},
            "content": [{"type":"text","text":"{\"number\":42,\"html_url\":\"https://github.com/other/repo/pull/42\"}"}]
        }));
        assert!(parse_pr_candidate(&foreign_secondary).is_none());

        let prose = mcp(json!({
            "content": [{"type":"text","text":"Created PR: https://github.com/acme/widget/pull/42"}]
        }));
        assert!(parse_pr_candidate(&prose).is_none());
    }

    #[test]
    fn requires_post_id_and_correct_hook_tool() {
        let mut event = bash("gh pr create", "https://github.com/acme/widget/pull/42");
        event.as_object_mut().unwrap().remove("tool_use_id");
        assert!(parse_pr_candidate(&event).is_none());

        let mut event = bash("gh pr create", "https://github.com/acme/widget/pull/42");
        event["tool_use_id"] = json!("");
        assert!(parse_pr_candidate(&event).is_none());

        let mut event = bash("gh pr create", "https://github.com/acme/widget/pull/42");
        event["tool_name"] = json!("exec_command");
        assert!(parse_pr_candidate(&event).is_none());
    }

    #[test]
    fn url_only_is_never_marked_verified() {
        let candidate = parse_pr_candidate(&bash(
            "gh pr create",
            "https://github.com/acme/widget/pull/42",
        ))
        .unwrap();
        // The API exposes only PrCandidate; no success/registered flag exists.
        assert_eq!(candidate.number, 42);
        assert_eq!(candidate.tool_use_id, "call_pr_1");
    }

    fn candidate() -> PrCandidate {
        PrCandidate {
            tool_use_id: "post-call-1".into(),
            number: 42,
            url: "https://github.com/Acme/Widget/pull/42".into(),
        }
    }

    fn pre_use(at: &str) -> PreToolUseObservation {
        PreToolUseObservation {
            observed_at_unix_ms: parse_utc_timestamp_ms(at).unwrap(),
            repository: "acme/widget".into(),
            head_ref: Some("feature-x".into()),
            base_ref: Some("main".into()),
            author_login: Some("Alice".into()),
            exact_call_and_result: true,
        }
    }

    // Shape mirrors GitHub REST GET pull-request snapshots. Tests inject it;
    // verifier never performs a request or persists a registration.
    fn get_fixture() -> Value {
        json!({
            "number": 42,
            "html_url": "https://github.com/acme/widget/pull/42",
            "created_at": "2025-01-02T03:04:06Z",
            "head": {"ref": "feature-x", "repo": {"full_name": "eros/widget-fork"}},
            "base": {"ref": "main", "repo": {"full_name": "Acme/Widget"}},
            "user": {"login": "alice"}
        })
    }

    #[test]
    fn attributes_only_when_get_identity_time_and_available_fields_match() {
        let pre = pre_use("2025-01-02T03:04:05.500Z");
        let outcome = verify_pr_candidate(
            &candidate(),
            &[pre],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap(),
        );
        assert!(matches!(outcome, VerificationOutcome::Attributed(_)));
    }

    #[test]
    fn existing_pr_is_ambiguous_for_simultaneous_or_same_second_pre_calls() {
        let first = pre_use("2025-01-02T03:04:05.500Z");
        let second = first.clone();
        let verified_at = parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap();
        let outcome = verify_pr_candidate(
            &candidate(),
            &[first, second],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            verified_at,
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));

        let stale = pre_use("2025-01-02T03:00:00Z");
        let outcome = verify_pr_candidate(
            &candidate(),
            &[stale],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            verified_at,
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));

        let mut same_second = pre_use("2025-01-02T03:04:06.500Z");
        same_second.exact_call_and_result = false;
        let outcome = verify_pr_candidate(
            &candidate(),
            &[same_second],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            verified_at,
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));
    }

    #[test]
    fn same_second_is_attributed_only_with_exact_call_and_untransformed_result() {
        let mut exact = pre_use("2025-01-02T03:04:06.500Z");
        exact.exact_call_and_result = true;
        let outcome = verify_pr_candidate(
            &candidate(),
            &[exact],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap(),
        );
        assert!(matches!(outcome, VerificationOutcome::Attributed(_)));

        let mut fallback = pre_use("2025-01-02T03:04:06.500Z");
        fallback.exact_call_and_result = false;
        let outcome = verify_pr_candidate(
            &candidate(),
            &[fallback],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap(),
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));

        let mut unaccredited = pre_use("2025-01-02T03:04:03.500Z");
        unaccredited.exact_call_and_result = false;
        let outcome = verify_pr_candidate(
            &candidate(),
            &[unaccredited],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap(),
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));
    }

    #[test]
    fn field_mismatch_or_missing_pre_link_never_attributes_existing_pr() {
        let mut wrong_branch = pre_use("2025-01-02T03:04:05.500Z");
        wrong_branch.head_ref = Some("other-branch".into());
        let verified_at = parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap();
        let outcome = verify_pr_candidate(
            &candidate(),
            &[wrong_branch],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            verified_at,
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));

        for (path, value) in [
            (&["base", "ref"][..], json!("develop")),
            (&["user", "login"][..], json!("bob")),
        ] {
            let mut wrong_field = get_fixture();
            wrong_field[path[0]][path[1]] = value;
            let outcome = verify_pr_candidate(
                &candidate(),
                &[pre_use("2025-01-02T03:04:05.500Z")],
                TEST_ATTRIBUTION_WINDOW_MS,
                200,
                &wrong_field,
                verified_at,
            );
            assert!(matches!(
                outcome,
                VerificationOutcome::ExistsButAmbiguous { .. }
            ));
        }

        let outcome = verify_pr_candidate(
            &candidate(),
            &[],
            TEST_ATTRIBUTION_WINDOW_MS,
            200,
            &get_fixture(),
            verified_at,
        );
        assert!(matches!(
            outcome,
            VerificationOutcome::ExistsButAmbiguous { .. }
        ));
    }

    #[test]
    fn get_identity_and_status_are_required() {
        let pre = pre_use("2025-01-02T03:04:05.500Z");
        let verified_at = parse_utc_timestamp_ms("2025-01-02T03:04:07Z").unwrap();
        assert!(matches!(
            verify_pr_candidate(
                &candidate(),
                std::slice::from_ref(&pre),
                TEST_ATTRIBUTION_WINDOW_MS,
                404,
                &get_fixture(),
                verified_at
            ),
            VerificationOutcome::Inconclusive { .. }
        ));

        let mut wrong_number = get_fixture();
        wrong_number["number"] = json!(43);
        assert!(matches!(
            verify_pr_candidate(
                &candidate(),
                std::slice::from_ref(&pre),
                TEST_ATTRIBUTION_WINDOW_MS,
                200,
                &wrong_number,
                verified_at
            ),
            VerificationOutcome::Inconclusive { .. }
        ));

        let mut inconsistent_candidate = candidate();
        inconsistent_candidate.url = "https://github.com/acme/widget/pull/43".into();
        assert!(matches!(
            verify_pr_candidate(
                &inconsistent_candidate,
                std::slice::from_ref(&pre),
                TEST_ATTRIBUTION_WINDOW_MS,
                200,
                &get_fixture(),
                verified_at
            ),
            VerificationOutcome::Inconclusive { .. }
        ));

        let mut wrong_base_repo = get_fixture();
        wrong_base_repo["base"]["repo"]["full_name"] = json!("acme/other");
        assert!(matches!(
            verify_pr_candidate(
                &candidate(),
                &[pre],
                TEST_ATTRIBUTION_WINDOW_MS,
                200,
                &wrong_base_repo,
                verified_at
            ),
            VerificationOutcome::Inconclusive { .. }
        ));
    }

    #[test]
    fn github_timestamp_parser_checks_utc_calendar_values() {
        assert_eq!(parse_utc_timestamp_ms("1970-01-01T00:00:00Z"), Some(0));
        assert!(parse_utc_timestamp_ms("2025-02-29T00:00:00Z").is_none());
        assert!(parse_utc_timestamp_ms("2024-02-29T00:00:00Z").is_some());
        assert!(parse_utc_timestamp_ms("2025-01-02T03:04:05+01:00").is_none());
    }
}
