//! Manifest parsing — the declarative verification checklist (TOML).
//!
//! A manifest is a list of typed checks. Each check declares what "correct"
//! means for one observable: a file's existence/content, a command's exit
//! code/output, an HTTP endpoint's status/body, git worktree state, or a JSON
//! field. The executor runs checks sequentially and aggregates a report.
//!
//! Parse/validation failures are the caller's bug (manifest authoring), not a
//! verification failure: the CLI maps them to exit code 2.

use serde::Deserialize;
use std::fmt;

#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    pub meta: Option<Meta>,
    #[serde(default)]
    pub check: Vec<Check>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    pub name: Option<String>,
    /// 允许"由**真判过**退化为不判"的检查名白名单（silence 棘轮的唯一逃生口）。
    ///
    /// `na` 在 verify 模式下只有一个来源：`enabled = false`。那已经是作者声明，
    /// 但它同时也是"让一条失败的检查从绿灯里消失"的唯一手法。棘轮默认把
    /// "上一条完成运行里判过、这次变 na"判为 inconclusive（exit 2）；要把某条
    /// 检查**有意**静音，必须在这里列名——一次可评审、有上界的编辑。
    #[serde(default, rename = "silence-ok")]
    pub silence_ok: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Check {
    File(FileCheck),
    Cmd(CmdCheck),
    Http(HttpCheck),
    Git(GitCheck),
    Json(JsonCheck),
}

impl Check {
    pub fn name(&self) -> &str {
        match self {
            Check::File(c) => &c.name,
            Check::Cmd(c) => &c.name,
            Check::Http(c) => &c.name,
            Check::Git(c) => &c.name,
            Check::Json(c) => &c.name,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Check::File(_) => "file",
            Check::Cmd(_) => "cmd",
            Check::Http(_) => "http",
            Check::Git(_) => "git",
            Check::Json(_) => "json",
        }
    }

    pub fn enabled(&self) -> bool {
        match self {
            Check::File(c) => c.enabled,
            Check::Cmd(c) => c.enabled,
            Check::Http(c) => c.enabled,
            Check::Git(c) => c.enabled,
            Check::Json(c) => c.enabled,
        }
    }
}

pub fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileCheck {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: String,
    /// exists | not_exists (default exists)
    #[serde(default)]
    pub expect: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub not_contains: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CmdCheck {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub cmd: String,
    /// expected exit code (default 0)
    #[serde(default)]
    pub exit: Option<i32>,
    #[serde(default)]
    pub stdout_contains: Option<String>,
    #[serde(default)]
    pub stderr_contains: Option<String>,
    #[serde(default)]
    pub stdout_regex: Option<String>,
    #[serde(default)]
    pub stderr_regex: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpCheck {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub url: String,
    /// expected status code (default 200)
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub body_contains: Option<String>,
    #[serde(default = "default_http_timeout")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitCheck {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// clean | branch (default clean)
    #[serde(default)]
    pub expect: Option<String>,
    /// required when expect = branch
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JsonCheck {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub path: String,
    /// dotted field path, array index supported: a.b[0].c
    pub field: String,
    /// equals <value> — value parsed as JSON literal (string/number/bool/null)
    #[serde(default)]
    pub equals: Option<serde_json::Value>,
    /// assert the field merely exists
    #[serde(default)]
    pub exists: Option<bool>,
}

pub fn default_timeout() -> u64 {
    60
}

pub fn default_http_timeout() -> u64 {
    10
}

#[derive(Debug)]
pub struct ManifestError(pub String);

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Parse + structurally validate a manifest.
pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
    let manifest: Manifest =
        toml::from_str(text).map_err(|e| ManifestError(format!("TOML parse error: {e}")))?;
    validate(&manifest)?;
    Ok(manifest)
}

fn validate(m: &Manifest) -> Result<(), ManifestError> {
    if m.check.is_empty() {
        return Err(ManifestError(
            "manifest defines no checks (empty gate = false confidence)".into(),
        ));
    }
    for (i, check) in m.check.iter().enumerate() {
        let ctx = format!("check[{}] \"{}\" ({})", i, check.name(), check.kind());
        match check {
            Check::File(c) => {
                if c.path.is_empty() {
                    return Err(ManifestError(format!("{ctx}: path is required")));
                }
                let expect = c.expect.as_deref().unwrap_or("exists");
                if expect != "exists" && expect != "not_exists" {
                    return Err(ManifestError(format!(
                        "{ctx}: expect must be exists|not_exists, got {expect:?}"
                    )));
                }
                let contents = c.contains.is_some() as u8
                    + c.not_contains.is_some() as u8
                    + c.regex.is_some() as u8;
                if contents > 1 {
                    return Err(ManifestError(format!(
                        "{ctx}: contains/not_contains/regex are mutually exclusive"
                    )));
                }
                if let Some(re) = &c.regex {
                    validate_regex(re, &ctx)?;
                }
            }
            Check::Cmd(c) => {
                if c.cmd.is_empty() {
                    return Err(ManifestError(format!("{ctx}: cmd is required")));
                }
                if c.timeout_secs == 0 {
                    return Err(ManifestError(format!("{ctx}: timeout_secs must be > 0")));
                }
                for re in [&c.stdout_regex, &c.stderr_regex].into_iter().flatten() {
                    validate_regex(re, &ctx)?;
                }
            }
            Check::Http(c) => {
                if c.url.is_empty() {
                    return Err(ManifestError(format!("{ctx}: url is required")));
                }
                if c.timeout_secs == 0 {
                    return Err(ManifestError(format!("{ctx}: timeout_secs must be > 0")));
                }
            }
            Check::Git(c) => {
                let expect = c.expect.as_deref().unwrap_or("clean");
                if expect != "clean" && expect != "branch" {
                    return Err(ManifestError(format!(
                        "{ctx}: expect must be clean|branch, got {expect:?}"
                    )));
                }
                if expect == "branch" && c.branch.as_deref().unwrap_or("").is_empty() {
                    return Err(ManifestError(format!(
                        "{ctx}: expect=branch requires branch"
                    )));
                }
            }
            Check::Json(c) => {
                if c.path.is_empty() || c.field.is_empty() {
                    return Err(ManifestError(format!("{ctx}: path and field are required")));
                }
                if c.equals.is_none() && c.exists != Some(true) {
                    return Err(ManifestError(format!(
                        "{ctx}: json check needs equals <value> or exists = true"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_regex(re: &str, ctx: &str) -> Result<(), ManifestError> {
    regex::Regex::new(re)
        .map_err(|e| ManifestError(format!("{ctx}: invalid regex {re:?}: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = r#"
[meta]
name = "t"

[[check]]
name = "file"
type = "file"
path = "a.txt"
contains = "x"

[[check]]
name = "cmd"
type = "cmd"
cmd = "true"
"#;

    #[test]
    fn parses_valid_manifest() {
        let m = parse(PASS).expect("valid manifest");
        assert_eq!(m.check.len(), 2);
        assert_eq!(m.check[0].name(), "file");
        assert_eq!(m.check[0].kind(), "file");
        assert!(m.check[0].enabled());
        assert_eq!(m.check[1].kind(), "cmd");
    }

    #[test]
    fn empty_manifest_rejected() {
        let err = parse("[meta]\nname = \"x\"\n").expect_err("empty gate rejected");
        assert!(err.0.contains("no checks"));
    }

    #[test]
    fn mutually_exclusive_contents_rejected() {
        let bad = r#"
[[check]]
name = "c"
type = "file"
path = "a"
contains = "x"
not_contains = "y"
"#;
        let err = parse(bad).expect_err("conflict rejected");
        assert!(err.0.contains("mutually exclusive"));
    }

    #[test]
    fn bad_regex_rejected() {
        let bad = r#"
[[check]]
name = "c"
type = "file"
path = "a"
regex = "("
"#;
        let err = parse(bad).expect_err("bad regex rejected");
        assert!(err.0.contains("invalid regex"));
    }

    #[test]
    fn git_branch_requires_branch_field() {
        let bad = r#"
[[check]]
name = "g"
type = "git"
expect = "branch"
"#;
        let err = parse(bad).expect_err("branch requires branch field");
        assert!(err.0.contains("requires branch"));
    }

    #[test]
    fn disabled_ok() {
        let m = parse(
            r#"
[[check]]
name = "off"
type = "cmd"
cmd = "exit 1"
enabled = false
"#,
        )
        .expect("disabled check parses");
        assert!(!m.check[0].enabled());
    }
}
