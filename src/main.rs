#![warn(unreachable_pub, unused_qualifications)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use color_eyre::eyre::Context as _;

fn main() -> color_eyre::Result<()> {
    let last_id = Arc::new(AtomicU64::new(id::load()?));
    let token = env::required::<String>("GITHUB_TOKEN")?;
    let client = repositories::GitHubClient::new(token);

    let my_id = last_id.clone();
    ctrlc::set_handler(move || {
        let id = my_id.load(Ordering::Relaxed);

        if let Err(report) = id::save(id) {
            eprintln!("Failed to save ID: {report}");
        }

        std::process::exit(0);
    })
    .unwrap();

    app::run(&client, last_id.clone()).wrap_err("Failed to run")
}

mod app {
    use std::io::{BufWriter, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use color_eyre::eyre::Context as _;

    use crate::{id, repositories, types};

    pub(crate) fn run(
        client: &repositories::GitHubClient,
        last_id: Arc<AtomicU64>,
    ) -> color_eyre::Result<()> {
        let file = std::fs::File::options()
            .create(true)
            .append(true)
            .open("repos.jsonl")
            .wrap_err("Failed to open repos.jsonl")?;
        let mut json = BufWriter::new(file);

        loop {
            let repos = repositories::fetch(client, last_id.load(Ordering::Relaxed))
                .wrap_err("Failed to fetch repositories")?;

            if repos.is_empty() {
                eprintln!("No new repositories found");
                break Ok(());
            }

            let ids = repos
                .iter()
                .map(|repo| repo.node_id.as_str())
                .collect::<Vec<_>>();

            let graph_repos = repositories::info(client, &ids)
                .wrap_err("Failed to fetch repository info")?
                .into_iter()
                .flatten();

            for repo in graph_repos {
                let (_, _, id) =
                    repositories::parse_node_id(&repo.id).expect("Invalid node_id format");

                write_repo(&mut json, &repo)?;
                persist_id(&last_id, id).wrap_err("Failed to save ID")?;
            }

            let id = repos.last().unwrap().id;
            persist_id(&last_id, id).wrap_err("Failed to save ID")?;
            json.flush().wrap_err("Failed to flush repos.jsonl")?;
        }
    }

    fn write_repo(
        writer: &mut BufWriter<std::fs::File>,
        repo: &types::GraphRepository,
    ) -> color_eyre::Result<()> {
        let serialized = serde_json::to_string(repo).wrap_err("Failed to serialize repository")?;
        writer
            .write_all(serialized.as_bytes())
            .wrap_err("Failed to write repository info to file")?;
        writer
            .write_all(b"\n")
            .wrap_err("Failed to write newline")?;
        Ok(())
    }

    fn persist_id(last_id: &Arc<AtomicU64>, id: u64) -> color_eyre::Result<()> {
        last_id.store(id, Ordering::Relaxed);
        id::save(id)
    }
}

mod id {
    use color_eyre::eyre::Context as _;

    pub(crate) fn load() -> color_eyre::Result<u64> {
        match std::fs::read_to_string("id") {
            Ok(text) => text.trim().parse().wrap_err("Failed to parse ID"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => color_eyre::eyre::bail!("Failed to read file: {error}"),
        }
    }

    pub(crate) fn save(id: u64) -> color_eyre::Result<()> {
        let mut buffer = itoa::Buffer::new();
        std::fs::write("id", buffer.format(id)).wrap_err("Failed to write ID")?;
        Ok(())
    }
}

mod repositories {
    use std::time::Duration;

    use color_eyre::eyre::Context as _;

    use crate::types;

    const GITHUB_API: &str = "https://api.github.com/";
    const USER_AGENT: &str = "https://github.com/gvozdvmozgu/repos";
    const GRAPHQL_QUERY_REPOSITORIES: &str = include_str!("../repos.graphql");

    #[derive(Clone)]
    pub(crate) struct GitHubClient {
        token: String,
    }

    impl GitHubClient {
        pub(crate) fn new(token: impl Into<String>) -> Self {
            Self {
                token: token.into(),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("{GITHUB_API}{path}")
        }

        fn with_defaults<B>(
            &self,
            request: ureq::RequestBuilder<B>,
        ) -> ureq::RequestBuilder<B> {
            request
                .header("authorization", &format!("token {}", self.token))
                .header("user-agent", USER_AGENT)
        }
    }

    pub(crate) fn parse_node_id(encoded: &str) -> Option<(String, String, u64)> {
        use base64::Engine as _;

        let decoded_bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .ok()?;
        let decoded = String::from_utf8(decoded_bytes).ok()?;

        let mut parts = decoded.splitn(2, ':');
        let prefix = parts.next()?.to_string();
        let rest = parts.next()?;

        let idx = rest.find(|c: char| c.is_ascii_digit())?;
        let type_name = rest[..idx].to_string();

        let numeric_id = rest[idx..].parse().ok()?;
        Some((prefix, type_name, numeric_id))
    }

    fn retry(
        mut call: impl FnMut() -> Result<http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<http::Response<ureq::Body>, ureq::Error> {
        let mut wait = Duration::from_secs(10);

        for attempt in 0..=5 {
            match call() {
                Ok(response) => return Ok(response),
                Err(error) if attempt < 5 => {
                    std::thread::sleep(wait);
                    eprintln!(
                        "Retrying request: {error}\nAttempt {}\nWait time: {wait:?}",
                        attempt + 1
                    );
                    wait *= 2;
                }
                Err(error) => return Err(error),
            };
        }

        unreachable!("Retry loop should always return")
    }

    pub(crate) fn fetch(
        client: &GitHubClient,
        last_id: u64,
    ) -> color_eyre::Result<Vec<types::Repo>> {
        let mut response = retry(|| {
            let mut buffer = itoa::Buffer::new();
            client
                .with_defaults(ureq::get(&client.url("repositories")))
                .query("since", buffer.format(last_id))
                .call()
        })?;

        response
            .body_mut()
            .read_json()
            .wrap_err("Failed to read JSON")
    }

    pub(crate) fn info(
        client: &GitHubClient,
        ids: &[&str],
    ) -> color_eyre::Result<Vec<Option<types::GraphRepository>>> {
        let mut response = retry(|| {
            client
                .with_defaults(ureq::post(&client.url("graphql")))
                .send_json(serde_json::json!({
                    "query": GRAPHQL_QUERY_REPOSITORIES,
                    "variables": {"ids": ids}
                }))
        })?;

        let response: types::GraphResponse = response
            .body_mut()
            .read_json()
            .wrap_err("Failed to read JSON")?;

        for err in response.errors.iter().flatten() {
            eprintln!("GraphQL error: {}", err.message);
        }

        if let Some(data) = response.data {
            Ok(data.nodes)
        } else {
            let mut report = color_eyre::eyre::eyre!("GitHub returned GraphQL errors");
            for err in response.errors.into_iter().flatten() {
                let line = err
                    .type_
                    .as_ref()
                    .map(|t| format!("[{}] {}", t, err.message))
                    .unwrap_or_else(|| err.message.clone());
                report = report.wrap_err(line);
            }
            Err(report)
        }
    }
}

mod types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) struct Repo {
        pub(crate) id: u64,
        pub(crate) node_id: String,
        pub(crate) name: String,
        pub(crate) full_name: String,
        pub(crate) private: bool,
        pub(crate) owner: Owner,
        pub(crate) html_url: String,
        pub(crate) description: Option<String>,
        pub(crate) fork: bool,
        pub(crate) url: String,
        pub(crate) forks_url: String,
        pub(crate) keys_url: String,
        pub(crate) collaborators_url: String,
        pub(crate) teams_url: String,
        pub(crate) hooks_url: String,
        pub(crate) issue_events_url: String,
        pub(crate) events_url: String,
        pub(crate) assignees_url: String,
        pub(crate) branches_url: String,
        pub(crate) tags_url: String,
        pub(crate) blobs_url: String,
        pub(crate) git_tags_url: String,
        pub(crate) git_refs_url: String,
        pub(crate) trees_url: String,
        pub(crate) statuses_url: String,
        pub(crate) languages_url: String,
        pub(crate) stargazers_url: String,
        pub(crate) contributors_url: String,
        pub(crate) subscribers_url: String,
        pub(crate) subscription_url: String,
        pub(crate) commits_url: String,
        pub(crate) git_commits_url: String,
        pub(crate) comments_url: String,
        pub(crate) issue_comment_url: String,
        pub(crate) contents_url: String,
        pub(crate) compare_url: String,
        pub(crate) merges_url: String,
        pub(crate) archive_url: String,
        pub(crate) downloads_url: String,
        pub(crate) issues_url: String,
        pub(crate) pulls_url: String,
        pub(crate) milestones_url: String,
        pub(crate) notifications_url: String,
        pub(crate) labels_url: String,
        pub(crate) releases_url: String,
        pub(crate) deployments_url: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) struct Owner {
        pub(crate) login: String,
        pub(crate) id: u64,
        pub(crate) node_id: String,
        pub(crate) avatar_url: String,
        pub(crate) gravatar_id: String,
        pub(crate) url: String,
        pub(crate) html_url: String,
        pub(crate) followers_url: String,
        pub(crate) following_url: String,
        pub(crate) gists_url: String,
        pub(crate) starred_url: String,
        pub(crate) subscriptions_url: String,
        pub(crate) organizations_url: String,
        pub(crate) repos_url: String,
        pub(crate) events_url: String,
        pub(crate) received_events_url: String,
        #[serde(rename = "type")]
        pub(crate) owner_type: String,
        pub(crate) user_view_type: String,
        pub(crate) site_admin: bool,
    }

    #[derive(Deserialize)]
    pub(crate) struct GraphResponse {
        pub(crate) data: Option<GraphRepositories>,
        pub(crate) errors: Option<Vec<GitHubError>>,
        #[allow(dead_code)]
        pub(crate) message: Option<String>,
    }

    #[derive(Deserialize)]
    pub(crate) struct GitHubError {
        pub(crate) message: String,
        #[serde(rename = "type")]
        pub(crate) type_: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct GraphRepositories {
        pub(crate) nodes: Vec<Option<GraphRepository>>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct GraphRepository {
        pub(crate) id: String,
        pub(crate) name_with_owner: String,
        pub(crate) stargazer_count: i64,
        pub(crate) default_branch_ref: Option<GraphRef>,
        pub(crate) languages: GraphLanguages,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub(crate) struct GraphLanguages {
        pub(crate) nodes: Vec<Option<GraphLanguage>>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub(crate) struct GraphLanguage {
        pub(crate) name: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub(crate) struct GraphRef {
        pub(crate) name: String,
    }
}

mod env {
    pub(crate) fn required<T: std::str::FromStr>(key: &str) -> color_eyre::Result<T>
    where
        T::Err: std::fmt::Display,
    {
        std::env::var(key)
            .map_err(|error| {
                color_eyre::eyre::eyre!(
                    "Failed to find required {key} environment variable: {error}"
                )
            })
            .and_then(|value| {
                value.parse::<T>().map_err(|error| {
                    color_eyre::eyre::eyre!("Failed to parse {key} environment variable: {error}")
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use base64::Engine as _;

    use super::{env, id, repositories};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDirGuard {
        old_dir: PathBuf,
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new() -> std::io::Result<Self> {
            let old_dir = std::env::current_dir()?;
            let path = std::env::temp_dir().join(format!(
                "repos-test-{}",
                TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            std::env::set_current_dir(&path)?;
            Ok(Self { old_dir, path })
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.old_dir);
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        key: String,
        prev: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap();
            let prev = std::env::var(key).ok();
            // Environment mutation is globally unsafe; we serialize access via a mutex.
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.to_string(),
                prev,
                _lock: lock,
            }
        }

        fn unset(key: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap();
            let prev = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self {
                key: key.to_string(),
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = &self.prev {
                unsafe { std::env::set_var(&self.key, prev) };
            } else {
                unsafe { std::env::remove_var(&self.key) };
            }
        }
    }

    #[test]
    fn parse_node_id_decodes_fields() {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("01:Repository12345");
        let (prefix, kind, id) =
            repositories::parse_node_id(&encoded).expect("should decode valid node id");

        assert_eq!(prefix, "01");
        assert_eq!(kind, "Repository");
        assert_eq!(id, 12345);
    }

    #[test]
    fn parse_node_id_rejects_invalid() {
        assert!(repositories::parse_node_id("not-base64").is_none());
        let encoded = base64::engine::general_purpose::STANDARD.encode("missing_number");
        assert!(repositories::parse_node_id(&encoded).is_none());
    }

    #[test]
    fn id_load_and_save_roundtrip() {
        let _dir = TempDirGuard::new().expect("failed to create temp dir");

        assert_eq!(id::load().unwrap(), 0);
        id::save(42).unwrap();
        assert_eq!(id::load().unwrap(), 42);
    }

    #[test]
    fn env_required_handles_presence_and_absence() {
        {
            let _unset = EnvGuard::unset("TEST_ENV_REQUIRED");
            assert!(env::required::<u64>("TEST_ENV_REQUIRED").is_err());
        }

        let _set = EnvGuard::set("TEST_ENV_REQUIRED", "123");
        assert_eq!(env::required::<u64>("TEST_ENV_REQUIRED").unwrap(), 123);
    }
}
