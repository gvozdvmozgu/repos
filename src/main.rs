#![warn(unreachable_pub, unused_qualifications)]

use std::sync::Arc;

use color_eyre::eyre::Context as _;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let initial_id = id::load().await?;
    let last_id = Arc::new(id::Tracker::new(initial_id));
    let token = env::required::<String>("GITHUB_TOKEN")?;
    let client = repositories::GitHubClient::new(token)?;

    let shutdown_id = last_id.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let id = shutdown_id.current();
            if let Err(report) = shutdown_id.persist(id).await {
                eprintln!("Failed to save ID: {report}");
            }
            std::process::exit(0);
        }
    });

    app::run(&client, last_id.clone())
        .await
        .wrap_err("Failed to run")
}

mod app {
    use std::sync::Arc;

    use color_eyre::eyre::Context as _;
    use tokio::fs::OpenOptions;
    use tokio::io::{AsyncWriteExt, BufWriter};

    use crate::{id, repositories, types};

    pub(crate) async fn run(
        client: &repositories::GitHubClient,
        last_id: Arc<id::Tracker>,
    ) -> color_eyre::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("repos.jsonl")
            .await
            .wrap_err("Failed to open repos.jsonl")?;
        let mut json = BufWriter::new(file);

        loop {
            let repos = repositories::fetch(client, last_id.current())
                .await
                .wrap_err("Failed to fetch repositories")?;

            if repos.is_empty() {
                eprintln!("No new repositories found");
                break Ok(());
            }

            let ids = repos
                .iter()
                .map(|repo| repo.node_id.as_str())
                .collect::<Vec<_>>();

            let graph_repos = fetch_graph_repositories(client, &ids, repos.len()).await?;
            let last_written_id = match write_graph_repositories(&mut json, graph_repos).await? {
                Some(id) => id,
                None => {
                    eprintln!(
                        "GraphQL returned zero nodes for REST page size {}; not advancing ID",
                        repos.len()
                    );
                    json.flush().await.wrap_err("Failed to flush repos.jsonl")?;
                    continue;
                }
            };

            last_id
                .persist(last_written_id)
                .await
                .wrap_err("Failed to save ID")?;
            json.flush().await.wrap_err("Failed to flush repos.jsonl")?;
        }
    }

    pub(crate) async fn fetch_graph_repositories<'a>(
        client: &repositories::GitHubClient,
        ids: &[&'a str],
        rest_count: usize,
    ) -> color_eyre::Result<Vec<types::GraphRepository>> {
        let graph_repos = repositories::info(client, ids)
            .await
            .wrap_err("Failed to fetch repository info")?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        if graph_repos.len() < rest_count {
            eprintln!(
                "GraphQL returned fewer nodes ({}) than REST page ({}); \
                 advancing to last written GraphQL repo only",
                graph_repos.len(),
                rest_count
            );
        }

        Ok(graph_repos)
    }

    pub(crate) async fn write_graph_repositories(
        writer: &mut BufWriter<tokio::fs::File>,
        graph_repos: Vec<types::GraphRepository>,
    ) -> color_eyre::Result<Option<u64>> {
        let mut last_written_id = None;

        for repo in graph_repos {
            let (_, _, id) = repositories::parse_node_id(&repo.id).expect("Invalid node_id format");
            write_repo(writer, &repo).await?;
            last_written_id = Some(id);
        }

        Ok(last_written_id)
    }

    async fn write_repo(
        writer: &mut BufWriter<tokio::fs::File>,
        repo: &types::GraphRepository,
    ) -> color_eyre::Result<()> {
        let serialized = serde_json::to_string(repo).wrap_err("Failed to serialize repository")?;
        writer
            .write_all(serialized.as_bytes())
            .await
            .wrap_err("Failed to write repository info to file")?;
        writer
            .write_all(b"\n")
            .await
            .wrap_err("Failed to write newline")?;
        Ok(())
    }
}

mod id {
    use std::sync::atomic::{AtomicU64, Ordering};

    use color_eyre::eyre::Context as _;
    use tokio::fs;
    use tokio::sync::Mutex;

    pub(crate) struct Tracker {
        current: AtomicU64,
        lock: Mutex<()>,
    }

    impl Tracker {
        pub(crate) fn new(initial: u64) -> Self {
            Self {
                current: AtomicU64::new(initial),
                lock: Mutex::new(()),
            }
        }

        pub(crate) fn current(&self) -> u64 {
            self.current.load(Ordering::Relaxed)
        }

        pub(crate) async fn persist(&self, id: u64) -> color_eyre::Result<()> {
            let _guard = self.lock.lock().await;
            self.current.store(id, Ordering::Relaxed);
            save(id).await
        }
    }

    pub(crate) async fn load() -> color_eyre::Result<u64> {
        match fs::read_to_string("id").await {
            Ok(text) => text.trim().parse().wrap_err("Failed to parse ID"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => color_eyre::eyre::bail!("Failed to read file: {error}"),
        }
    }

    pub(crate) async fn save(id: u64) -> color_eyre::Result<()> {
        let mut buffer = itoa::Buffer::new();
        fs::write("id", buffer.format(id))
            .await
            .wrap_err("Failed to write ID")?;
        Ok(())
    }
}

mod repositories {
    use std::future::Future;
    use std::time::Duration;

    use color_eyre::eyre::Context as _;
    use reqwest::{Url, header};
    use tokio::time::sleep;

    use crate::types;

    const GITHUB_API: &str = "https://api.github.com/";
    const USER_AGENT: &str = "https://github.com/gvozdvmozgu/repos";
    const GRAPHQL_QUERY_REPOSITORIES: &str = include_str!("../repos.graphql");

    #[derive(Clone)]
    pub(crate) struct GitHubClient {
        http: reqwest::Client,
        base: Url,
    }

    impl GitHubClient {
        pub(crate) fn new(token: impl Into<String>) -> color_eyre::Result<Self> {
            let token = token.into();
            let mut headers = header::HeaderMap::new();
            let auth = header::HeaderValue::from_str(&format!("token {}", token))
                .wrap_err("Invalid GitHub token header value")?;
            headers.insert(header::AUTHORIZATION, auth);

            let http = reqwest::Client::builder()
                .user_agent(USER_AGENT)
                .default_headers(headers)
                .build()
                .wrap_err("Failed to build reqwest client")?;

            let base = Url::parse(GITHUB_API).wrap_err("Invalid GitHub API base URL")?;

            Ok(Self { http, base })
        }

        fn url(&self, path: &str) -> Url {
            self.base
                .join(path)
                .expect("Failed to join GitHub API path")
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

    async fn retry<F, Fut>(mut call: F) -> reqwest::Result<reqwest::Response>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = reqwest::Result<reqwest::Response>>,
    {
        let mut wait = Duration::from_secs(10);

        for attempt in 0..=5 {
            match call().await {
                Ok(response) => return Ok(response),
                Err(error) if attempt < 5 => {
                    sleep(wait).await;
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

    pub(crate) async fn fetch(
        client: &GitHubClient,
        last_id: u64,
    ) -> color_eyre::Result<Vec<types::Repo>> {
        let response = retry(|| {
            let mut buffer = itoa::Buffer::new();
            let url = client.url("repositories");

            async move {
                client
                    .http
                    .get(url)
                    .query(&[("since", buffer.format(last_id))])
                    .send()
                    .await
            }
        })
        .await?;

        response.json().await.wrap_err("Failed to read JSON")
    }

    pub(crate) async fn info(
        client: &GitHubClient,
        ids: &[&str],
    ) -> color_eyre::Result<Vec<Option<types::GraphRepository>>> {
        let response = retry(|| {
            let url = client.url("graphql");
            let ids = ids.to_owned();

            async move {
                client
                    .http
                    .post(url)
                    .json(&serde_json::json!({
                        "query": GRAPHQL_QUERY_REPOSITORIES,
                        "variables": {"ids": ids}
                    }))
                    .send()
                    .await
            }
        })
        .await?;

        let response: types::GraphResponse =
            response.json().await.wrap_err("Failed to read JSON")?;

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
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    use super::{app, env, id, repositories, types};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
    static WORKDIR_LOCK: Mutex<()> = Mutex::new(());

    struct TempDirGuard {
        old_dir: PathBuf,
        path: PathBuf,
        _lock: MutexGuard<'static, ()>,
    }

    impl TempDirGuard {
        fn new() -> std::io::Result<Self> {
            let lock = WORKDIR_LOCK.lock().unwrap();
            let old_dir = std::env::current_dir()?;
            let path = std::env::temp_dir().join(format!(
                "repos-test-{}",
                TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            if path.exists() {
                let _ = fs::remove_dir_all(&path);
            }
            fs::create_dir(&path)?;
            std::env::set_current_dir(&path)?;
            Ok(Self {
                old_dir,
                path,
                _lock: lock,
            })
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
        let encoded = base64::engine::general_purpose::STANDARD.encode("01:Repository12345");
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

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            assert_eq!(id::load().await.unwrap(), 0);
            id::save(42).await.unwrap();
            assert_eq!(id::load().await.unwrap(), 42);
        });
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

    #[test]
    fn write_graph_repositories_tracks_last_id_and_writes_lines() {
        let _dir = TempDirGuard::new().expect("failed to create temp dir");
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let repo_a = sample_repo(1, "owner/repo-a");
            let repo_b = sample_repo(2, "owner/repo-b");

            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("repos.jsonl")
                .await
                .unwrap();
            let mut writer = tokio::io::BufWriter::new(file);

            let last = app::write_graph_repositories(&mut writer, vec![repo_a, repo_b])
                .await
                .unwrap();
            writer.flush().await.unwrap();

            assert_eq!(last, Some(2));

            let contents = tokio::fs::read_to_string("repos.jsonl").await.unwrap();
            let lines: Vec<_> = contents.lines().collect();
            assert_eq!(lines.len(), 2);
        });
    }

    #[test]
    fn write_graph_repositories_handles_empty_input() {
        let _dir = TempDirGuard::new().expect("failed to create temp dir");
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("repos.jsonl")
                .await
                .unwrap();
            let mut writer = tokio::io::BufWriter::new(file);

            let last = app::write_graph_repositories(&mut writer, Vec::new())
                .await
                .unwrap();
            writer.flush().await.unwrap();

            assert!(last.is_none());
            let contents = tokio::fs::read_to_string("repos.jsonl").await.unwrap();
            assert!(contents.is_empty());
        });
    }

    #[test]
    fn tracker_persist_serializes_id() {
        let _dir = TempDirGuard::new().expect("failed to create temp dir");
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            let tracker = id::Tracker::new(0);
            tracker.persist(99).await.unwrap();
            assert_eq!(tracker.current(), 99);

            let from_file = id::load().await.unwrap();
            assert_eq!(from_file, 99);
        });
    }

    fn sample_repo(id: u64, name: &str) -> types::GraphRepository {
        let encoded_id =
            base64::engine::general_purpose::STANDARD.encode(format!("01:Repository{id}"));
        types::GraphRepository {
            id: encoded_id,
            name_with_owner: name.to_string(),
            stargazer_count: 0,
            default_branch_ref: Some(types::GraphRef {
                name: "main".to_string(),
            }),
            languages: types::GraphLanguages {
                nodes: vec![Some(types::GraphLanguage {
                    name: "Rust".to_string(),
                })],
            },
        }
    }
}
