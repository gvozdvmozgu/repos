#![warn(unreachable_pub, unused_qualifications)]

const REPOS_PER_BATCH: usize = 100;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use color_eyre::eyre::Context as _;

fn main() -> color_eyre::Result<()> {
    let last_id = Arc::new(AtomicU64::new(id::load()?));
    let token = env::required::<String>("GITHUB_TOKEN")?;

    let my_id = last_id.clone();
    ctrlc::set_handler(move || {
        let id = my_id.load(Ordering::Relaxed);
        let _ = id::save(id);

        std::process::exit(0);
    })
    .unwrap();

    let mut outcome = app::run(&token, last_id.clone());

    if let Err(save_fail) = id::save(last_id.load(Ordering::Relaxed)) {
        outcome = outcome.map_err(|report| report.wrap_err(save_fail));
    }

    outcome.wrap_err("Failed to run")
}

mod app {
    use std::io::Write;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use color_eyre::eyre::Context as _;

    use crate::{REPOS_PER_BATCH, repositories};

    pub(crate) fn run(token: &str, last_id: Arc<AtomicU64>) -> color_eyre::Result<()> {
        let mut json = std::fs::File::options()
            .create(true)
            .append(true)
            .open("repos.jsonl")
            .wrap_err("Failed to open repos.jsonl")?;

        loop {
            let repos = repositories::fetch(token, last_id.load(Ordering::Relaxed))
                .wrap_err("Failed to fetch repositories")?;

            for batch in repos.chunks(REPOS_PER_BATCH) {
                eprintln!("Fetched {} repositories", batch.len());

                let ids = batch
                    .iter()
                    .map(|repo| repo.node_id.as_str())
                    .collect::<Vec<_>>();

                let graph_repos = repositories::info(token, &ids)
                    .wrap_err("Failed to fetch repository info")?
                    .into_iter()
                    .flatten();

                for repo in graph_repos {
                    let (_, _, id) =
                        repositories::parse_node_id(&repo.id).expect("Invalid node_id format");

                    let serialized = serde_json::to_string(&repo).unwrap();
                    json.write_all(serialized.as_bytes())
                        .wrap_err("Failed to write repository info to file")?;
                    json.write_all(b"\n").wrap_err("Failed to write newline")?;

                    last_id.store(id, Ordering::Relaxed);
                }
            }
        }
    }
}

mod id {
    use color_eyre::eyre::Context as _;

    pub(crate) fn load() -> color_eyre::Result<u64> {
        match std::fs::read_to_string("id") {
            Ok(text) => text.parse().wrap_err("Failed to parse ID"),
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
    const GRAPHQL_QUERY_REPOSITORIES: &str = include_str!("../repos.graphql");

    macro_rules! request {
        (get, $token:expr, $path:expr $(, $call:ident ( $($args:tt)* ) )* ) => {{
            let mut req = ureq::get(&format!("{}{}", GITHUB_API, $path));

            req = req
                .header("authorization", &format!("token {}", $token))
                .header("user-agent", "https://github.com/gvozdvmozgu/repos");

            $(
                req = req.$call($($args)*);
            )*
            req
        }};

        (post, $token:expr, $path:expr $(, $call:ident ( $($args:tt)* ) )* ) => {{
            let mut req = ureq::post(&format!("{}{}", GITHUB_API, $path));
            req = req
                .header("authorization", &format!("token {}", $token))
                .header("user-agent", "https://github.com/gvozdvmozgu/repos");
            $(
                req = req.$call($($args)*);
            )*
            req
        }};
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

    fn retry<T>(
        call: impl Fn() -> Result<http::Response<T>, ureq::Error>,
    ) -> Result<http::Response<T>, ureq::Error> {
        let mut wait = Duration::from_secs(10);
        let mut attempts = 0;

        loop {
            match call() {
                Ok(response) => return Ok(response),
                Err(error) if attempts < 5 => {
                    std::thread::sleep(wait);
                    attempts += 1;
                    wait *= 2;

                    eprintln!("Retrying request: {error}\nAttempt {attempts}\nWait time: {wait:?}");
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn fetch(token: &str, last_id: u64) -> color_eyre::Result<Vec<types::Repo>> {
        let mut response = retry(|| {
            let mut buffer = itoa::Buffer::new();
            request!(get, token, "repositories")
                .query("since", buffer.format(last_id))
                .call()
        })?;

        response
            .body_mut()
            .read_json()
            .wrap_err("Failed to read JSON")
    }

    pub(crate) fn info(
        token: &str,
        ids: &[&str],
    ) -> color_eyre::Result<Vec<Option<types::GraphRepository>>> {
        let mut response = retry(|| {
            request!(post, token, "graphql").send_json(
                serde_json::json!({"query": GRAPHQL_QUERY_REPOSITORIES, "variables": {"ids": ids}}),
            )
        })?;

        let response: types::GraphResponse = response
            .body_mut()
            .read_json()
            .wrap_err("Failed to read JSON")?;

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
