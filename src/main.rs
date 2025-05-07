#![warn(unreachable_pub)]

const REPOS_PER_BATCH: usize = 100;

use color_eyre::eyre::Context as _;

fn main() -> color_eyre::Result<()> {
    let mut last_id = id::load()?;
    let mut outcome = run(&mut last_id);

    if let Err(run_error) = id::save(last_id) {
        outcome = outcome.map_err(|report| report.wrap_err(run_error));
    }

    outcome.wrap_err("Failed to run")
}

fn run(last_id: &mut u64) -> color_eyre::Result<()> {
    loop {
        let repos = repositories::fetch(*last_id).wrap_err("Failed to fetch repositories")?;
        for repos in repos.chunks(REPOS_PER_BATCH) {
            let ids = repos.iter().map(|repo| repo.id).collect::<Vec<_>>();
            repositories::info(&ids).wrap_err("Failed to fetch repository info")?;

            *last_id = *ids.last().unwrap();
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
    use color_eyre::eyre::Context as _;

    const GITHUB_REPOSITORIES: &str = "https://api.github.com/repositories";
    const GITHUB_GRAPHQL: &str = "https://api.github.com/graphql";
    const GRAPHQL_QUERY_REPOSITORIES: &str = include_str!("../repos.graphql");

    pub(crate) fn fetch(last_id: u64) -> color_eyre::Result<Vec<crate::types::Repo>> {
        let mut buffer = itoa::Buffer::new();
        let mut response = ureq::get(GITHUB_REPOSITORIES)
            .query("since", buffer.format(last_id))
            .call()?;

        response
            .body_mut()
            .read_json()
            .wrap_err("Failed to read JSON")
    }

    pub(crate) fn info(ids: &[u64]) -> color_eyre::Result<Vec<String>> {
        let _response = ureq::post(GITHUB_GRAPHQL).send_json(
            serde_json::json!({"query": GRAPHQL_QUERY_REPOSITORIES, "variables": ids}),
        )?;

        todo!()
    }
}

mod types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) struct Repo {
        pub id: u64,
        pub node_id: String,
        pub name: String,
        pub full_name: String,
        pub private: bool,
        pub owner: Owner,
        pub html_url: String,
        pub description: Option<String>,
        pub fork: bool,
        pub url: String,
        pub forks_url: String,
        pub keys_url: String,
        pub collaborators_url: String,
        pub teams_url: String,
        pub hooks_url: String,
        pub issue_events_url: String,
        pub events_url: String,
        pub assignees_url: String,
        pub branches_url: String,
        pub tags_url: String,
        pub blobs_url: String,
        pub git_tags_url: String,
        pub git_refs_url: String,
        pub trees_url: String,
        pub statuses_url: String,
        pub languages_url: String,
        pub stargazers_url: String,
        pub contributors_url: String,
        pub subscribers_url: String,
        pub subscription_url: String,
        pub commits_url: String,
        pub git_commits_url: String,
        pub comments_url: String,
        pub issue_comment_url: String,
        pub contents_url: String,
        pub compare_url: String,
        pub merges_url: String,
        pub archive_url: String,
        pub downloads_url: String,
        pub issues_url: String,
        pub pulls_url: String,
        pub milestones_url: String,
        pub notifications_url: String,
        pub labels_url: String,
        pub releases_url: String,
        pub deployments_url: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) struct Owner {
        pub login: String,
        pub id: u64,
        pub node_id: String,
        pub avatar_url: String,
        pub gravatar_id: String,
        pub url: String,
        pub html_url: String,
        pub followers_url: String,
        pub following_url: String,
        pub gists_url: String,
        pub starred_url: String,
        pub subscriptions_url: String,
        pub organizations_url: String,
        pub repos_url: String,
        pub events_url: String,
        pub received_events_url: String,
        #[serde(rename = "type")]
        pub owner_type: String,
        pub user_view_type: String,
        pub site_admin: bool,
    }
}
