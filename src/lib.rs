//! GitHub webhook handler for [`warp`] web framework.

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use sha1::Sha1;
use std::fmt::Debug;
use warp::body::FullBody;
use warp::{Buf, Filter, Rejection};

/// Webhook kind.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Kind(&'static str);

pub const CHECK_RUN: Kind = Kind("check_run");
pub const CHECK_SUITE: Kind = Kind("check_suite");
pub const COMMIT_COMMENT: Kind = Kind("commit_comment");
pub const CREATE: Kind = Kind("create");
pub const DELETE: Kind = Kind("delete");
pub const DEPLOYMENT: Kind = Kind("deployment");
pub const DEPLOYMENT_STATUS: Kind = Kind("deployment_status");
pub const FORK: Kind = Kind("fork");
pub const GITHUB_APP_AUTHORIZATION: Kind = Kind("github_app_authorization");
pub const GOLLUM: Kind = Kind("gollum");
pub const INSTALLATION: Kind = Kind("installation");
pub const INSTALLATION_REPOSITORIES: Kind = Kind("installation_repositories");
pub const ISSUE_COMMENT: Kind = Kind("issue_comment");
pub const ISSUES: Kind = Kind("issues");
pub const LABEL: Kind = Kind("label");
pub const MARKETPLACE_PURCHASE: Kind = Kind("marketplace_purchase");
pub const MEMBER: Kind = Kind("member");
pub const MEMBERSHIP: Kind = Kind("membership");
pub const MILESTONE: Kind = Kind("milestone");
pub const ORGANIZATION: Kind = Kind("organization");
pub const ORG_BLOCK: Kind = Kind("org_block");
pub const PAGE_BUILD: Kind = Kind("page_build");
pub const PROJECT_CARD: Kind = Kind("project_card");
pub const PROJECT_COLUMN: Kind = Kind("project_column");
pub const PROJECT: Kind = Kind("project");
pub const PUBLIC: Kind = Kind("public");
pub const PULL_REQUEST_REVIEW_COMMENT: Kind = Kind("pull_request_review_comment");
pub const PULL_REQUEST_REVIEW: Kind = Kind("pull_request_review");
pub const PULL_REQUEST: Kind = Kind("pull_request");
pub const PUSH: Kind = Kind("push");
pub const REPOSITORY: Kind = Kind("repository");
pub const REPOSITORY_IMPORT: Kind = Kind("repository_import");
pub const REPOSITORY_VULNERABILITY_ALERT: Kind = Kind("repository_vulnerability_alert");
pub const RELEASE: Kind = Kind("release");
pub const SECURITY_ADVISORY: Kind = Kind("security_advisory");
pub const STATUS: Kind = Kind("status");
pub const TEAM: Kind = Kind("team");
pub const TEAM_ADD: Kind = Kind("team_add");
pub const WATCH: Kind = Kind("watch");

/// Creates a GitHub webhook responder.
///
/// The generic `T` parameter points to a deserializable structure. This
/// crate doesn't provide its own structures, you are intended to write down
/// your own. The reason for that is that this allows skipping parsing
/// unnecessary data.
///
/// # Examples
///
/// ```
/// use serde_derive::Deserialize;
/// use warp::{path, Filter};
/// use warp_github_webhook::{webhook, PUSH};
///
/// #[derive(Deserialize)]
/// struct PushEvent {
///     compare: String,
/// }
///
/// let route = path!("github")
///     .and(webhook(PUSH, ""))
///     .map(|PushEvent { compare }| compare);
/// ```
pub fn webhook<T>(
    Kind(kind): Kind,
    secret: impl AsRef<str> + Clone + Send + Sync + 'static,
) -> impl Clone + Debug + Filter<Extract = (T,), Error = Rejection>
where
    T: 'static + DeserializeOwned + Send,
{
    if secret.as_ref().is_empty() {
        warp::post2()
            .and(warp::header::exact("X-GitHub-Event", kind))
            .and(warp::body::json())
            .boxed()
    } else {
        warp::post2()
            .and(warp::header("X-Hub-Signature"))
            .and(warp::header::exact("X-GitHub-Event", kind))
            .and(warp::body::concat())
            .and_then(move |signature: String, body: FullBody| {
                let start = "sha1=";
                if !signature.starts_with(start) {
                    return Err(warp::reject::custom("Unexpected algorithm"));
                }
                let signature = hex::decode(&signature[start.len()..])
                    .map_err(|_| warp::reject::custom("Undecodable hex string"))?;
                let json: Vec<u8> = body.collect();
                let mut mac = Hmac::<Sha1>::new_varkey(secret.as_ref().as_bytes()).unwrap();
                mac.input(&json);
                mac.verify(&signature)
                    .map_err(|_| warp::reject::custom("Invalid HMAC signature"))?;
                serde_json::from_slice(&json)
                    .map_err(|_| warp::reject::custom("Undeserializable JSON"))
            })
            .boxed()
    }
}

#[cfg(test)]
mod test {
    use super::{webhook, PUSH};
    use serde_derive::Deserialize;
    use warp::Filter;

    #[test]
    fn without_secret() {
        #[derive(Deserialize)]
        struct PushEvent {
            compare: String,
        }

        let route = webhook(PUSH, "").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .header("X-GitHub-Event", "push")
                .body(r#"{"compare": "f"}"#)
                .reply(&route)
                .body(),
            b"f",
        )
    }

    #[test]
    fn with_secret() {
        #[derive(Deserialize)]
        struct PushEvent {
            compare: String,
        }

        let route = webhook(PUSH, "secret").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .header("X-GitHub-Event", "push")
                .header(
                    "X-Hub-Signature",
                    "sha1=7c7bc65ac1fce0a1c87fe0229a2bd229a4130bb6"
                )
                .body(r#"{"compare": "f"}"#)
                .reply(&route)
                .body(),
            b"f",
        )
    }

    #[test]
    fn with_wrong_secret() {
        #[derive(Deserialize)]
        struct PushEvent {
            compare: String,
        }

        let route = webhook(PUSH, "secret").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .header("X-GitHub-Event", "push")
                .header(
                    "X-Hub-Signature",
                    "sha1=7c7bc65ac1fce0a1c87fe0229a2bd229a4130bb7"
                )
                .body(r#"{"compare": "f"}"#)
                .reply(&route)
                .body(),
            &b"Unhandled rejection: Invalid HMAC signature"[..],
        )
    }

    #[test]
    fn wrong_event() {
        #[derive(Deserialize)]
        struct PushEvent {
            compare: String,
        }

        let route = webhook(PUSH, "").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .header("X-GitHub-Event", "pull")
                .body(r#"{"compare": "f"}"#)
                .reply(&route)
                .body(),
            &b"Invalid request header 'X-GitHub-Event'"[..],
        );
    }

    #[test]
    fn missing_header() {
        #[derive(Deserialize)]
        struct PushEvent {
            compare: String,
        }

        let route = webhook(PUSH, "").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .body(r#"{"compare": "f"}"#)
                .reply(&route)
                .body(),
            &b"Missing request header 'X-GitHub-Event'"[..],
        );
    }

    #[test]
    fn invalid_json() {
        #[derive(Deserialize)]
        struct PushEvent {
            compare: String,
        }

        let route = webhook(PUSH, "").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .header("X-GitHub-Event", "push")
                .body(r#"{"x": "f"}"#)
                .reply(&route)
                .body(),
            &b"Request body deserialize error: missing field `compare` at line 1 column 10"[..],
        );
    }
}
