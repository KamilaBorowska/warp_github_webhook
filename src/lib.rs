//! GitHub webhook handler for [`warp`] web framework.

use github_webhook_message_validator::validate;
use serde::de::DeserializeOwned;
use std::fmt::{self, Debug, Formatter};
use warp::reject::Reject;
use warp::{Filter, Rejection};

/// Represents an error in parsing webhook. Can be captured with `recover`.
pub struct Error {
    kind: ErrorKind,
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::UnexpectedAlgorithm => write!(f, "Unexpected algorithm"),
            ErrorKind::InvalidHmacSignature => write!(f, "Invalid HMAC signature"),
            ErrorKind::Hex(e) => write!(f, "{}", e),
            ErrorKind::Serde(e) => write!(f, "{}", e),
        }
    }
}

impl Reject for Error {}

enum ErrorKind {
    UnexpectedAlgorithm,
    InvalidHmacSignature,
    Hex(hex::FromHexError),
    Serde(serde_json::Error),
}

fn err(kind: ErrorKind) -> Error {
    Error { kind }
}

/// Webhook kind.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Kind(&'static str);

impl Kind {
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
}

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
/// use warp_github_webhook::{webhook, Kind};
///
/// #[derive(Deserialize)]
/// struct PushEvent {
///     compare: String,
/// }
///
/// let route = path!("github")
///     .and(webhook(Kind::PUSH, ""))
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
        warp::post()
            .and(warp::header::exact("X-GitHub-Event", kind))
            .and(warp::body::bytes())
            .and_then(|body: bytes::Bytes| async move {
                parse_json(&body).map_err(warp::reject::custom)
            })
            .boxed()
    } else {
        warp::post()
            .and(warp::header("X-Hub-Signature"))
            .and(warp::header::exact("X-GitHub-Event", kind))
            .and(warp::body::bytes())
            .map(move |signature: String, body: bytes::Bytes| {
                let start = "sha1=";
                if !signature.starts_with(start) {
                    return Err(err(ErrorKind::UnexpectedAlgorithm));
                }
                let signature =
                    hex::decode(&signature[start.len()..]).map_err(|e| err(ErrorKind::Hex(e)))?;
                if validate(secret.as_ref().as_bytes(), &signature, &body) {
                    parse_json(&body)
                } else {
                    Err(err(ErrorKind::InvalidHmacSignature))
                }
            })
            .and_then(|result: Result<_, _>| async { result.map_err(warp::reject::custom) })
            .boxed()
    }
}

fn parse_json<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(&bytes).map_err(|e| err(ErrorKind::Serde(e)))
}

#[cfg(test)]
mod test {
    use super::{webhook, Kind};
    use serde_derive::Deserialize;
    use warp::Filter;

    #[derive(Debug, Deserialize)]
    struct PushEvent {
        compare: String,
    }

    #[tokio::test]
    async fn without_secret() {
        let route = webhook(Kind::PUSH, "").map(|PushEvent { compare }| compare);
        let response = warp::test::request()
            .method("POST")
            .header("X-GitHub-Event", "push")
            .body(r#"{"compare": "f"}"#)
            .reply(&route)
            .await;

        assert_eq!(response.body(), &b"f"[..],)
    }

    #[tokio::test]
    async fn with_secret() {
        let route = webhook(Kind::PUSH, "secret").map(|PushEvent { compare }| compare);

        let response = warp::test::request()
            .method("POST")
            .header("X-GitHub-Event", "push")
            .header(
                "X-Hub-Signature",
                "sha1=7c7bc65ac1fce0a1c87fe0229a2bd229a4130bb6",
            )
            .body(r#"{"compare": "f"}"#)
            .reply(&route)
            .await;

        assert_eq!(response.body(), &b"f"[..]);
    }

    #[tokio::test]
    async fn with_wrong_secret() {
        let route = webhook(Kind::PUSH, "secret").map(|PushEvent { compare }| compare);

        let response = warp::test::request()
            .method("POST")
            .header("X-GitHub-Event", "push")
            .header(
                "X-Hub-Signature",
                "sha1=7c7bc65ac1fce0a1c87fe0229a2bd229a4130bb7",
            )
            .body(r#"{"compare": "f"}"#)
            .reply(&route)
            .await;

        assert_eq!(
            response.body(),
            &b"Unhandled rejection: Invalid HMAC signature"[..]
        );
    }

    #[tokio::test]
    async fn wrong_event() {
        let route = webhook(Kind::PUSH, "").map(|PushEvent { compare }| compare);

        assert_eq!(
            &**warp::test::request()
                .method("POST")
                .header("X-GitHub-Event", "pull")
                .body(r#"{"compare": "f"}"#)
                .reply(&route)
                .await
                .body(),
            &br#"Invalid request header "X-GitHub-Event""#[..],
        );
    }

    #[tokio::test]
    async fn missing_header() {
        let route = webhook(Kind::PUSH, "").map(|PushEvent { compare }| compare);

        let response = warp::test::request()
            .method("POST")
            .body(r#"{"compare": "f"}"#)
            .reply(&route)
            .await;

        assert_eq!(
            response.body(),
            &br#"Missing request header "X-GitHub-Event""#[..],
        );
    }

    #[tokio::test]
    async fn invalid_json() {
        let route = webhook(Kind::PUSH, "").map(|PushEvent { compare }| compare);

        let response = warp::test::request()
            .method("POST")
            .header("X-GitHub-Event", "push")
            .body(r#"{"x": "f"}"#)
            .reply(&route)
            .await;

        assert_eq!(
            response.body(),
            &b"Unhandled rejection: missing field `compare` at line 1 column 10"[..],
        );
    }

    #[tokio::test]
    async fn invalid_signed_json() {
        let route = webhook(Kind::PUSH, "secret").map(|PushEvent { compare }| compare);

        let response = warp::test::request()
            .method("POST")
            .header("X-GitHub-Event", "push")
            .header(
                "X-Hub-Signature",
                "sha1=6a8e0e5f7da97721bd89c8276e2f3f6569fdea71",
            )
            .body(r#"{"x": "f"}"#)
            .reply(&route)
            .await;

        assert_eq!(
            response.body(),
            &b"Unhandled rejection: missing field `compare` at line 1 column 10"[..],
        );
    }
}
