//! duckvis-api authorization calls: `authz/check` and `authz/resolve-attachment`.
//!
//! Both are called with the swanlake service-account bearer token and fail
//! closed: a deny returns `false`/`None`, a network error or 5xx maps to
//! `Unavailable` (contract C4). A 401 triggers a single SA-token re-mint and one
//! retry (contract C5).

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{sa, DuckvisAuth, DuckvisError};

/// A resolved project attachment (contract C3 allow path). `secret_config` is
/// the full ATTACH statement and must never be logged.
#[derive(Debug, Clone)]
pub struct ResolvedAttachment {
    pub attachment_id: String,
    pub name: String,
    pub kind: String,
    pub secret_config: String,
}

#[derive(Serialize)]
struct CheckObject<'a> {
    kind: &'a str,
    id: &'a str,
}

#[derive(Serialize)]
struct CheckRequest<'a> {
    subject: &'a str,
    permission: &'a str,
    object: CheckObject<'a>,
}

#[derive(Deserialize)]
struct CheckResponse {
    #[serde(default)]
    allow: bool,
}

#[derive(Serialize)]
struct ResolveRequest<'a> {
    subject: &'a str,
    project_id: &'a str,
    bind_id: &'a str,
}

#[derive(Deserialize)]
struct ResolveResponse {
    #[serde(default)]
    allow: bool,
    attachment_id: Option<String>,
    name: Option<String>,
    kind: Option<String>,
    secret_config: Option<String>,
}

impl DuckvisAuth {
    /// `POST {api}/v1/authz/check` for `Project.view`. Returns the `allow` bit.
    /// Deny → `Ok(false)`; network/5xx → `Err(Unavailable)` (fail closed).
    pub async fn check_project_view(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<bool, DuckvisError> {
        self.check_project(subject, project_id, "Project.view").await
    }

    /// `POST {api}/v1/authz/check` for `Project.mutate_data`, fixed for the
    /// session lifetime. A deny arms attachments read-only; an unavailable
    /// authorization service fails the session bind closed.
    pub async fn check_project_mutate_data(
        &self,
        subject: &str,
        project_id: &str,
    ) -> Result<bool, DuckvisError> {
        self.check_project(subject, project_id, "Project.mutate_data")
            .await
    }

    async fn check_project(
        &self,
        subject: &str,
        project_id: &str,
        permission: &str,
    ) -> Result<bool, DuckvisError> {
        let body = project_check_request(subject, project_id, permission);
        let url = format!("{}/v1/authz/check", self.api_url.trim_end_matches('/'));

        let resp: CheckResponse = self.post_json_with_retry(&url, &body).await?;
        Ok(resp.allow)
    }

    /// `POST {api}/v1/authz/resolve-attachment`. Returns `Some(..)` on allow,
    /// `Ok(None)` on deny; network/5xx → `Err(Unavailable)`.
    pub async fn resolve_attachment(
        &self,
        subject: &str,
        project_id: &str,
        bind_id: &str,
    ) -> Result<Option<ResolvedAttachment>, DuckvisError> {
        let body = resolve_attachment_request(subject, project_id, bind_id);
        let url = format!(
            "{}/v1/authz/resolve-attachment",
            self.api_url.trim_end_matches('/')
        );

        let resp: ResolveResponse = self.post_json_with_retry(&url, &body).await?;
        if !resp.allow {
            return Ok(None);
        }

        match (resp.attachment_id, resp.name, resp.secret_config) {
            (Some(attachment_id), Some(name), Some(secret_config)) => {
                Ok(Some(ResolvedAttachment {
                    attachment_id,
                    name,
                    kind: resp.kind.unwrap_or_else(|| "connection".to_string()),
                    secret_config,
                }))
            }
            _ => {
                // allow:true but missing fields — treat as an upstream contract
                // violation and fail closed (do not leak details).
                warn!("resolve-attachment allow response missing required fields");
                Err(DuckvisError::Unavailable)
            }
        }
    }

    /// POST a JSON body with the SA bearer token; on 401 re-mint the SA token once
    /// and retry. 2xx → parse JSON; 4xx (non-401) → treat as fail-closed deny by
    /// bubbling `Unavailable` only for network/5xx, mapping other client errors to
    /// `Unavailable` as well (they indicate a misconfigured caller, not a user
    /// decision). The authorization *decision* is carried in the 200 body.
    async fn post_json_with_retry<B, R>(&self, url: &str, body: &B) -> Result<R, DuckvisError>
    where
        B: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let token = sa::get_token(
            &self.sa_token,
            &self.client,
            &self.api_url,
            &self.client_id,
            &self.issuer,
            &self.signing_key,
        )
        .await?;

        let resp = self.send_json(url, body, &token).await?;
        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            // Re-mint the SA token once and retry.
            let fresh = sa::force_refresh(
                &self.sa_token,
                &self.client,
                &self.api_url,
                &self.client_id,
                &self.issuer,
                &self.signing_key,
            )
            .await?;
            let retry = self.send_json(url, body, &fresh).await?;
            if !retry.status().is_success() {
                warn!(status = %retry.status(), "authz call failed after SA re-mint");
                return Err(DuckvisError::Unavailable);
            }
            return retry.json::<R>().await.map_err(|e| {
                warn!(error = %e, "authz response parse failed");
                DuckvisError::Unavailable
            });
        }

        if !status.is_success() {
            warn!(status = %status, "authz call non-success status");
            return Err(DuckvisError::Unavailable);
        }

        resp.json::<R>().await.map_err(|e| {
            warn!(error = %e, "authz response parse failed");
            DuckvisError::Unavailable
        })
    }

    async fn send_json<B: Serialize>(
        &self,
        url: &str,
        body: &B,
        token: &str,
    ) -> Result<reqwest::Response, DuckvisError> {
        self.client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "authz request send failed");
                DuckvisError::Unavailable
            })
    }
}

fn project_check_request<'a>(
    subject: &'a str,
    project_id: &'a str,
    permission: &'a str,
) -> CheckRequest<'a> {
    CheckRequest {
        subject,
        permission,
        object: CheckObject {
            kind: "project",
            id: project_id,
        },
    }
}

fn resolve_attachment_request<'a>(
    subject: &'a str,
    project_id: &'a str,
    bind_id: &'a str,
) -> ResolveRequest<'a> {
    ResolveRequest {
        subject,
        project_id,
        bind_id,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn project_view_check_matches_duckvis_api_contract() -> Result<(), serde_json::Error> {
        let request = project_check_request("subject-1", "project-1", "Project.view");

        assert_eq!(
            serde_json::to_value(request)?,
            json!({
                "subject": "subject-1",
                "permission": "Project.view",
                "object": { "kind": "project", "id": "project-1" }
            })
        );
        Ok(())
    }

    #[test]
    fn project_mutate_data_check_matches_duckvis_api_contract() -> Result<(), serde_json::Error> {
        let request = project_check_request("subject-1", "project-1", "Project.mutate_data");

        assert_eq!(
            serde_json::to_value(request)?,
            json!({
                "subject": "subject-1",
                "permission": "Project.mutate_data",
                "object": { "kind": "project", "id": "project-1" }
            })
        );
        Ok(())
    }

    #[test]
    fn attachment_resolution_matches_duckvis_api_contract() -> Result<(), serde_json::Error> {
        let request = resolve_attachment_request("subject-1", "project-1", "binding-1");

        assert_eq!(
            serde_json::to_value(request)?,
            json!({
                "subject": "subject-1",
                "project_id": "project-1",
                "bind_id": "binding-1"
            })
        );
        Ok(())
    }
}
