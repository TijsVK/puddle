// SPDX-License-Identifier: GPL-3.0-or-later
//! The `Authorization` value a Git host takes for a token.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use puddle_proxy::SecretValue;

/// The user name GitHub documents for token authentication over HTTPS; the host looks at the
/// token only.
const TOKEN_USER: &str = "x-access-token";

/// What `token` goes out as to the Git host `credential_host`.
///
/// Azure DevOps takes a personal access token as the password of an empty user name, and an Entra
/// access token (a JWT, what Git Credential Manager signs in with) as a bearer token. Every other
/// host gets HTTP Basic with `x-access-token` as the user name, which GitHub, GitLab and Gitea
/// accept for personal, OAuth and fine-grained tokens.
pub(crate) fn authorization(credential_host: &str, token: &str) -> SecretValue {
    if credential_host == "dev.azure.com" {
        if looks_like_jwt(token) {
            return SecretValue::new(format!("Bearer {token}"));
        }
        return SecretValue::new(format!("Basic {}", STANDARD.encode(format!(":{token}"))));
    }
    SecretValue::new(format!(
        "Basic {}",
        STANDARD.encode(format!("{TOKEN_USER}:{token}"))
    ))
}

/// Three dot-separated parts, the first the base64url of a JSON header (`{"`).
fn looks_like_jwt(token: &str) -> bool {
    token.starts_with("eyJ") && token.split('.').count() == 3
}

#[cfg(test)]
mod tests {
    use puddle_proxy::InjectedHeader;

    use super::*;

    fn text(value: &SecretValue, expected: &str) -> bool {
        InjectedHeader::new("authorization", value.clone())
            .unwrap()
            .value_is(expected)
    }

    #[test]
    fn github_and_other_hosts_get_basic_with_the_token_user() {
        let value = authorization("github.com", "ghp_abc");
        let want = format!("Basic {}", STANDARD.encode("x-access-token:ghp_abc"));
        assert!(text(&value, &want));
        assert!(text(
            &authorization("git.example", "t"),
            &format!("Basic {}", STANDARD.encode("x-access-token:t"))
        ));
    }

    #[test]
    fn azure_devops_gets_a_pat_as_the_password_and_an_entra_token_as_a_bearer() {
        let pat = authorization("dev.azure.com", "abc123");
        assert!(text(&pat, &format!("Basic {}", STANDARD.encode(":abc123"))));
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln";
        assert!(text(
            &authorization("dev.azure.com", jwt),
            &format!("Bearer {jwt}")
        ));
        // Two dots are not enough, nor is a JWT-looking token on another host.
        assert!(text(
            &authorization("dev.azure.com", "eyJabc.def"),
            &format!("Basic {}", STANDARD.encode(":eyJabc.def"))
        ));
        assert!(text(
            &authorization("github.com", jwt),
            &format!("Basic {}", STANDARD.encode(format!("x-access-token:{jwt}")))
        ));
    }
}
