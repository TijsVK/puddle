// SPDX-License-Identifier: GPL-3.0-or-later
//! The `OpenAPI` 3.1 contract (ADR 0004), generated from the routes and the [`crate::wire`]
//! types. Committed as `crates/puddle-api/openapi/openapi.json`, with the TypeScript types
//! generated from it; a test and the `openapi` gate fail when either is stale.

use utoipa::OpenApi as _;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityRequirement, SecurityScheme};
use utoipa::openapi::{ContentBuilder, OpenApi, Ref, RefOr, Response, ResponseBuilder};
use utoipa_axum::router::OpenApiRouter;

use crate::routes::{AppState, api_router, slow_router};

/// The contract's version. Bump the minor version for additive changes and the major version
/// for anything a generated client would break on.
pub const API_VERSION: &str = "0.8.0";

/// The security scheme's name in the spec.
const BEARER: &str = "bearer";

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "puddle",
        description = "puddle's local API: pending requests, rules, audit, settings, consents and \
                       the event stream. Listens on 127.0.0.1 only. Every request needs \
                       `Authorization: Bearer <token>` (from the connection file), a `Host` of \
                       `127.0.0.1:<port>` or `localhost:<port>`, and no foreign `Origin`."
    ),
    components(schemas(
        puddle_types::Event,
        crate::events::Lagged,
        crate::error::ApiErrorBody,
        crate::error::ErrorCode,
        crate::wire::ConsentKind,
        crate::wire::AuditType,
        crate::wire::AuditOutcome,
        crate::wire::ConnectionOrigin,
        puddle_types::WorkspaceName
    )),
    tags(
        (name = "service", description = "Who is answering"),
        (name = "events", description = "The server-sent event stream"),
        (name = "pending", description = "Connections waiting for a decision"),
        (name = "rules", description = "Allow and deny rules"),
        (name = "audit", description = "The audit log"),
        (name = "settings", description = "Global and per-workspace settings"),
        (name = "consents", description = "What the user agreed to"),
        (name = "doctor", description = "The system check: what this computer needs to run workspaces, and the fix for what is missing"),
        (name = "first-run", description = "Whether the first-run flow has been through"),
        (name = "network", description = "How puddle reaches the internet: proxy, sign-in, company roots"),
        (name = "identities", description = "Git identities (author and credentials) and each workspace's identities, repository table and push and pull switches"),
        (name = "workspaces", description = "Workspaces: repository checkouts with their own disk and sandbox"),
        (name = "environment", description = "Environment variables and secrets, global and per workspace; a secret's value is write-only")
    )
)]
struct ApiDoc;

/// The spec.
#[must_use]
pub fn openapi() -> OpenApi {
    let mut doc = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .merge(api_router())
        .merge(slow_router())
        .into_openapi();
    API_VERSION.clone_into(&mut doc.info.version);
    doc.components
        .get_or_insert_with(Default::default)
        .add_security_scheme(
            BEARER,
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
    doc.security = Some(vec![SecurityRequirement::new(BEARER, Vec::<String>::new())]);
    add_guard_responses(&mut doc);
    doc
}

/// The spec as pretty-printed JSON with a trailing newline: the committed file's exact bytes.
#[must_use]
pub fn openapi_json() -> String {
    let mut json = openapi()
        .to_pretty_json()
        .unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"));
    json.push('\n');
    json
}

fn error_response(description: &str) -> RefOr<Response> {
    RefOr::T(
        ResponseBuilder::new()
            .description(description)
            .content(
                "application/json",
                ContentBuilder::new()
                    .schema(Some(Ref::from_schema_name("ApiErrorBody")))
                    .build(),
            )
            .build(),
    )
}

/// The guard's refusals and the internal error apply to every operation; listing them once here
/// keeps the handlers' annotations to what is specific to them.
fn add_guard_responses(doc: &mut OpenApi) {
    let common = [
        ("401", "missing or wrong bearer token"),
        ("403", "forbidden origin"),
        ("421", "Host is not the API's own address"),
        ("500", "puddle failed; see its log"),
    ];
    for item in doc.paths.paths.values_mut() {
        let operations = [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.patch,
        ];
        for operation in operations.into_iter().flatten() {
            for (status, description) in common {
                operation
                    .responses
                    .responses
                    .entry(status.to_owned())
                    .or_insert_with(|| error_response(description));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;

    fn spec() -> Value {
        serde_json::from_str(&openapi_json()).unwrap()
    }

    #[test]
    fn spec_is_openapi_3_1_with_bearer_security() {
        let s = spec();
        assert_eq!(s["openapi"], "3.1.0");
        assert_eq!(s["info"]["version"], API_VERSION);
        assert_eq!(s["security"], serde_json::json!([{ "bearer": [] }]));
        assert_eq!(
            s["components"]["securitySchemes"]["bearer"],
            serde_json::json!({ "type": "http", "scheme": "bearer" })
        );
    }

    #[test]
    fn every_operation_documents_the_guard_refusals() {
        let s = spec();
        let mut count = 0;
        for (path, item) in s["paths"].as_object().unwrap() {
            assert!(path.starts_with("/api/"), "{path}");
            for (method, op) in item.as_object().unwrap() {
                count += 1;
                for status in ["401", "403", "421", "500"] {
                    assert!(
                        op["responses"].get(status).is_some(),
                        "{method} {path} lacks {status}"
                    );
                }
                assert!(op["tags"].as_array().is_some_and(|t| !t.is_empty()));
            }
        }
        assert_eq!(count, 63, "operations in the spec");
    }

    /// ADR 0002: responses always carry every field (`null`, never absent), so the generated
    /// TypeScript has `T | null`, not `T?`. Request bodies (`*Request`) may leave fields out.
    #[test]
    fn response_schemas_require_every_property() {
        let s = spec();
        let schemas = s["components"]["schemas"].as_object().unwrap();
        for (name, schema) in schemas {
            if name.ends_with("Request")
                || name == "SettingsLayer"
                || name == "LocalToggles"
                || name == "UiPrefs"
            {
                continue;
            }
            check_required(name, schema);
        }
        // Shared by requests and responses: required in the spec (responses always send them),
        // tolerated when absent in a request.
        for name in ["SettingsLayer", "LocalToggles", "VsCodeServer", "UiPrefs"] {
            check_required(name, &schemas[name]);
        }
    }

    fn check_required(name: &str, schema: &Value) {
        if let Some(variants) = schema.get("oneOf").and_then(Value::as_array) {
            for v in variants {
                check_required(name, v);
            }
            return;
        }
        let Some(props) = schema.get("properties").and_then(Value::as_object) else {
            return;
        };
        let required: BTreeSet<&str> = schema["required"]
            .as_array()
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for prop in props.keys() {
            assert!(
                required.contains(prop.as_str()),
                "{name}.{prop} is not required"
            );
        }
    }

    #[test]
    fn every_ref_resolves() {
        fn refs(v: &Value, out: &mut Vec<String>) {
            match v {
                Value::Object(map) => {
                    if let Some(Value::String(r)) = map.get("$ref") {
                        out.push(r.clone());
                    }
                    map.values().for_each(|c| refs(c, out));
                }
                Value::Array(items) => items.iter().for_each(|c| refs(c, out)),
                _ => {}
            }
        }
        let s = spec();
        let mut all = Vec::new();
        refs(&s, &mut all);
        assert!(all.len() > 10, "{all:?}");
        for r in all {
            let name = r
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("{r}"));
            assert!(
                s["components"]["schemas"].get(name).is_some(),
                "{r} does not resolve"
            );
        }
    }

    #[test]
    fn spec_names_no_flatten_or_untagged_shapes() {
        // `allOf` would come from #[serde(flatten)]; `anyOf` from untagged enums (ADR 0002/0004).
        let text = openapi_json();
        assert!(!text.contains("\"allOf\""));
        assert!(!text.contains("\"anyOf\""));
    }

    #[test]
    fn event_union_and_lagged_are_components() {
        let s = spec();
        let schemas = &s["components"]["schemas"];
        assert!(schemas["Event"]["oneOf"].is_array());
        assert!(schemas["Lagged"]["properties"]["missed"].is_object());
        assert!(schemas["ApiErrorBody"].is_object());
        assert!(
            s["paths"]["/api/events"]["get"]["responses"]["200"]["content"]["text/event-stream"]
                .is_object()
        );
    }

    #[test]
    fn committed_spec_is_current() {
        let committed = include_str!("../openapi/openapi.json");
        assert!(
            committed == openapi_json(),
            "crates/puddle-api/openapi/openapi.json is stale: run `cargo xtask openapi`"
        );
    }
}
