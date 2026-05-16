//! OpenAPI 3.1 spec endpoint (W7).
//!
//! Serves the spec/openapi.yaml file at multiple endpoints:
//!   - GET /openapi.yaml — raw YAML
//!   - GET /openapi.json — converted to JSON
//!   - GET /docs        — Swagger UI (CDN-hosted, no extra deps)
//!   - GET /redoc       — Redoc UI (CDN-hosted)

use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};

const OPENAPI_YAML: &str = include_str!("../../spec/openapi.yaml");

pub async fn openapi_yaml() -> impl IntoResponse {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-yaml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        OPENAPI_YAML,
    )
}

pub async fn openapi_json() -> Response {
    match serde_yaml::from_str::<serde_json::Value>(OPENAPI_YAML) {
        Ok(json) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            axum::Json(json),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to convert YAML→JSON: {}", e),
        ).into_response(),
    }
}

pub async fn docs() -> Html<&'static str> {
    Html(SWAGGER_HTML)
}

pub async fn redoc() -> Html<&'static str> {
    Html(REDOC_HTML)
}

const SWAGGER_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>JECP API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  <style>
    body { margin: 0; padding: 0; }
    .topbar { display: none; }
  </style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  window.onload = () => {
    window.ui = SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: "#swagger-ui",
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      layout: "BaseLayout",
    });
  };
</script>
</body>
</html>
"##;

const REDOC_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>JECP API Reference</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>body { margin: 0; padding: 0; }</style>
</head>
<body>
<redoc spec-url="/openapi.json"></redoc>
<script src="https://cdn.redocly.com/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>
"##;
