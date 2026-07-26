//! Minimal Rust-owned OpenAPI assembly helpers.
//!
//! This crate is intentionally smaller than a framework. Service crates keep
//! owning their axum routers and DTOs; this builder records the matching
//! contract metadata and emits a preview OpenAPI 3.1 document from
//! `schemars::JsonSchema` types.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use schemars::{JsonSchema, generate::SchemaSettings};
use serde_json::{Map, Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    fn as_openapi_key(self) -> &'static str {
        match self {
            Method::Get => "get",
            Method::Post => "post",
            Method::Put => "put",
            Method::Patch => "patch",
            Method::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone)]
struct SchemaComponent {
    name: String,
    schema: Value,
    nested_suffix: &'static str,
}

impl SchemaComponent {
    fn new_for_deserialize<T>(name: &str) -> Self
    where
        T: JsonSchema,
    {
        Self {
            name: name.to_owned(),
            schema: serde_json::to_value(schemars::schema_for!(T))
                .expect("schemars schema should serialize"),
            nested_suffix: "Input",
        }
    }

    fn new_for_serialize<T>(name: &str) -> Self
    where
        T: JsonSchema,
    {
        let generator = SchemaSettings::default().for_serialize().into_generator();
        Self {
            name: name.to_owned(),
            schema: serde_json::to_value(generator.into_root_schema_for::<T>())
                .expect("schemars schema should serialize"),
            nested_suffix: "",
        }
    }

    fn into_normalized_components(self) -> Vec<Self> {
        let mut components = Vec::new();
        collect_schema_components(self.name, self.schema, self.nested_suffix, &mut components);
        components
    }
}

#[derive(Debug, Clone)]
pub struct Operation {
    operation_id: String,
    summary: Option<String>,
    tags: Vec<String>,
    path_params: Vec<String>,
    query_params: Vec<QueryParam>,
    request_body: Option<Value>,
    responses: BTreeMap<u16, Response>,
    schemas: Vec<SchemaComponent>,
}

impl Operation {
    pub fn new(operation_id: impl Into<String>) -> Self {
        Self {
            operation_id: operation_id.into(),
            summary: None,
            tags: Vec::new(),
            path_params: Vec::new(),
            query_params: Vec::new(),
            request_body: None,
            responses: BTreeMap::new(),
            schemas: Vec::new(),
        }
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn path_param(mut self, name: impl Into<String>) -> Self {
        self.path_params.push(name.into());
        self
    }

    pub fn query_param(mut self, name: impl Into<String>, schema: Value) -> Self {
        self.query_params.push(QueryParam {
            name: name.into(),
            schema,
            required: false,
        });
        self
    }

    pub fn required_query_param(mut self, name: impl Into<String>, schema: Value) -> Self {
        self.query_params.push(QueryParam {
            name: name.into(),
            schema,
            required: true,
        });
        self
    }

    pub fn json_request<T>(mut self, component_name: &str) -> Self
    where
        T: JsonSchema,
    {
        self.schemas
            .push(SchemaComponent::new_for_deserialize::<T>(component_name));
        self.request_body = Some(component_ref(component_name));
        self
    }

    pub fn json_response<T>(
        mut self,
        status: u16,
        description: impl Into<String>,
        component_name: &str,
    ) -> Self
    where
        T: JsonSchema,
    {
        self.schemas
            .push(SchemaComponent::new_for_serialize::<T>(component_name));
        self.responses.insert(
            status,
            Response {
                description: description.into(),
                content_type: Some("application/json".to_owned()),
                body_schema: Some(component_ref(component_name)),
                headers: BTreeMap::new(),
            },
        );
        self
    }

    pub fn json_array_response<T>(
        mut self,
        status: u16,
        description: impl Into<String>,
        component_name: &str,
    ) -> Self
    where
        T: JsonSchema,
    {
        self.schemas
            .push(SchemaComponent::new_for_serialize::<T>(component_name));
        self.responses.insert(
            status,
            Response {
                description: description.into(),
                content_type: Some("application/json".to_owned()),
                body_schema: Some(json!({
                    "type": "array",
                    "items": component_ref(component_name),
                })),
                headers: BTreeMap::new(),
            },
        );
        self
    }

    pub fn json_response_schema(
        mut self,
        status: u16,
        description: impl Into<String>,
        schema: Value,
    ) -> Self {
        self.responses.insert(
            status,
            Response {
                description: description.into(),
                content_type: Some("application/json".to_owned()),
                body_schema: Some(schema),
                headers: BTreeMap::new(),
            },
        );
        self
    }

    pub fn text_response(mut self, status: u16, description: impl Into<String>) -> Self {
        self.responses.insert(
            status,
            Response {
                description: description.into(),
                content_type: Some("text/plain".to_owned()),
                body_schema: Some(json!({ "type": "string" })),
                headers: BTreeMap::new(),
            },
        );
        self
    }

    pub fn empty_response(mut self, status: u16, description: impl Into<String>) -> Self {
        self.responses.insert(
            status,
            Response {
                description: description.into(),
                content_type: None,
                body_schema: None,
                headers: BTreeMap::new(),
            },
        );
        self
    }

    pub fn response_header(mut self, status: u16, name: impl Into<String>, schema: Value) -> Self {
        self.responses
            .entry(status)
            .or_insert_with(|| Response {
                description: "OK".to_owned(),
                content_type: None,
                body_schema: None,
                headers: BTreeMap::new(),
            })
            .headers
            .insert(name.into(), schema);
        self
    }

    fn into_openapi(self) -> Value {
        let mut operation = Map::new();
        operation.insert("operationId".into(), Value::String(self.operation_id));
        if let Some(summary) = self.summary {
            operation.insert("summary".into(), Value::String(summary));
        }
        if !self.tags.is_empty() {
            operation.insert(
                "tags".into(),
                Value::Array(self.tags.into_iter().map(Value::String).collect()),
            );
        }
        if !self.path_params.is_empty() || !self.query_params.is_empty() {
            operation.insert(
                "parameters".into(),
                Value::Array(
                    self.path_params
                        .into_iter()
                        .map(|name| {
                            json!({
                                "name": name,
                                "in": "path",
                                "required": true,
                                "schema": { "type": "string" },
                            })
                        })
                        .chain(self.query_params.into_iter().map(|param| {
                            json!({
                                "name": param.name,
                                "in": "query",
                                "required": param.required,
                                "schema": param.schema,
                            })
                        }))
                        .collect(),
                ),
            );
        }
        if let Some(schema) = self.request_body {
            operation.insert(
                "requestBody".into(),
                json!({
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": schema,
                        },
                    },
                }),
            );
        }
        operation.insert(
            "responses".into(),
            Value::Object(
                self.responses
                    .into_iter()
                    .map(|(status, response)| (status.to_string(), response.into_openapi()))
                    .collect(),
            ),
        );
        Value::Object(operation)
    }
}

#[derive(Debug, Clone)]
struct QueryParam {
    name: String,
    schema: Value,
    required: bool,
}

#[derive(Debug, Clone)]
struct Response {
    description: String,
    content_type: Option<String>,
    body_schema: Option<Value>,
    headers: BTreeMap<String, Value>,
}

impl Response {
    fn into_openapi(self) -> Value {
        let mut response = match (self.content_type, self.body_schema) {
            (Some(content_type), Some(schema)) => json!({
                "description": self.description,
                "content": {
                    content_type: {
                        "schema": schema,
                    },
                },
            }),
            _ => json!({
                "description": self.description,
            }),
        };
        if !self.headers.is_empty()
            && let Value::Object(ref mut object) = response
        {
            object.insert(
                "headers".into(),
                Value::Object(
                    self.headers
                        .into_iter()
                        .map(|(name, schema)| (name, json!({ "schema": schema })))
                        .collect(),
                ),
            );
        }
        response
    }
}

#[derive(Debug, Clone)]
pub struct OpenApiBuilder {
    title: String,
    version: String,
    paths: BTreeMap<String, BTreeMap<Method, Operation>>,
    schemas: BTreeMap<String, Value>,
}

impl OpenApiBuilder {
    pub fn new(title: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            version: version.into(),
            paths: BTreeMap::new(),
            schemas: BTreeMap::new(),
        }
    }

    pub fn operation(
        mut self,
        path: impl Into<String>,
        method: Method,
        operation: Operation,
    ) -> Self {
        for component in operation
            .schemas
            .iter()
            .cloned()
            .flat_map(SchemaComponent::into_normalized_components)
        {
            match self.schemas.get(&component.name) {
                Some(existing) => {
                    debug_assert_eq!(existing, &component.schema);
                }
                None => {
                    self.schemas
                        .insert(component.name.clone(), component.schema);
                }
            }
        }
        self.paths
            .entry(path.into())
            .or_default()
            .insert(method, operation);
        self
    }

    pub fn finish(self) -> Value {
        let paths = self
            .paths
            .into_iter()
            .map(|(path, operations)| {
                let mut path_item = Map::new();
                for (method, operation) in operations {
                    path_item.insert(method.as_openapi_key().into(), operation.into_openapi());
                }
                (path, Value::Object(path_item))
            })
            .collect();

        json!({
            "openapi": "3.1.0",
            "info": {
                "title": self.title,
                "version": self.version,
            },
            "paths": Value::Object(paths),
            "components": {
                "schemas": Value::Object(self.schemas.into_iter().collect()),
            },
        })
    }
}

pub fn component_ref(component_name: &str) -> Value {
    json!({
        "$ref": format!("#/components/schemas/{component_name}"),
    })
}

pub fn with_standard_health_routes(builder: OpenApiBuilder) -> OpenApiBuilder {
    builder
        .operation(
            "/healthz",
            Method::Get,
            Operation::new("healthz")
                .tag("health")
                .summary("Liveness probe")
                .text_response(200, "OK"),
        )
        .operation(
            "/readyz",
            Method::Get,
            Operation::new("readyz")
                .tag("health")
                .summary("Readiness probe")
                .text_response(200, "OK")
                .text_response(503, "Service Unavailable"),
        )
}

fn collect_schema_components(
    name: String,
    mut schema: Value,
    nested_suffix: &'static str,
    components: &mut Vec<SchemaComponent>,
) {
    let defs = schema
        .as_object_mut()
        .and_then(|object| {
            object.remove("$schema");
            object
                .entry("title")
                .or_insert_with(|| Value::String(name.clone()));
            object.remove("$defs")
        })
        .and_then(|defs| match defs {
            Value::Object(defs) => Some(defs),
            _ => None,
        });

    rewrite_defs_refs(&mut schema, nested_suffix);
    components.push(SchemaComponent {
        name,
        schema,
        nested_suffix,
    });

    if let Some(defs) = defs {
        for (def_name, def_schema) in defs {
            collect_schema_components(
                format!("{def_name}{nested_suffix}"),
                def_schema,
                nested_suffix,
                components,
            );
        }
    }
}

fn rewrite_defs_refs(value: &mut Value, nested_suffix: &str) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref")
                && let Some(component) = reference.strip_prefix("#/$defs/")
            {
                *reference = format!("#/components/schemas/{component}{nested_suffix}");
            }
            for child in object.values_mut() {
                rewrite_defs_refs(child, nested_suffix);
            }
        }
        Value::Array(items) => {
            for child in items {
                rewrite_defs_refs(child, nested_suffix);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    #[allow(dead_code)]
    #[derive(JsonSchema)]
    struct Widget {
        id: String,
    }

    #[allow(dead_code)]
    #[derive(JsonSchema)]
    struct WidgetList {
        widgets: Vec<Widget>,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Serialize, JsonSchema)]
    struct WireShape {
        always: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        maybe: String,
    }

    #[test]
    fn emits_component_backed_json_response() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/widgets/{id}",
                Method::Get,
                Operation::new("getWidget")
                    .path_param("id")
                    .json_response::<Widget>(200, "Widget", "Widget"),
            )
            .finish();

        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(
            doc["paths"]["/widgets/{id}"]["get"]["parameters"][0]["name"],
            "id"
        );
        assert_eq!(
            doc["paths"]["/widgets/{id}"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["$ref"],
            "#/components/schemas/Widget"
        );
        assert_eq!(doc["components"]["schemas"]["Widget"]["type"], "object");
    }

    #[test]
    fn response_components_use_serialized_wire_shape() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/wire",
                Method::Get,
                Operation::new("getWire").json_response::<WireShape>(200, "Wire", "WireShape"),
            )
            .operation(
                "/wire",
                Method::Post,
                Operation::new("createWire").json_request::<WireShape>("WireShapeRequest"),
            )
            .finish();

        assert_eq!(
            doc["components"]["schemas"]["WireShape"]["required"],
            json!(["always"])
        );
        assert_eq!(
            doc["components"]["schemas"]["WireShapeRequest"]["required"],
            json!(["always", "maybe"])
        );
    }

    #[test]
    fn empty_responses_omit_content() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/widgets/{id}",
                Method::Delete,
                Operation::new("deleteWidget")
                    .path_param("id")
                    .empty_response(204, "No Content"),
            )
            .finish();

        let response = &doc["paths"]["/widgets/{id}"]["delete"]["responses"]["204"];
        assert_eq!(response["description"], "No Content");
        assert_eq!(response.get("content"), None);
    }

    #[test]
    fn text_responses_emit_text_plain_content() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/healthz",
                Method::Get,
                Operation::new("healthz").text_response(200, "OK"),
            )
            .finish();

        let schema =
            &doc["paths"]["/healthz"]["get"]["responses"]["200"]["content"]["text/plain"]["schema"];
        assert_eq!(schema["type"], "string");
    }

    #[test]
    fn emits_query_parameters() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/widgets",
                Method::Get,
                Operation::new("listWidgets")
                    .query_param("page", json!({"type": "integer", "format": "int32"}))
                    .required_query_param("search", json!({"type": "string"}))
                    .json_array_response::<Widget>(200, "Widgets", "Widget"),
            )
            .finish();

        let params = doc["paths"]["/widgets"]["get"]["parameters"]
            .as_array()
            .unwrap();
        assert_eq!(params[0]["name"], "page");
        assert_eq!(params[0]["in"], "query");
        assert_eq!(params[0]["required"], false);
        assert_eq!(params[0]["schema"]["type"], "integer");
        assert_eq!(params[1]["name"], "search");
        assert_eq!(params[1]["required"], true);
        assert_eq!(params[1]["schema"]["type"], "string");
    }

    #[test]
    fn response_headers_are_recorded() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/login",
                Method::Post,
                Operation::new("login")
                    .json_response::<Widget>(200, "Widget", "Widget")
                    .response_header(200, "Set-Cookie", json!({"type": "string"})),
            )
            .finish();

        assert_eq!(
            doc["paths"]["/login"]["post"]["responses"]["200"]["headers"]["Set-Cookie"]["schema"]["type"],
            "string"
        );
    }

    #[test]
    fn array_responses_reference_item_component() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/widgets",
                Method::Get,
                Operation::new("listWidgets")
                    .json_array_response::<Widget>(200, "Widgets", "Widget"),
            )
            .finish();

        let schema = &doc["paths"]["/widgets"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"];
        assert_eq!(schema["type"], "array");
        assert_eq!(schema["items"]["$ref"], "#/components/schemas/Widget");
        assert!(matches!(
            &doc["components"]["schemas"]["Widget"],
            Value::Object(_)
        ));
    }

    #[test]
    fn nested_defs_are_promoted_to_components() {
        let doc = OpenApiBuilder::new("Test API", "0")
            .operation(
                "/widget-list",
                Method::Get,
                Operation::new("getWidgetList").json_response::<WidgetList>(
                    200,
                    "Widget list",
                    "WidgetList",
                ),
            )
            .operation(
                "/widgets/{id}",
                Method::Get,
                Operation::new("getWidget")
                    .path_param("id")
                    .json_response::<Widget>(200, "Widget", "Widget"),
            )
            .finish();

        assert_eq!(
            doc["components"]["schemas"]["WidgetList"]["properties"]["widgets"]["items"]["$ref"],
            "#/components/schemas/Widget"
        );
        assert!(doc["components"]["schemas"]["WidgetList"]["$defs"].is_null());
        assert!(doc["components"]["schemas"]["Widget"]["$schema"].is_null());
        assert_eq!(doc["components"]["schemas"]["Widget"]["title"], "Widget");
    }

    #[test]
    fn standard_health_routes_match_server_core_text_contract() {
        let doc = with_standard_health_routes(OpenApiBuilder::new("Test API", "0")).finish();

        assert_eq!(
            doc["paths"]["/healthz"]["get"]["responses"]["200"]["content"]["text/plain"]["schema"]
                ["type"],
            "string"
        );
        assert_eq!(
            doc["paths"]["/readyz"]["get"]["responses"]["503"]["content"]["text/plain"]["schema"]["type"],
            "string"
        );
    }
}
