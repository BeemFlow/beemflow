//! Procedural macros for BeemFlow core operations
//!
//! Provides `#[operation]` and `#[operation_group]` macros that automatically:
//! - Generate operation metadata
//! - Register operations for CLI/HTTP/MCP interfaces
//! - Eliminate magic strings and duplication

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, ItemMod, ItemStruct, LitStr, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

/// Parse attribute arguments for operation_group
struct OperationGroupArgs {
    group_name: Ident,
}

impl Parse for OperationGroupArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let group_name: Ident = input.parse()?;
        Ok(OperationGroupArgs { group_name })
    }
}

/// Attribute macro for operation groups
///
/// Usage: #[operation_group(flows)]
#[proc_macro_attribute]
pub fn operation_group(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as OperationGroupArgs);
    let input = parse_macro_input!(item as ItemMod);

    let group_name = args.group_name.to_string();
    let mod_name = &input.ident;
    let vis = &input.vis;

    // Extract module content
    let (_brace, items) = match input.content {
        Some((brace, items)) => (brace, items),
        None => {
            return syn::Error::new_spanned(input, "Module must have content")
                .to_compile_error()
                .into();
        }
    };

    // Find all struct items that are actual operations (have a 'deps' field)
    let operation_structs: Vec<&Ident> = items
        .iter()
        .filter_map(|item| {
            if let syn::Item::Struct(s) = item {
                // Check if this struct has a 'deps' field
                let has_deps_field = if let syn::Fields::Named(fields) = &s.fields {
                    fields
                        .named
                        .iter()
                        .any(|f| f.ident.as_ref().map(|i| i == "deps").unwrap_or(false))
                } else {
                    false
                };

                if has_deps_field { Some(&s.ident) } else { None }
            } else {
                None
            }
        })
        .collect();

    // Generate registration calls for all structs
    let registration_calls = operation_structs.iter().map(|struct_name| {
        quote! {
            registry.register(
                #struct_name::new(deps.clone()),
                #struct_name::OPERATION_NAME,
            );
        }
    });

    // Generate HTTP route registration function
    let http_route_calls = operation_structs.iter().map(|struct_name| {
        quote! {
            router = router.merge(#struct_name::http_route(deps.clone()));
        }
    });

    // Generate MCP tool registration function
    let mcp_tool_calls = operation_structs.iter().map(|struct_name| {
        quote! {
            {
                let metadata = #struct_name::metadata();

                // Filter out CLI-only fields from schema for MCP
                let filtered_schema = filter_cli_only_fields(&metadata.schema);

                // Determine if tool is read-only based on HTTP method
                let is_read_only = matches!(metadata.http_method, Some("GET"));

                let mut tool = rmcp::model::Tool::new(
                    std::borrow::Cow::Owned(format!("beemflow_{}", #struct_name::OPERATION_NAME)),
                    std::borrow::Cow::Owned(#struct_name::DESCRIPTION.to_string()),
                    std::sync::Arc::new(filtered_schema),
                );

                // Add annotations with read_only_hint
                tool.annotations = Some(
                    rmcp::model::ToolAnnotations::new().read_only(is_read_only)
                );

                tools.push(tool);
            }
        }
    });

    // Pass through the module with added metadata and auto-registration
    let expanded = quote! {
        #vis mod #mod_name {
            pub const GROUP_NAME: &str = #group_name;

            #(#items)*

            /// Auto-generated function to register all operations in this group
            pub fn register_all(
                registry: &mut super::super::OperationRegistry,
                deps: std::sync::Arc<super::Dependencies>,
            ) {
                #(#registration_calls)*
            }

            /// Auto-generated function to register HTTP routes for all operations in this group
            pub fn register_http_routes(deps: std::sync::Arc<super::Dependencies>) -> axum::Router {
                let mut router = axum::Router::new();
                #(#http_route_calls)*
                router
            }

            /// Filter out CLI-only fields from JSON schema for MCP
            /// Removes field named "file" which is CLI-only convention
            fn filter_cli_only_fields(schema: &serde_json::Map<String, serde_json::Value>) -> serde_json::Map<String, serde_json::Value> {
                let mut filtered = schema.clone();

                // Filter properties if they exist
                // Remove "file" field which is our CLI-only convention
                if let Some(serde_json::Value::Object(props)) = filtered.get_mut("properties") {
                    props.remove("file");
                }

                // Also remove "file" from required array if present
                if let Some(serde_json::Value::Array(required)) = filtered.get_mut("required") {
                    required.retain(|v| v.as_str() != Some("file"));
                }

                filtered
            }

            /// Auto-generated function to register MCP tools for all operations in this group
            pub fn register_mcp_tools(deps: std::sync::Arc<super::Dependencies>) -> Vec<rmcp::model::Tool> {
                let mut tools = Vec::new();
                #(#mcp_tool_calls)*
                tools
            }
        }
    };

    TokenStream::from(expanded)
}

/// Parse attribute arguments for operation
struct OperationArgs {
    name: Option<String>,
    http: Option<String>,
    cli: Option<String>,
    description: Option<String>,
    group: Option<String>,
    input: Option<Ident>,
}

impl Parse for OperationArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut name = None;
        let mut http = None;
        let mut cli = None;
        let mut description = None;
        let mut group = None;
        let mut input_type = None;

        while !input.is_empty() {
            let ident: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match ident.to_string().as_str() {
                "input" => {
                    // Parse identifier for input type
                    let type_ident: Ident = input.parse()?;
                    input_type = Some(type_ident);
                }
                _ => {
                    let value: LitStr = input.parse()?;
                    match ident.to_string().as_str() {
                        "name" => name = Some(value.value()),
                        "http" => http = Some(value.value()),
                        "cli" => cli = Some(value.value()),
                        "description" => description = Some(value.value()),
                        "group" => group = Some(value.value()),
                        _ => return Err(syn::Error::new_spanned(ident, "Unknown attribute")),
                    }
                }
            }

            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(OperationArgs {
            name,
            http,
            cli,
            description,
            group,
            input: input_type,
        })
    }
}

/// Convert PascalCase to snake_case
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();

    for ch in s.chars() {
        if ch.is_uppercase() {
            if !result.is_empty() {
                result.push('_');
            }
            // Safe: to_lowercase() always returns at least one character
            if let Some(lowercase) = ch.to_lowercase().next() {
                result.push(lowercase);
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Parse HTTP method and path from string like "GET /flows/{name}"
fn parse_http_route(http: &str) -> (String, String) {
    let parts: Vec<&str> = http.splitn(2, ' ').collect();
    match (parts.first(), parts.get(1)) {
        (Some(&method), Some(&path)) => (method.to_string(), path.to_string()),
        _ => ("GET".to_string(), http.to_string()),
    }
}

/// Extract path parameters from a path template like "/flows/{name}/runs/{run_id}"
/// Returns vec of parameter names like ["name", "run_id"]
fn extract_path_params(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                Some(segment[1..segment.len() - 1].to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Generate HTTP route method for an operation
fn generate_http_route_method(
    http_method: &str,
    http_path: &str,
    input_type: &Option<Ident>,
) -> proc_macro2::TokenStream {
    use proc_macro2::Span;

    let path_params = extract_path_params(http_path);
    let method_lower = http_method.to_lowercase();
    let method_ident = Ident::new(&method_lower, Span::call_site());

    // Generate axum extractor and input construction
    // Strategy: Use JSON body for POST/PUT/PATCH with path params merged in
    let (extractors, input_construction) = if let Some(input_ty) = input_type {
        if path_params.is_empty() {
            // No path params - simple case
            if http_method == "GET" || http_method == "DELETE" {
                // For GET/DELETE, use Query params
                (
                    quote! { axum::extract::Query(input): axum::extract::Query<#input_ty> },
                    quote! { input },
                )
            } else {
                // For POST/PUT/PATCH, use JSON body
                (
                    quote! { axum::extract::Json(input): axum::extract::Json<#input_ty> },
                    quote! { input },
                )
            }
        } else if path_params.len() == 1 && (http_method == "GET" || http_method == "DELETE") {
            // Single path param with GET/DELETE - construct input from path param only
            #[allow(clippy::indexing_slicing)] // Safe: checked path_params.len() == 1 above
            let param = &path_params[0];
            let param_ident = Ident::new(param, Span::call_site());
            (
                quote! {
                    axum::extract::Path(#param_ident): axum::extract::Path<String>
                },
                quote! {
                    #input_ty { #param_ident }
                },
            )
        } else {
            // Path params with POST/PUT/PATCH - merge path params with JSON body
            // This handles cases like POST /flows/{name}/rollback with body containing other fields
            let param_idents: Vec<_> = path_params
                .iter()
                .map(|p| Ident::new(p, Span::call_site()))
                .collect();

            let extractor = if param_idents.len() == 1 {
                #[allow(clippy::indexing_slicing)] // Safe: checked param_idents.len() == 1
                let param = &param_idents[0];
                quote! {
                    axum::extract::Path(#param): axum::extract::Path<String>,
                    axum::extract::Json(mut body): axum::extract::Json<serde_json::Value>
                }
            } else {
                let param_types = vec![quote! { String }; path_params.len()];
                quote! {
                    axum::extract::Path((#(#param_idents),*)): axum::extract::Path<(#(#param_types),*)>,
                    axum::extract::Json(mut body): axum::extract::Json<serde_json::Value>
                }
            };

            // Merge path params into body JSON
            let merge_params = path_params.iter().map(|p| {
                let param_ident = Ident::new(p, Span::call_site());
                quote! {
                    if let Some(obj) = body.as_object_mut() {
                        obj.insert(#p.to_string(), serde_json::json!(#param_ident));
                    }
                }
            });

            (
                extractor,
                quote! {
                    {
                        #(#merge_params)*
                        serde_json::from_value::<#input_ty>(body)
                            .map_err(|e| crate::http::AppError::from(
                                crate::BeemFlowError::validation(format!("Invalid input: {}", e))
                            ))?
                    }
                },
            )
        }
    } else {
        // No input type
        (quote! {}, quote! { () })
    };

    // Generate handler parameters with Extension extractor for RequestContext
    // Extension<T> extracts per-request state inserted by middleware
    // HTTP API routes are protected by auth middleware, so RequestContext is always present
    let handler_params = if !matches!(extractors.to_string().as_str(), "") {
        quote! {
            axum::extract::Extension(req_ctx): axum::extract::Extension<crate::auth::RequestContext>,
            #extractors
        }
    } else {
        quote! {
            axum::extract::Extension(req_ctx): axum::extract::Extension<crate::auth::RequestContext>
        }
    };

    quote! {
        /// Auto-generated HTTP route registration for this operation
        pub fn http_route(deps: std::sync::Arc<super::Dependencies>) -> axum::Router {
            axum::Router::new().route(
                Self::HTTP_PATH.unwrap(),
                axum::routing::#method_ident({
                    move |#handler_params| async move {
                        let op = Self::new(deps.clone());

                        // Construct input (may fail with validation errors)
                        let input = #input_construction;

                        // Execute with RequestContext in task-local storage
                        // This makes the context available to the operation via REQUEST_CONTEXT.try_with()
                        crate::core::REQUEST_CONTEXT.scope(req_ctx, async move {
                            op.execute(input).await
                        })
                        .await
                        .map(|output| axum::Json(output))
                        .map_err(|e| crate::http::AppError::from(e))
                    }
                })
            )
        }
    }
}

/// Attribute macro for individual operations
///
/// Usage: #[operation(name = "get_flow", http = "GET /flows/{name}", cli = "get <NAME>")]
#[proc_macro_attribute]
pub fn operation(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as OperationArgs);
    let input = parse_macro_input!(item as ItemStruct);

    let struct_name = &input.ident;
    let vis = &input.vis;
    let fields = &input.fields;
    let attrs = &input.attrs;

    // Determine operation name
    let operation_name = args
        .name
        .unwrap_or_else(|| to_snake_case(&struct_name.to_string()));

    // Extract doc comments for description (fallback)
    let doc_comment = attrs
        .iter()
        .filter_map(|attr| {
            if attr.path().is_ident("doc")
                && let syn::Meta::NameValue(meta) = &attr.meta
                && let syn::Expr::Lit(expr_lit) = &meta.value
                && let syn::Lit::Str(lit_str) = &expr_lit.lit
            {
                return Some(lit_str.value().trim().to_string());
            }
            None
        })
        .collect::<Vec<_>>()
        .join(" ");

    let description = args.description.unwrap_or_else(|| {
        if doc_comment.is_empty() {
            format!("{} operation", struct_name)
        } else {
            doc_comment
        }
    });

    // Parse HTTP metadata and generate helper method
    let (http_method_const, http_path_const, http_route_method) = if let Some(http) = &args.http {
        let (method, path) = parse_http_route(http);
        let http_method_helper = generate_http_route_method(&method, &path, &args.input);
        (
            quote! { Some(#method) },
            quote! { Some(#path) },
            http_method_helper,
        )
    } else {
        // Generate empty http_route method if no HTTP metadata
        (
            quote! { None },
            quote! { None },
            quote! {
                /// No HTTP route defined for this operation
                pub fn http_route(_deps: std::sync::Arc<super::Dependencies>) -> axum::Router {
                    axum::Router::new()
                }
            },
        )
    };

    // CLI metadata
    let cli_pattern = if let Some(cli) = args.cli {
        quote! { Some(#cli) }
    } else {
        quote! { None }
    };

    // Group metadata - use explicit group or fall back to GROUP_NAME
    let group_value = if let Some(group) = args.group {
        quote! { #group }
    } else {
        quote! { GROUP_NAME }
    };

    // Note: MCP tool generation will be done in operation_group macro
    // to avoid import issues with rmcp types

    // Generate schema from Input type if provided, with OnceLock caching
    let schema_generation = if let Some(input_type) = args.input {
        quote! {
            {
                use std::sync::OnceLock;
                use schemars::schema_for;

                static SCHEMA: OnceLock<serde_json::Map<String, serde_json::Value>> = OnceLock::new();

                SCHEMA.get_or_init(|| {
                    let schema = schema_for!(#input_type);
                    match serde_json::to_value(&schema) {
                        Ok(serde_json::Value::Object(map)) => map,
                        _ => {
                            // Fallback to empty schema if conversion fails
                            let mut schema = serde_json::Map::new();
                            schema.insert("type".to_string(), serde_json::Value::String("object".to_string()));
                            schema.insert("properties".to_string(), serde_json::Value::Object(serde_json::Map::new()));
                            schema.insert("additionalProperties".to_string(), serde_json::Value::Bool(true));
                            schema
                        }
                    }
                }).clone()
            }
        }
    } else {
        // Default fallback schema if no input type specified
        quote! {
            {
                use std::sync::OnceLock;

                static SCHEMA: OnceLock<serde_json::Map<String, serde_json::Value>> = OnceLock::new();

                SCHEMA.get_or_init(|| {
                    let mut schema = serde_json::Map::new();
                    schema.insert("type".to_string(), serde_json::Value::String("object".to_string()));
                    schema.insert("properties".to_string(), serde_json::Value::Object(serde_json::Map::new()));
                    schema.insert("additionalProperties".to_string(), serde_json::Value::Bool(true));
                    schema
                }).clone()
            }
        }
    };

    // Generate operation metadata and helper methods
    let expanded = quote! {
        #[derive(Clone)]
        #(#attrs)*
        #vis struct #struct_name #fields

        impl #struct_name {
            pub const OPERATION_NAME: &'static str = #operation_name;
            pub const DESCRIPTION: &'static str = #description;
            pub const GROUP: &'static str = #group_value;
            pub const HTTP_METHOD: Option<&'static str> = #http_method_const;
            pub const HTTP_PATH: Option<&'static str> = #http_path_const;
            pub const CLI_PATTERN: Option<&'static str> = #cli_pattern;

            pub fn new(deps: std::sync::Arc<super::Dependencies>) -> Self {
                Self { deps }
            }

            // Auto-generated helper methods
            #http_route_method
        }

        impl super::super::HasMetadata for #struct_name {
            fn metadata() -> super::super::OperationMetadata {
                super::super::OperationMetadata {
                    name: Self::OPERATION_NAME,
                    description: Self::DESCRIPTION,
                    group: Self::GROUP,
                    http_method: Self::HTTP_METHOD,
                    http_path: Self::HTTP_PATH,
                    cli_pattern: Self::CLI_PATTERN,
                    schema: #schema_generation,
                }
            }
        }
    };

    TokenStream::from(expanded)
}
