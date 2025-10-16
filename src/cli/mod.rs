//! Command-line interface for BeemFlow
//!
//! Provides CLI access to all operations via auto-generated commands from metadata.
//! Uses the same DRY approach as HTTP routes and MCP tools.

use crate::Result;
use crate::auth::server::generate_client_secret;
use crate::config::Config;
use crate::core::{OperationMetadata, OperationRegistry};
use crate::model::OAuthClient;
use chrono::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command, ValueEnum};
use serde_json::Value;
use std::collections::HashMap;

/// MCP transport options
#[derive(ValueEnum, Clone, Debug)]
enum McpTransport {
    /// stdio transport for local process communication (Claude Desktop)
    Stdio,
    /// Streamable HTTP transport (MCP 2025-03-26 spec) for remote access
    Http,
}

/// Parse a comma-separated list from CLI arguments
fn parse_comma_list(matches: &ArgMatches, key: &str) -> Vec<String> {
    matches
        .get_one::<String>(key)
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

/// Convert String to 'static str for CLI command building
///
/// This uses String::leak() which is appropriate for CLIs because:
/// 1. Commands are built once at program startup
/// 2. Program exits immediately after parsing (short-lived process)
/// 3. OS reclaims all memory on exit
/// 4. This is the standard Rust pattern for dynamic CLI generation with clap
///
/// Alternative approaches (and why they don't work here):
/// - Static strings: Can't be used for dynamic metadata-driven commands
/// - Owned storage: Clap's builder API requires 'static lifetime
/// - Runtime API: Would require rewriting all command logic
fn to_static_str(s: String) -> &'static str {
    s.leak()
}

/// Create operation registry with dependencies
async fn create_registry() -> Result<OperationRegistry> {
    let config = Config::load_and_inject(crate::constants::CONFIG_FILE_NAME)?;
    let deps = crate::core::create_dependencies(&config).await?;
    Ok(OperationRegistry::new(deps))
}

/// Main CLI entry point
pub async fn run() -> Result<()> {
    // Create registry for operation access
    let registry = create_registry().await?;

    // Build CLI from operation metadata (same pattern as HTTP/MCP use metadata)
    let app = build_cli(&registry);
    let matches = app.get_matches();

    // Handle special commands (not operations)
    match matches.subcommand() {
        Some(("serve", sub_matches)) => {
            return handle_serve_command(sub_matches).await;
        }
        Some(("cron", _)) => {
            return run_cron_check().await;
        }
        Some(("mcp", sub_matches)) => {
            if let Some(("serve", mcp_serve_matches)) = sub_matches.subcommand() {
                let transport = mcp_serve_matches
                    .get_one::<McpTransport>("transport")
                    .cloned()
                    .unwrap_or(McpTransport::Stdio);
                let host = mcp_serve_matches
                    .get_one::<String>("host")
                    .map(|s| s.as_str())
                    .unwrap_or("127.0.0.1");
                let port = mcp_serve_matches
                    .get_one::<String>("port")
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(3001);
                return serve_mcp(transport, host, port).await;
            }
        }
        Some(("oauth", sub_matches)) => {
            return handle_oauth_command(sub_matches).await;
        }
        _ => {}
    }

    // Try to dispatch to an operation (uses registry.execute() like MCP does)
    if let Some((op_name, input)) = dispatch_to_operation(&matches, &registry)? {
        let result = registry.execute(&op_name, input).await?;
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }

    // No command matched
    eprintln!("No command specified. Use --help for usage information.");
    std::process::exit(1);
}

// ============================================================================
// CLI Building (from operation metadata)
// ============================================================================

/// Build CLI from operations metadata (same DRY principle as HTTP/MCP)
fn build_cli(registry: &OperationRegistry) -> Command {
    let mut app = Command::new("flow")
        .about("BeemFlow - Workflow orchestration runtime")
        .version(env!("CARGO_PKG_VERSION"));

    // Add special commands that aren't operations
    app = app
        .subcommand(
            Command::new("serve")
                .about("Start BeemFlow server")
                .arg(
                    Arg::new("http")
                        .long("http")
                        .action(ArgAction::SetTrue)
                        .help("Enable HTTP REST API (triggers exclusive mode)"),
                )
                .arg(
                    Arg::new("mcp")
                        .long("mcp")
                        .action(ArgAction::SetTrue)
                        .help("Enable MCP over HTTP transport (triggers exclusive mode)"),
                )
                .arg(
                    Arg::new("mcp-stdio")
                        .long("mcp-stdio")
                        .action(ArgAction::SetTrue)
                        .help("Enable MCP over stdio (exclusive, for Claude Desktop)"),
                )
                .arg(
                    Arg::new("oauth-server")
                        .long("oauth-server")
                        .action(ArgAction::SetTrue)
                        .help("Enable OAuth authorization server (wraps MCP with auth)"),
                )
                .arg(
                    Arg::new("host")
                        .long("host")
                        .default_value("0.0.0.0")
                        .help("Server host"),
                )
                .arg(
                    Arg::new("port")
                        .long("port")
                        .short('p')
                        .default_value("3330")
                        .help("Server port"),
                ),
        )
        .subcommand(Command::new("cron").about("Run cron checks"))
        .subcommand(
            Command::new("oauth")
                .about("OAuth client management")
                .subcommand(
                    Command::new("create-client")
                        .about("Create OAuth client")
                        .arg(Arg::new("name").long("name").required(true))
                        .arg(
                            Arg::new("grant-types")
                                .long("grant-types")
                                .default_value("client_credentials"),
                        )
                        .arg(Arg::new("scopes").long("scopes").default_value("mcp"))
                        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
                )
                .subcommand(
                    Command::new("list-clients")
                        .about("List OAuth clients")
                        .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
                )
                .subcommand(
                    Command::new("revoke-client")
                        .about("Revoke OAuth client")
                        .arg(Arg::new("client-id").required(true).index(1)),
                ),
        );

    // Build operation commands from metadata
    add_operation_commands(app, registry)
}

/// Build commands from operation metadata (mirrors HTTP route generation)
fn add_operation_commands(mut app: Command, registry: &OperationRegistry) -> Command {
    let metadata = registry.get_all_metadata();

    // Group operations by CLI structure
    let mut grouped: HashMap<String, Vec<(&String, &OperationMetadata)>> = HashMap::new();

    for (op_name, meta) in metadata {
        if let Some(cli_pattern) = meta.cli_pattern {
            let words: Vec<&str> = cli_pattern
                .split_whitespace()
                .take_while(|w| !w.starts_with('<') && !w.starts_with('['))
                .collect();

            let group = words.first().map(|s| s.to_string()).unwrap_or_default();
            grouped.entry(group).or_default().push((op_name, meta));
        }
    }

    // Build subcommands for each group
    for (group_name, ops) in grouped {
        if group_name.is_empty() {
            continue;
        }

        // Use to_static_str to satisfy clap's 'static lifetime requirement
        let group_name_static = to_static_str(group_name.clone());
        let group_about = to_static_str(format!("{} operations", group_name));
        let mut group_cmd = Command::new(group_name_static).about(group_about);

        for (op_name, meta) in ops {
            if let Some(cli_pattern) = meta.cli_pattern {
                // cli_pattern has 'static lifetime, so words do too
                let words: Vec<&'static str> = cli_pattern.split_whitespace().collect();
                let subcmd_name = words.get(1).copied().unwrap_or(words[0]);

                let cmd = build_operation_command(op_name, meta, subcmd_name);
                group_cmd = group_cmd.subcommand(cmd);
            }
        }

        // Add special "mcp serve" subcommand to the mcp group
        if group_name == "mcp" {
            group_cmd = group_cmd.subcommand(
                Command::new("serve")
                    .about("Start MCP server")
                    .arg(
                        Arg::new("transport")
                            .long("transport")
                            .value_parser(clap::value_parser!(McpTransport))
                            .default_value("stdio")
                            .help("Transport: stdio or http"),
                    )
                    .arg(Arg::new("host").long("host").default_value("127.0.0.1"))
                    .arg(Arg::new("port").long("port").default_value("3001")),
            );
        }

        app = app.subcommand(group_cmd);
    }

    app
}

/// Build a clap Command for an operation using its schema
fn build_operation_command(
    _op_name: &str,
    meta: &OperationMetadata,
    cmd_name: &'static str,
) -> Command {
    let mut cmd = Command::new(cmd_name).about(meta.description);

    // Extract field information from JSON schema
    if let Some(properties) = meta.schema.get("properties").and_then(|p| p.as_object()) {
        let required: Vec<&str> = meta
            .schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let cli_pattern = meta.cli_pattern.unwrap_or("");
        let mut positional_index = 1;

        for (field_name, field_schema) in properties {
            let is_required = required.contains(&field_name.as_str());

            // Handle both string type and array of types (e.g., ["object", "null"] for Option<HashMap>)
            let field_type = match field_schema.get("type") {
                Some(serde_json::Value::String(s)) => s.as_str(),
                Some(serde_json::Value::Array(arr)) => {
                    // For arrays like ["object", "null"], pick the first non-null type
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .find(|&s| s != "null")
                        .unwrap_or("string")
                }
                _ => "string",
            };

            let description = field_schema
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("");

            // Check if this is a positional arg in the pattern
            // It's positional if it appears as <FIELD> but NOT as --flag <FIELD>
            let uppercase_field = format!("<{}>", field_name.to_uppercase());
            let flag_pattern = format!("--{} {}", field_name, uppercase_field);
            let is_positional =
                cli_pattern.contains(&uppercase_field) && !cli_pattern.contains(&flag_pattern);

            // Use to_static_str for clap's 'static lifetime requirement
            let field_name_static = to_static_str(field_name.clone());
            let description_static = to_static_str(description.to_string());

            if is_positional {
                cmd = cmd.arg(
                    Arg::new(field_name_static)
                        .required(is_required)
                        .index(positional_index)
                        .help(description_static),
                );
                positional_index += 1;
            } else if field_type == "boolean" {
                cmd = cmd.arg(
                    Arg::new(field_name_static)
                        .long(field_name_static)
                        .action(ArgAction::SetTrue)
                        .help(description_static),
                );
            } else {
                cmd = cmd.arg(
                    Arg::new(field_name_static)
                        .long(field_name_static)
                        .required(is_required)
                        .help(description_static),
                );
            }
        }
    }

    cmd
}

/// Dispatch CLI matches to operation (uses registry.execute() like MCP)
fn dispatch_to_operation(
    matches: &ArgMatches,
    registry: &OperationRegistry,
) -> Result<Option<(String, Value)>> {
    let metadata = registry.get_all_metadata();

    // Check for two-level subcommands (group subcmd)
    if let Some((group, group_matches)) = matches.subcommand()
        && let Some((subcmd, subcmd_matches)) = group_matches.subcommand()
    {
        let prefix = format!("{} {}", group, subcmd);

        // Find matching operation
        for (op_name, meta) in metadata {
            if let Some(cli_pattern) = meta.cli_pattern
                && cli_pattern.starts_with(&prefix)
            {
                let input = extract_input_from_matches(subcmd_matches, meta)?;
                return Ok(Some((op_name.clone(), input)));
            }
        }
    }

    Ok(None)
}

/// Extract operation input from CLI arguments using schema
fn extract_input_from_matches(matches: &ArgMatches, meta: &OperationMetadata) -> Result<Value> {
    let mut input = serde_json::Map::new();

    if let Some(properties) = meta.schema.get("properties").and_then(|p| p.as_object()) {
        for (field_name, field_schema) in properties {
            // Handle both string type and array of types (e.g., ["object", "null"] for Option<HashMap>)
            let field_type = match field_schema.get("type") {
                Some(serde_json::Value::String(s)) => s.as_str(),
                Some(serde_json::Value::Array(arr)) => {
                    // For arrays like ["object", "null"], pick the first non-null type
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .find(|&s| s != "null")
                        .unwrap_or("string")
                }
                _ => "string",
            };

            if field_type == "boolean" {
                if matches.get_flag(field_name.as_str()) {
                    input.insert(field_name.clone(), serde_json::json!(true));
                }
            } else if let Some(value_str) = matches.get_one::<String>(field_name.as_str()) {
                let parsed = match field_type {
                    "integer" | "number" => value_str
                        .parse::<i64>()
                        .map(|n| serde_json::json!(n))
                        .unwrap_or_else(|_| serde_json::json!(value_str)),
                    "object" | "array" => serde_json::from_str(value_str)
                        .unwrap_or_else(|_| serde_json::json!(value_str)),
                    _ => serde_json::json!(value_str),
                };
                input.insert(field_name.clone(), parsed);
            }
        }
    }

    Ok(serde_json::json!(input))
}

// ============================================================================
// Special Commands (not operations)
// ============================================================================

/// Handle the serve command with new interface flags
async fn handle_serve_command(matches: &ArgMatches) -> Result<()> {
    // Parse interface flags
    let http_flag = matches.get_flag("http");
    let mcp_flag = matches.get_flag("mcp");
    let mcp_stdio_flag = matches.get_flag("mcp-stdio");
    let oauth_server_flag = matches.get_flag("oauth-server");

    // Validation: --mcp-stdio is exclusive
    if mcp_stdio_flag && (http_flag || mcp_flag) {
        eprintln!("Error: --mcp-stdio cannot be combined with --http or --mcp");
        std::process::exit(1);
    }

    // Validation: --oauth-server requires HTTP server
    if mcp_stdio_flag && oauth_server_flag {
        eprintln!("Error: --oauth-server requires HTTP server (incompatible with --mcp-stdio)");
        std::process::exit(1);
    }

    // Validation: --port/--host don't apply to stdio
    if mcp_stdio_flag {
        let has_port = matches.contains_id("port")
            && matches.get_one::<String>("port").map(|s| s.as_str()) != Some("3330");
        let has_host = matches.contains_id("host")
            && matches.get_one::<String>("host").map(|s| s.as_str()) != Some("0.0.0.0");

        if has_port || has_host {
            eprintln!("Error: --port and --host not applicable to --mcp-stdio");
            std::process::exit(1);
        }
    }

    // Special case: stdio only
    if mcp_stdio_flag {
        return serve_mcp_stdio().await;
    }

    // Load config to get defaults
    let mut config =
        Config::load_and_inject(crate::constants::CONFIG_FILE_NAME).unwrap_or_default();

    // Determine interfaces with CLI override logic
    let explicit_mode = http_flag || mcp_flag;

    let interfaces = if explicit_mode {
        // Explicit mode: CLI flags override everything
        crate::http::ServerInterfaces {
            http_api: http_flag,
            mcp: mcp_flag,
            oauth_server: oauth_server_flag,
        }
    } else {
        // Default mode: use config defaults, allow --oauth-server to enable
        let http_config = config.http.as_ref();
        crate::http::ServerInterfaces {
            http_api: http_config.map(|c| c.enable_http_api).unwrap_or(true),
            mcp: http_config.map(|c| c.enable_mcp).unwrap_or(true),
            oauth_server: oauth_server_flag
                || http_config.map(|c| c.enable_oauth_server).unwrap_or(false),
        }
    };

    // Validate at least one interface enabled
    if !interfaces.http_api && !interfaces.mcp {
        eprintln!("Error: At least one interface must be enabled");
        std::process::exit(1);
    }

    // Get host and port (CLI overrides config)
    let host = matches.get_one::<String>("host").unwrap();
    let port = matches
        .get_one::<String>("port")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(crate::constants::DEFAULT_HTTP_PORT);

    // Update config with CLI values
    if let Some(http_config) = config.http.as_mut() {
        http_config.host = host.to_string();
        http_config.port = port;
    } else {
        config.http = Some(crate::config::HttpConfig {
            host: host.to_string(),
            port,
            secure: false,
            allowed_origins: None,
            trust_proxy: false,
            enable_http_api: true,
            enable_mcp: true,
            enable_oauth_server: false,
        });
    }

    // Print startup message
    println!("🚀 Starting BeemFlow server on {}:{}", host, port);
    if interfaces.http_api {
        println!("   ✓ HTTP REST API enabled");
    }
    if interfaces.mcp {
        println!("   ✓ MCP over HTTP enabled");
    }
    if interfaces.oauth_server {
        println!("   ✓ OAuth authorization server enabled");
    }
    println!("   Press Ctrl+C to stop\n");

    crate::http::start_server(config, interfaces).await?;

    Ok(())
}

/// Start MCP over stdio (for Claude Desktop)
async fn serve_mcp_stdio() -> Result<()> {
    // CRITICAL: For stdio transport, stdout is reserved for JSON-RPC messages.
    // All diagnostic output MUST go to stderr to avoid corrupting the protocol.
    eprintln!("Starting MCP server (stdio transport)");
    eprintln!("Ready for JSON-RPC messages on stdin/stdout");

    let config = Config::load_and_inject(crate::constants::CONFIG_FILE_NAME)?;
    let deps = crate::core::create_dependencies(&config).await?;
    let registry = std::sync::Arc::new(OperationRegistry::new(deps));
    let mcp_server = crate::mcp::McpServer::new(registry);

    mcp_server.serve_stdio().await
}

/// Start MCP server (special command - not an operation)
async fn serve_mcp(transport: McpTransport, host: &str, port: u16) -> Result<()> {
    let registry = create_registry().await?;
    let mcp_server = crate::mcp::McpServer::new(std::sync::Arc::new(registry));

    match transport {
        McpTransport::Stdio => {
            // CRITICAL: For stdio transport, stdout is reserved for JSON-RPC messages.
            // All diagnostic output MUST go to stderr to avoid corrupting the protocol.
            // Use eprintln!() or tracing (which logs to stderr by default)
            eprintln!("Starting MCP server (stdio transport)");
            eprintln!("Ready for JSON-RPC messages on stdin/stdout");

            mcp_server.serve_stdio().await?;
        }
        McpTransport::Http => {
            println!("🚀 Starting MCP server (Streamable HTTP transport with OAuth)");
            let config = Config::load_and_inject(crate::constants::CONFIG_FILE_NAME)?;
            let oauth_issuer = config
                .http
                .as_ref()
                .map(|c| format!("http://{}:{}", c.host, c.port))
                .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());

            let deps = crate::core::create_dependencies(&config).await?;

            println!("   OAuth issuer: {}", oauth_issuer);
            println!("   Create client: flow oauth create-client --name \"Claude Desktop\"");
            println!("   Using MCP 2025-03-26 Streamable HTTP transport");

            mcp_server
                .serve_http(host, port, oauth_issuer, deps.storage)
                .await?;
        }
    }
    Ok(())
}

/// Run cron check (special command - not an operation)
async fn run_cron_check() -> Result<()> {
    eprintln!("Cron functionality temporarily disabled during refactoring");
    Ok(())
}

/// Handle OAuth commands (special command - not an operation)
async fn handle_oauth_command(matches: &ArgMatches) -> Result<()> {
    let config = Config::load_and_inject(crate::constants::CONFIG_FILE_NAME)?;
    let storage = crate::storage::create_storage_from_config(&config.storage).await?;

    match matches.subcommand() {
        Some(("create-client", sub)) => {
            let name = sub.get_one::<String>("name").unwrap();
            let grant_types = parse_comma_list(sub, "grant-types");
            let scopes = parse_comma_list(sub, "scopes");
            let json = sub.get_flag("json");

            let client_id = format!(
                "{}-{}",
                name.to_lowercase().replace(' ', "-"),
                Utc::now().format("%Y%m%d%H%M%S")
            );
            let client_secret = generate_client_secret();

            let client = OAuthClient {
                id: client_id.clone(),
                secret: client_secret.clone(),
                name: name.clone(),
                redirect_uris: vec![],
                grant_types,
                response_types: vec!["code".to_string()],
                scope: scopes.join(" "),
                client_uri: None,
                logo_uri: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            storage.save_oauth_client(&client).await?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "client_id": client_id,
                        "client_secret": client_secret,
                    }))?
                );
            } else {
                println!("\n✅ OAuth client created!");
                println!("Client ID:     {}", client_id);
                println!("Client Secret: {}", client_secret);
                println!("\nUse these in Claude/ChatGPT settings");
            }
        }
        Some(("list-clients", sub)) => {
            let json = sub.get_flag("json");
            let clients = storage.list_oauth_clients().await?;

            if json {
                println!("{}", serde_json::to_string_pretty(&clients)?);
            } else {
                println!("\nOAuth Clients:");
                for client in clients {
                    println!("  {} ({})", client.name, client.id);
                }
            }
        }
        Some(("revoke-client", sub)) => {
            let client_id = sub.get_one::<String>("client-id").unwrap();
            storage.delete_oauth_client(client_id).await?;
            println!("✅ Client '{}' revoked", client_id);
        }
        _ => {}
    }
    Ok(())
}
