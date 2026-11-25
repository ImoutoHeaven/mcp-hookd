use clap::{Parser, Subcommand};
use mcp_hookd::config::Config;
use mcp_hookd::emit::{DEFAULT_INGEST_URL, EmitOptions, OnInvalid, run_emit};
use mcp_hookd::server::run_serve;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "mcp-hookd",
    version,
    about = "Webhook subscription, verification, ingest, and delivery daemon for MCP Events"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate configuration and exit.
    Check {
        #[arg(long, env = "HOOKD_CONFIG", default_value = "hookd.json")]
        config: PathBuf,
    },
    /// Run the HTTP facade and webhook delivery daemon in the foreground.
    Serve {
        #[arg(long, env = "HOOKD_CONFIG", default_value = "hookd.json")]
        config: PathBuf,
    },
    /// Send one event or a stream of NDJSON events to POST /v1/events.
    Emit {
        #[arg(long, env = "HOOKD_INGEST_URL", default_value = DEFAULT_INGEST_URL)]
        url: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        stream: bool,
        #[arg(long, value_enum, default_value_t = OnInvalid::Fail)]
        on_invalid: OnInvalid,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check { config } => match Config::load_from_path(&config) {
            Ok(_) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("mcp-hookd check failed: {err}");
                ExitCode::FAILURE
            }
        },
        Command::Serve { config } => {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("mcp-hookd serve failed to start runtime: {err}");
                    return ExitCode::FAILURE;
                }
            };
            rt.block_on(run_serve(&config))
        }
        Command::Emit {
            url,
            name,
            stream,
            on_invalid,
        } => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    eprintln!("mcp-hookd emit failed to start runtime: {err}");
                    return ExitCode::FAILURE;
                }
            };
            rt.block_on(run_emit(EmitOptions {
                url,
                name,
                stream,
                on_invalid,
                token: None,
            }))
        }
    }
}
