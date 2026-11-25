use clap::{Parser, Subcommand, ValueEnum};
use mcp_hookd::config::Config;
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
        #[arg(
            long,
            env = "HOOKD_INGEST_URL",
            default_value = "http://127.0.0.1:8081/v1/events"
        )]
        url: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        stream: bool,
        #[arg(long, value_enum, default_value_t = OnInvalid::Fail)]
        on_invalid: OnInvalid,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OnInvalid {
    Fail,
    Drop,
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
        Command::Serve { config: _ } => {
            eprintln!("serve not yet implemented");
            ExitCode::FAILURE
        }
        Command::Emit { .. } => {
            eprintln!("emit not yet implemented");
            ExitCode::FAILURE
        }
    }
}
