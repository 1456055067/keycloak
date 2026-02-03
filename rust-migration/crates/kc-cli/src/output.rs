//! Output formatting utilities.

use colored::Colorize;
use tabled::{settings::Style, Table, Tabled};

use crate::config::OutputFormat;

/// Prints a success message.
pub fn success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Prints an error message.
pub fn error(message: &str) {
    eprintln!("{} {}", "✗".red().bold(), message);
}

/// Prints a warning message.
pub fn warning(message: &str) {
    eprintln!("{} {}", "⚠".yellow().bold(), message);
}

/// Prints an info message.
pub fn info(message: &str) {
    println!("{} {}", "ℹ".blue().bold(), message);
}

/// Outputs data in the specified format.
pub fn output<T: Tabled + serde::Serialize>(
    data: &[T],
    format: OutputFormat,
) -> crate::CliResult<()> {
    match format {
        OutputFormat::Table => {
            if data.is_empty() {
                info("No results found.");
            } else {
                let table = Table::new(data).with(Style::rounded()).to_string();
                println!("{table}");
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(data)?;
            println!("{json}");
        }
        OutputFormat::Yaml => {
            // Simple YAML-like output
            for item in data {
                let json = serde_json::to_value(item)?;
                print_yaml_value(&json, 0);
                println!();
            }
        }
        OutputFormat::Quiet => {
            // Minimal output - just IDs or primary identifiers
        }
    }
    Ok(())
}

/// Outputs a single item.
pub fn output_single<T: serde::Serialize>(item: &T, format: OutputFormat) -> crate::CliResult<()> {
    match format {
        OutputFormat::Table | OutputFormat::Yaml => {
            let json = serde_json::to_value(item)?;
            print_yaml_value(&json, 0);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(item)?;
            println!("{json}");
        }
        OutputFormat::Quiet => {}
    }
    Ok(())
}

/// Prints a JSON value as YAML-like output.
fn print_yaml_value(value: &serde_json::Value, indent: usize) {
    let prefix = "  ".repeat(indent);

    match value {
        serde_json::Value::Null => println!("{prefix}null"),
        serde_json::Value::Bool(b) => println!("{prefix}{b}"),
        serde_json::Value::Number(n) => println!("{prefix}{n}"),
        serde_json::Value::String(s) => println!("{prefix}{s}"),
        serde_json::Value::Array(arr) => {
            for item in arr {
                print!("{prefix}- ");
                print_yaml_value(item, indent + 1);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if val.is_object() || val.is_array() {
                    println!("{prefix}{key}:");
                    print_yaml_value(val, indent + 1);
                } else {
                    print!("{prefix}{key}: ");
                    match val {
                        serde_json::Value::Null => println!("null"),
                        serde_json::Value::Bool(b) => println!("{b}"),
                        serde_json::Value::Number(n) => println!("{n}"),
                        serde_json::Value::String(s) => println!("{s}"),
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Prompts for confirmation.
pub fn confirm(message: &str) -> crate::CliResult<bool> {
    print!("{message} [y/N]: ");
    std::io::Write::flush(&mut std::io::stdout())?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    Ok(input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes"))
}

/// Prompts for password input (hidden).
pub fn prompt_password(prompt: &str) -> crate::CliResult<String> {
    rpassword::prompt_password(prompt).map_err(|e| crate::CliError::Io(e.into()))
}
