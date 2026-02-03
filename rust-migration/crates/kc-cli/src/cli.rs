//! CLI argument parsing.

use clap::{Parser, Subcommand};

use crate::config::OutputFormat;

/// Keycloak CLI - Administration tool for Keycloak Rust.
#[derive(Debug, Parser)]
#[command(name = "kc")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Server URL (overrides config).
    #[arg(short, long, env = "KC_SERVER_URL")]
    pub server: Option<String>,

    /// Database URL for direct access (overrides config).
    #[arg(long, env = "KC_DATABASE_URL")]
    pub database_url: Option<String>,

    /// Default realm (overrides config).
    #[arg(short, long, env = "KC_REALM")]
    pub realm: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormat,

    /// Enable verbose output.
    #[arg(short, long)]
    pub verbose: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// CLI commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Realm management commands.
    #[command(subcommand)]
    Realm(RealmCommand),

    /// User management commands.
    #[command(subcommand)]
    User(UserCommand),

    /// Client management commands.
    #[command(subcommand)]
    Client(ClientCommand),

    /// Role management commands.
    #[command(subcommand)]
    Role(RoleCommand),

    /// Group management commands.
    #[command(subcommand)]
    Group(GroupCommand),

    /// Export configuration.
    Export(ExportArgs),

    /// Import configuration.
    Import(ImportArgs),

    /// Cryptographic utilities.
    #[command(subcommand)]
    Crypto(CryptoCommand),

    /// Configuration management.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Server status check.
    Status,
}

/// Realm commands.
#[derive(Debug, Subcommand)]
pub enum RealmCommand {
    /// List all realms.
    List,

    /// Get realm details.
    Get {
        /// Realm name.
        name: String,
    },

    /// Create a new realm.
    Create {
        /// Realm name.
        name: String,

        /// Display name.
        #[arg(long)]
        display_name: Option<String>,

        /// Enable the realm.
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Update a realm.
    Update {
        /// Realm name.
        name: String,

        /// New display name.
        #[arg(long)]
        display_name: Option<String>,

        /// Enable/disable the realm.
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Delete a realm.
    Delete {
        /// Realm name.
        name: String,

        /// Skip confirmation.
        #[arg(long)]
        force: bool,
    },
}

/// User commands.
#[derive(Debug, Subcommand)]
pub enum UserCommand {
    /// List users in a realm.
    List {
        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Search query.
        #[arg(long)]
        search: Option<String>,

        /// Filter by username.
        #[arg(long)]
        username: Option<String>,

        /// Filter by email.
        #[arg(long)]
        email: Option<String>,

        /// Maximum results.
        #[arg(long, default_value = "100")]
        max: u32,
    },

    /// Get user details.
    Get {
        /// User ID or username.
        id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,
    },

    /// Create a new user.
    Create {
        /// Username.
        username: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Email address.
        #[arg(long)]
        email: Option<String>,

        /// First name.
        #[arg(long)]
        first_name: Option<String>,

        /// Last name.
        #[arg(long)]
        last_name: Option<String>,

        /// Enable the user.
        #[arg(long, default_value = "true")]
        enabled: bool,

        /// Set password (will prompt if not provided).
        #[arg(long)]
        password: Option<String>,

        /// Require password change on first login.
        #[arg(long)]
        temporary_password: bool,
    },

    /// Update a user.
    Update {
        /// User ID or username.
        id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Email address.
        #[arg(long)]
        email: Option<String>,

        /// First name.
        #[arg(long)]
        first_name: Option<String>,

        /// Last name.
        #[arg(long)]
        last_name: Option<String>,

        /// Enable/disable the user.
        #[arg(long)]
        enabled: Option<bool>,
    },

    /// Delete a user.
    Delete {
        /// User ID or username.
        id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Skip confirmation.
        #[arg(long)]
        force: bool,
    },

    /// Set user password.
    SetPassword {
        /// User ID or username.
        id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// New password (will prompt if not provided).
        #[arg(long)]
        password: Option<String>,

        /// Temporary password (require change on login).
        #[arg(long)]
        temporary: bool,
    },
}

/// Client commands.
#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// List clients in a realm.
    List {
        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Search query.
        #[arg(long)]
        search: Option<String>,

        /// Maximum results.
        #[arg(long, default_value = "100")]
        max: u32,
    },

    /// Get client details.
    Get {
        /// Client ID (not UUID).
        client_id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,
    },

    /// Create a new client.
    Create {
        /// Client ID.
        client_id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Client name.
        #[arg(long)]
        name: Option<String>,

        /// Public client (no secret).
        #[arg(long)]
        public: bool,

        /// Redirect URIs (comma-separated).
        #[arg(long)]
        redirect_uris: Option<String>,

        /// Web origins (comma-separated).
        #[arg(long)]
        web_origins: Option<String>,

        /// Enable the client.
        #[arg(long, default_value = "true")]
        enabled: bool,
    },

    /// Delete a client.
    Delete {
        /// Client ID.
        client_id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Skip confirmation.
        #[arg(long)]
        force: bool,
    },

    /// Get client secret.
    GetSecret {
        /// Client ID.
        client_id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,
    },

    /// Regenerate client secret.
    RegenerateSecret {
        /// Client ID.
        client_id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,
    },
}

/// Role commands.
#[derive(Debug, Subcommand)]
pub enum RoleCommand {
    /// List roles in a realm.
    List {
        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Client ID (for client roles).
        #[arg(long)]
        client: Option<String>,
    },

    /// Create a role.
    Create {
        /// Role name.
        name: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Client ID (for client role).
        #[arg(long)]
        client: Option<String>,

        /// Role description.
        #[arg(long)]
        description: Option<String>,
    },

    /// Delete a role.
    Delete {
        /// Role name.
        name: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Client ID (for client role).
        #[arg(long)]
        client: Option<String>,

        /// Skip confirmation.
        #[arg(long)]
        force: bool,
    },
}

/// Group commands.
#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// List groups in a realm.
    List {
        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Search query.
        #[arg(long)]
        search: Option<String>,
    },

    /// Create a group.
    Create {
        /// Group name.
        name: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Parent group ID.
        #[arg(long)]
        parent: Option<String>,
    },

    /// Delete a group.
    Delete {
        /// Group ID or name.
        id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,

        /// Skip confirmation.
        #[arg(long)]
        force: bool,
    },

    /// List group members.
    Members {
        /// Group ID or name.
        id: String,

        /// Realm name.
        #[arg(long)]
        realm: Option<String>,
    },
}

/// Export arguments.
#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// Output file (stdout if not specified).
    #[arg(short, long)]
    pub file: Option<String>,

    /// Realm to export (all if not specified).
    #[arg(long)]
    pub realm: Option<String>,

    /// Include users.
    #[arg(long, default_value = "true")]
    pub users: bool,

    /// Include clients.
    #[arg(long, default_value = "true")]
    pub clients: bool,

    /// Include roles.
    #[arg(long, default_value = "true")]
    pub roles: bool,

    /// Include groups.
    #[arg(long, default_value = "true")]
    pub groups: bool,
}

/// Import arguments.
#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// Input file.
    pub file: String,

    /// Target realm (overrides file realm).
    #[arg(long)]
    pub realm: Option<String>,

    /// Skip existing resources.
    #[arg(long)]
    pub skip_existing: bool,

    /// Overwrite existing resources.
    #[arg(long)]
    pub overwrite: bool,
}

/// Crypto commands.
#[derive(Debug, Subcommand)]
pub enum CryptoCommand {
    /// Generate a new keypair.
    GenerateKey {
        /// Key algorithm (es384, es512, rs384, rs512, ps384, ps512).
        #[arg(short, long, default_value = "es384")]
        algorithm: String,

        /// Output file for private key (PEM format).
        #[arg(short, long)]
        output: Option<String>,

        /// Output file for public key.
        #[arg(long)]
        public_key: Option<String>,

        /// Output file for self-signed certificate.
        #[arg(long)]
        certificate: Option<String>,

        /// Certificate subject CN.
        #[arg(long, default_value = "Keycloak")]
        subject: String,

        /// Certificate validity in days.
        #[arg(long, default_value = "365")]
        validity_days: u32,
    },

    /// Decode a JWT token.
    DecodeToken {
        /// The JWT token to decode.
        token: String,

        /// Verify signature (requires JWKS URL or public key).
        #[arg(long)]
        verify: bool,

        /// JWKS URL for signature verification.
        #[arg(long)]
        jwks_url: Option<String>,
    },

    /// Generate a random secret.
    GenerateSecret {
        /// Length in bytes.
        #[arg(short, long, default_value = "32")]
        length: usize,

        /// Output format (hex, base64, alphanumeric).
        #[arg(short, long, default_value = "base64")]
        format: String,
    },

    /// Hash a password.
    HashPassword {
        /// Password to hash (will prompt if not provided).
        #[arg(short, long)]
        password: Option<String>,

        /// Algorithm (argon2id, bcrypt, pbkdf2).
        #[arg(short, long, default_value = "argon2id")]
        algorithm: String,
    },
}

/// Config commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Show current configuration.
    Show,

    /// Set a configuration value.
    Set {
        /// Configuration key.
        key: String,
        /// Configuration value.
        value: String,
    },

    /// Initialize configuration interactively.
    Init,
}
