//! Cryptographic utility commands.

use base64::Engine;

use crate::cli::CryptoCommand;
use crate::output::{error, info};
use crate::CliConfig;

/// Runs a crypto command.
pub async fn run_crypto(cmd: CryptoCommand, _config: &CliConfig) -> crate::CliResult<()> {
    match cmd {
        CryptoCommand::GenerateKey {
            algorithm,
            output,
            public_key,
            certificate,
            subject,
            validity_days,
        } => {
            generate_key(
                &algorithm,
                output.as_deref(),
                public_key.as_deref(),
                certificate.as_deref(),
                &subject,
                validity_days,
            )
        }
        CryptoCommand::DecodeToken {
            token,
            verify,
            jwks_url,
        } => decode_token(&token, verify, jwks_url.as_deref()).await,
        CryptoCommand::GenerateSecret { length, format } => generate_secret(length, &format),
        CryptoCommand::HashPassword { password, algorithm } => {
            do_hash_password(password.as_deref(), &algorithm)
        }
    }
}

/// Generates a new keypair.
fn generate_key(
    algorithm: &str,
    _output: Option<&str>,
    _public_key_path: Option<&str>,
    _certificate_path: Option<&str>,
    _subject: &str,
    _validity_days: u32,
) -> crate::CliResult<()> {
    // Validate algorithm
    let alg = algorithm.to_lowercase();
    let supported = matches!(alg.as_str(), "es384" | "ec384" | "p384" | "es512" | "ec512" | "p521");

    if !supported {
        return Err(crate::CliError::InvalidArgument(format!(
            "Unsupported algorithm: {}. Key generation requires CNSA 2.0 compliant algorithms (es384, es512).",
            algorithm
        )));
    }

    info("Key generation is not yet implemented in CLI.");
    info("Use OpenSSL or similar tools to generate keys:");
    info("  # For ES384 (P-384):");
    info("  openssl ecparam -genkey -name secp384r1 -noout -out private.pem");
    info("  openssl ec -in private.pem -pubout -out public.pem");
    info("");
    info("  # For ES512 (P-521):");
    info("  openssl ecparam -genkey -name secp521r1 -noout -out private.pem");
    info("  openssl ec -in private.pem -pubout -out public.pem");

    Ok(())
}

/// Decodes a JWT token.
async fn decode_token(token: &str, verify: bool, jwks_url: Option<&str>) -> crate::CliResult<()> {
    // Split the token into parts
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        return Err(crate::CliError::InvalidArgument(
            "Invalid JWT format: expected 3 parts separated by '.'".to_string(),
        ));
    }

    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Decode header
    let header_bytes = engine
        .decode(parts[0])
        .map_err(|e| crate::CliError::InvalidArgument(format!("Invalid header base64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)?;

    // Decode payload
    let payload_bytes = engine
        .decode(parts[1])
        .map_err(|e| crate::CliError::InvalidArgument(format!("Invalid payload base64: {e}")))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;

    // Print header
    println!("=== Header ===");
    println!("{}", serde_json::to_string_pretty(&header)?);

    // Print payload
    println!("\n=== Payload ===");
    println!("{}", serde_json::to_string_pretty(&payload)?);

    // Check expiration
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        let exp_time = chrono::DateTime::from_timestamp(exp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Invalid timestamp".to_string());

        let now = chrono::Utc::now().timestamp();
        if exp < now {
            error(&format!("Token EXPIRED at: {}", exp_time));
        } else {
            info(&format!("Token expires at: {}", exp_time));
        }
    }

    // Check issued at
    if let Some(iat) = payload.get("iat").and_then(|v| v.as_i64()) {
        let iat_time = chrono::DateTime::from_timestamp(iat, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Invalid timestamp".to_string());
        info(&format!("Token issued at: {}", iat_time));
    }

    // Signature verification
    if verify {
        if let Some(url) = jwks_url {
            info(&format!("Fetching JWKS from: {}", url));
            info("Signature verification not yet implemented");
        } else {
            error("Signature verification requires --jwks-url");
        }
    }

    Ok(())
}

/// Generates a random secret.
fn generate_secret(length: usize, format: &str) -> crate::CliResult<()> {
    let bytes = kc_crypto::random_bytes(length);

    let output = match format.to_lowercase().as_str() {
        "hex" => hex_encode(&bytes),
        "base64" => base64::engine::general_purpose::STANDARD.encode(&bytes),
        "alphanumeric" => kc_crypto::random_alphanumeric(length),
        _ => {
            return Err(crate::CliError::InvalidArgument(format!(
                "Unknown format: {}. Supported: hex, base64, alphanumeric",
                format
            )));
        }
    };

    println!("{}", output);
    Ok(())
}

/// Hashes a password using Argon2id.
fn do_hash_password(password: Option<&str>, algorithm: &str) -> crate::CliResult<()> {
    let pwd = if let Some(p) = password {
        p.to_string()
    } else {
        crate::output::prompt_password("Enter password: ")?
    };

    match algorithm.to_lowercase().as_str() {
        "argon2id" | "argon2" => {
            let hasher = kc_auth::PasswordHasherService::default();
            let hash = hasher.hash(&pwd)
                .map_err(|e| crate::CliError::Crypto(format!("Hashing failed: {e}")))?;
            println!("{}", hash);
            Ok(())
        }
        "bcrypt" => {
            Err(crate::CliError::InvalidArgument(
                "bcrypt not supported. Use argon2id (recommended)".to_string(),
            ))
        }
        "pbkdf2" => {
            Err(crate::CliError::InvalidArgument(
                "pbkdf2 not supported. Use argon2id (recommended)".to_string(),
            ))
        }
        _ => {
            Err(crate::CliError::InvalidArgument(format!(
                "Unknown algorithm: {}. Supported: argon2id",
                algorithm
            )))
        }
    }
}

/// Hex encode bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
