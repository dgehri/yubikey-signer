//! Test environment helpers.
//!
//! Integration tests are often run from IDEs or CI environments where a local
//! `.env` file is not automatically loaded. To keep tests ergonomic, we load a
//! repository-root `.env` (if present) into the process environment.
//!
//! Values already present in the process environment are **not** overwritten.

use std::env;
use std::fs;
use std::path::Path;

/// Attempt to load environment variables from a `.env` file.
///
/// - Looks for `<repo>/.env` using `CARGO_MANIFEST_DIR`.
/// - Ignores blank lines and `#` comments.
/// - Parses `KEY=VALUE` (first `=` wins).
/// - Does **not** overwrite variables that are already set in the process.
///
/// # Panics
/// Never panics. Failures are ignored on purpose.
pub fn load_dotenv_if_present() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let env_path = manifest_dir.join(".env");

    let Ok(content) = fs::read_to_string(&env_path) else {
        return;
    };

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        // Do not override explicitly set environment variables.
        if env::var_os(key).is_some() {
            continue;
        }

        let mut value = raw_value.trim().trim_end_matches('\r').to_string();
        // Support simple quoting styles.
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len().saturating_sub(1)].to_string();
        }

        env::set_var(key, value);
    }
}
