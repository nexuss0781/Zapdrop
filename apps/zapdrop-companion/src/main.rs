use serde::Serialize;
use std::{env, io, path::PathBuf};

const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[1, 2];
const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CompanionCapabilities {
    product: &'static str,
    protocol_versions: &'static [u32],
    secure_v2_transport: bool,
    receive_approval: bool,
    webview_required: bool,
    supported_platforms: &'static [&'static str],
}

fn main() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--print-capabilities") {
        let capabilities = CompanionCapabilities {
            product: "Zapdrop companion",
            protocol_versions: SUPPORTED_PROTOCOL_VERSIONS,
            secure_v2_transport: false,
            receive_approval: true,
            webview_required: false,
            supported_platforms: &["windows-legacy", "windows-modern", "linux", "macos"],
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&capabilities).map_err(|error| error.to_string())?
        );
        return Ok(());
    }
    let receive_dir = argument_value(&args, "--receive-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if !receive_dir.exists() {
        return Err(format!(
            "receive directory does not exist: {}",
            receive_dir.display()
        ));
    }
    if let Some(remote) = argument_value(&args, "--protocol-versions") {
        let remote_versions = remote
            .split(',')
            .map(|value| value.parse::<u32>().map_err(|_| "invalid protocol version"))
            .collect::<Result<Vec<_>, _>>()?;
        negotiate_protocol(&remote_versions).map_err(|error| error.to_string())?;
    }
    println!("Zapdrop companion ready; receive approval is required for every job.");
    Ok(())
}

fn argument_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

pub fn negotiate_protocol(remote_versions: &[u32]) -> io::Result<u32> {
    SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .rev()
        .find(|version| remote_versions.contains(version))
        .copied()
        .ok_or_else(|| invalid("no mutually supported Zapdrop protocol version"))
}

pub fn validate_relative_path(path: &str) -> io::Result<()> {
    if path.is_empty()
        || path.len() > MAX_RELATIVE_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        || path.chars().any(|character| character.is_control())
    {
        return Err(invalid("unsafe companion relative path"));
    }
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_highest_common_protocol_version() {
        assert_eq!(negotiate_protocol(&[1, 2]).unwrap(), 2);
        assert_eq!(negotiate_protocol(&[1]).unwrap(), 1);
        assert!(negotiate_protocol(&[3]).is_err());
    }

    #[test]
    fn rejects_companion_path_traversal() {
        validate_relative_path("folder/file.txt").unwrap();
        assert!(validate_relative_path("../escape").is_err());
        assert!(validate_relative_path("folder\\file.txt").is_err());
        assert!(validate_relative_path("folder//file.txt").is_err());
    }
}
