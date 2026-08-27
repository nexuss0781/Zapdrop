use serde::Serialize;
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub modified: u64,
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerLocation {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedSource {
    pub path: String,
    pub name: String,
    pub kind: String,
    pub size: u64,
}

pub fn list_directory(path: Option<String>) -> Result<ExplorerLocation, String> {
    let requested = path.map(PathBuf::from).unwrap_or_else(home_directory);
    let directory = canonical_directory(&requested).map_err(|error| error.to_string())?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).map_err(|error| error.to_string())?;
        let file_type = metadata.file_type();
        let kind = if file_type.is_symlink() {
            "symlink"
        } else if metadata.is_dir() {
            "folder"
        } else if metadata.is_file() {
            "file"
        } else {
            "other"
        };
        let name = entry.file_name().to_string_lossy().to_string();
        entries.push(DirectoryEntry {
            hidden: name.starts_with('.'),
            name,
            path: entry_path.to_string_lossy().to_string(),
            kind: kind.to_string(),
            size: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
            modified: metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| value.as_secs())
                .unwrap_or_default(),
        });
    }
    entries.sort_by_key(|entry| (entry.kind != "folder", entry.name.to_lowercase()));
    Ok(ExplorerLocation {
        parent: directory
            .parent()
            .map(|value| value.to_string_lossy().to_string()),
        path: directory.to_string_lossy().to_string(),
        entries,
    })
}

pub fn inspect_sources(paths: Vec<String>) -> Result<Vec<SelectedSource>, String> {
    if paths.is_empty() {
        return Err("select at least one file or folder".to_string());
    }
    let mut selected = Vec::with_capacity(paths.len());
    for value in paths {
        let path = canonical_existing(Path::new(&value)).map_err(|error| error.to_string())?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "symbolic links are not supported: {}",
                path.display()
            ));
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(format!("not a file or folder: {}", path.display()));
        }
        selected.push(SelectedSource {
            name: path
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string()),
            path: path.to_string_lossy().to_string(),
            kind: if metadata.is_dir() { "folder" } else { "file" }.to_string(),
            size: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
        });
    }
    Ok(selected)
}

fn home_directory() -> PathBuf {
    directories::BaseDirs::new()
        .map(|value| value.home_dir().to_path_buf())
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn canonical_directory(path: &Path) -> io::Result<PathBuf> {
    let canonical = canonical_existing(path)?;
    if !canonical.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a directory",
        ));
    }
    Ok(canonical)
}

fn canonical_existing(path: &Path) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path cannot be empty",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "symbolic links are not supported",
        ));
    }
    fs::canonicalize(path)
}

#[cfg(test)]
mod tests {
    use super::{inspect_sources, list_directory};
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_sources() {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("zapdrop-explorer-link-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("note.txt"), b"hello").unwrap();
        symlink(root.join("note.txt"), root.join("link.txt")).unwrap();
        assert!(
            inspect_sources(vec![root.join("link.txt").to_string_lossy().to_string()]).is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn lists_directory_and_inspects_regular_file() {
        let root = std::env::temp_dir().join(format!("zapdrop-explorer-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("folder")).unwrap();
        fs::write(root.join("note.txt"), b"hello").unwrap();
        let location = list_directory(Some(root.to_string_lossy().to_string())).unwrap();
        assert_eq!(location.entries.len(), 2);
        let selected =
            inspect_sources(vec![root.join("note.txt").to_string_lossy().to_string()]).unwrap();
        assert_eq!(selected[0].kind, "file");
        fs::remove_dir_all(root).unwrap();
    }
}
