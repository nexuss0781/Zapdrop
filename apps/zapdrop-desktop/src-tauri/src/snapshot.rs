use crate::swarm::{
    ChunkProfile, DirectoryEntry, DirectoryNode, FileObject, ObjectKind, PieceDescriptor,
    SnapshotRoot, SWARM_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use unicode_normalization::UnicodeNormalization;

pub const DEFAULT_SNAPSHOT_PAGE_BYTES: usize = 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const DEFAULT_DISK_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JOURNAL_RANGES: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct SnapshotSource {
    pub path: PathBuf,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceGeneration {
    pub size: u64,
    pub modified_at_nanos: u128,
    pub sha256: String,
}

pub fn capture_source_generation(path: &Path) -> io::Result<SourceGeneration> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("source generation requires a regular file"));
    }
    Ok(SourceGeneration {
        size: metadata.len(),
        modified_at_nanos: modified_at_nanos(path)?,
        sha256: hash_file(path)?,
    })
}

pub fn verify_source_generation(path: &Path, expected: &SourceGeneration) -> io::Result<()> {
    let current = capture_source_generation(path)?;
    if current != *expected {
        return Err(invalid("source changed since snapshot creation"));
    }
    Ok(())
}

pub fn disk_space_preflight(
    destination: &Path,
    required_bytes: u64,
    reserve_bytes: Option<u64>,
) -> io::Result<u64> {
    let available = fs2::available_space(destination).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("unable to query destination free space: {error}"),
        )
    })?;
    let reserve = reserve_bytes.unwrap_or(DEFAULT_DISK_RESERVE_BYTES);
    let required = required_bytes
        .checked_add(reserve)
        .ok_or_else(|| invalid("disk-space requirement overflow"))?;
    if available < required {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("insufficient destination space: need {required}, have {available}"),
        ));
    }
    Ok(available)
}

#[derive(Debug, Clone)]
pub struct SnapshotOptions {
    pub chunk_profile: ChunkProfile,
    pub page_bytes: usize,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            chunk_profile: ChunkProfile::default(),
            page_bytes: DEFAULT_SNAPSHOT_PAGE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PieceIndexPage {
    pub kind: String,
    pub version: u32,
    pub page_id: String,
    pub file_object_id: String,
    pub pieces: Vec<PieceDescriptor>,
    pub next_page: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotBuildResult {
    pub root: SnapshotRoot,
    pub directories: Vec<DirectoryNode>,
    pub files: Vec<FileObject>,
    pub piece_pages: Vec<PieceIndexPage>,
    pub subtree_cache: Vec<SubtreeCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotObjectRef {
    pub kind: String,
    pub object_id: String,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotMetadataPage {
    pub kind: String,
    pub version: u32,
    pub page_id: String,
    pub objects: Vec<SnapshotObjectRef>,
    pub next_page: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubtreeCacheEntry {
    pub relative_path: String,
    pub object_id: String,
    pub modified_at_nanos: u128,
    pub total_bytes: u64,
    pub total_files: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SubtreeReuseIndex {
    entries: HashMap<String, SubtreeCacheEntry>,
}

impl SubtreeReuseIndex {
    pub fn from_snapshot(snapshot: &SnapshotBuildResult) -> Self {
        Self {
            entries: snapshot
                .subtree_cache
                .iter()
                .cloned()
                .map(|entry| (entry.relative_path.clone(), entry))
                .collect(),
        }
    }

    pub fn reusable(
        &self,
        relative_path: &str,
        modified_at_nanos: u128,
    ) -> Option<&SubtreeCacheEntry> {
        self.entries
            .get(relative_path)
            .filter(|entry| entry.modified_at_nanos == modified_at_nanos)
    }
}

pub fn build_metadata_pages(
    snapshot: &SnapshotBuildResult,
    page_bytes: usize,
) -> io::Result<Vec<SnapshotMetadataPage>> {
    if !(4 * 1024..=16 * 1024 * 1024).contains(&page_bytes) {
        return Err(invalid("metadata page size is outside the supported range"));
    }
    let mut objects = Vec::new();
    objects.extend(snapshot.directories.iter().map(|node| {
        SnapshotObjectRef {
            kind: "directory".to_string(),
            object_id: node.object_id.clone(),
            byte_len: serde_json::to_vec(node)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0),
        }
    }));
    objects.extend(snapshot.files.iter().map(|file| {
        SnapshotObjectRef {
            kind: "file".to_string(),
            object_id: file.object_id.clone(),
            byte_len: serde_json::to_vec(file)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0),
        }
    }));
    objects.extend(snapshot.piece_pages.iter().map(|page| {
        SnapshotObjectRef {
            kind: "piece-index".to_string(),
            object_id: page.page_id.clone(),
            byte_len: serde_json::to_vec(page)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0),
        }
    }));
    let mut groups = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = metadata_page_base_size(true);
    for object in objects {
        let object_bytes = serde_json::to_vec(&object).map_err(invalid)?.len();
        let added = object_bytes + usize::from(!current.is_empty());
        if current.is_empty() && current_bytes + added > page_bytes {
            return Err(invalid("metadata object cannot fit in a page"));
        }
        if !current.is_empty() && current_bytes + added > page_bytes {
            groups.push(current);
            current = Vec::new();
            current_bytes = metadata_page_base_size(true);
        }
        current.push(object);
        current_bytes += added;
    }
    if !current.is_empty() {
        groups.push(current);
    }
    let mut pages = Vec::with_capacity(groups.len());
    let mut next = None;
    for objects in groups.into_iter().rev() {
        let mut page = SnapshotMetadataPage {
            kind: "zapdrop_snapshot_metadata_page".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            page_id: "pending".to_string(),
            objects,
            next_page: next.clone(),
        };
        page.page_id = digest_json(&page)?;
        next = Some(page.page_id.clone());
        pages.push(page);
    }
    pages.reverse();
    Ok(pages)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JournalItem {
    pub object_id: String,
    pub source_sha256: String,
    pub destination_path: String,
    pub verified_ranges: Vec<ByteRange>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TransferJournal {
    pub kind: String,
    pub version: u32,
    pub job_id: String,
    pub snapshot_root: String,
    pub updated_at: u64,
    pub items: Vec<JournalItem>,
}

pub fn build_snapshot(
    sources: &[SnapshotSource],
    options: &SnapshotOptions,
) -> io::Result<SnapshotBuildResult> {
    if sources.is_empty() {
        return Err(invalid("at least one snapshot source is required"));
    }
    options
        .chunk_profile
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if !(4 * 1024..=16 * 1024 * 1024).contains(&options.page_bytes) {
        return Err(invalid("snapshot page size is outside the supported range"));
    }

    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut piece_pages = Vec::new();
    let mut subtree_cache = Vec::new();
    let mut root_entries = Vec::new();
    let mut names = HashSet::new();
    let mut total_bytes = 0u64;
    let mut total_files = 0u64;

    for source in sources {
        let relative = normalize_relative_path(&source.relative_path)?;
        let name = relative
            .rsplit('/')
            .next()
            .ok_or_else(|| invalid("snapshot source has no final component"))?
            .to_string();
        if !names.insert(name.clone()) {
            return Err(invalid("duplicate snapshot source path"));
        }
        let metadata = fs::symlink_metadata(&source.path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("symbolic links are not supported in snapshots"));
        }
        let (kind, size, object_id) = if metadata.is_dir() {
            let (node, bytes, count) = build_directory(
                &source.path,
                &relative,
                &options.chunk_profile,
                options.page_bytes,
                &mut directories,
                &mut files,
                &mut piece_pages,
                &mut subtree_cache,
            )?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("snapshot size overflow"))?;
            total_files = total_files
                .checked_add(count)
                .ok_or_else(|| invalid("snapshot file count overflow"))?;
            (ObjectKind::Directory, 0, node.object_id)
        } else if metadata.is_file() {
            let (file, pages) = build_file(
                &source.path,
                &relative,
                &options.chunk_profile,
                options.page_bytes,
            )?;
            total_bytes = total_bytes
                .checked_add(file.size)
                .ok_or_else(|| invalid("snapshot size overflow"))?;
            total_files += 1;
            let object_id = file.object_id.clone();
            piece_pages.extend(pages);
            files.push(file);
            (ObjectKind::File, metadata.len(), object_id)
        } else {
            return Err(invalid("unsupported snapshot source type"));
        };
        root_entries.push(DirectoryEntry {
            name,
            kind,
            size,
            object_id,
        });
    }

    root_entries.sort_by(|left, right| left.name.cmp(&right.name));
    let root_node = make_directory_node(root_entries)?;
    directories.push(root_node.clone());
    subtree_cache.push(SubtreeCacheEntry {
        relative_path: String::new(),
        object_id: root_node.object_id.clone(),
        modified_at_nanos: 0,
        total_bytes,
        total_files,
    });
    let node_count = directories.len() as u64 + files.len() as u64 + piece_pages.len() as u64;
    Ok(SnapshotBuildResult {
        root: SnapshotRoot {
            kind: "zapdrop_snapshot_root".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            root_id: root_node.object_id,
            node_count,
            total_bytes,
            total_files,
            chunk_profile_id: options.chunk_profile.profile_id.clone(),
            created_at: epoch_seconds(),
            signature: String::new(),
        },
        directories,
        files,
        piece_pages,
        subtree_cache,
    })
}

fn build_directory(
    path: &Path,
    relative: &str,
    profile: &ChunkProfile,
    page_bytes: usize,
    directories: &mut Vec<DirectoryNode>,
    files: &mut Vec<FileObject>,
    piece_pages: &mut Vec<PieceIndexPage>,
    subtree_cache: &mut Vec<SubtreeCacheEntry>,
) -> io::Result<(DirectoryNode, u64, u64)> {
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    for child in fs::read_dir(path)? {
        let child = child?;
        let name = normalize_component(child.file_name().as_os_str())?;
        if !names.insert(name.clone()) {
            return Err(invalid("Unicode normalization produced duplicate names"));
        }
        let child_path = child.path();
        let child_relative = format!("{relative}/{name}");
        let metadata = fs::symlink_metadata(&child_path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("symbolic links are not supported in snapshots"));
        }
        let (kind, size, object_id) = if metadata.is_dir() {
            let (node, bytes, count) = build_directory(
                &child_path,
                &child_relative,
                profile,
                page_bytes,
                directories,
                files,
                piece_pages,
                subtree_cache,
            )?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("snapshot size overflow"))?;
            total_files = total_files
                .checked_add(count)
                .ok_or_else(|| invalid("snapshot file count overflow"))?;
            (ObjectKind::Directory, 0, node.object_id)
        } else if metadata.is_file() {
            let (file, pages) = build_file(&child_path, &child_relative, profile, page_bytes)?;
            total_bytes = total_bytes
                .checked_add(file.size)
                .ok_or_else(|| invalid("snapshot size overflow"))?;
            total_files += 1;
            let object_id = file.object_id.clone();
            piece_pages.extend(pages);
            files.push(file);
            (ObjectKind::File, metadata.len(), object_id)
        } else {
            return Err(invalid("unsupported filesystem entry type"));
        };
        entries.push(DirectoryEntry {
            name,
            kind,
            size,
            object_id,
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let node = make_directory_node(entries)?;
    directories.push(node.clone());
    subtree_cache.push(SubtreeCacheEntry {
        relative_path: relative.to_string(),
        object_id: node.object_id.clone(),
        modified_at_nanos: modified_at_nanos(path)?,
        total_bytes,
        total_files,
    });
    Ok((node, total_bytes, total_files))
}

fn make_directory_node(entries: Vec<DirectoryEntry>) -> io::Result<DirectoryNode> {
    let mut node = DirectoryNode {
        kind: "zapdrop_directory_node".to_string(),
        version: SWARM_PROTOCOL_VERSION,
        object_id: "pending".to_string(),
        entries,
    };
    node.validate()
        .map_err(|error| invalid(error.to_string()))?;
    node.object_id = digest_json(&node)?;
    Ok(node)
}

fn build_file(
    path: &Path,
    relative: &str,
    profile: &ChunkProfile,
    page_bytes: usize,
) -> io::Result<(FileObject, Vec<PieceIndexPage>)> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut file_hasher = Sha256::new();
    let mut descriptors = Vec::new();
    let mut offset = 0u64;
    let mut index = 0u64;
    let mut buffer = vec![0u8; profile.piece_size as usize];
    while offset < size {
        let target = (size - offset).min(profile.piece_size) as usize;
        let mut read_total = 0usize;
        while read_total < target {
            let read = file.read(&mut buffer[read_total..target])?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "source changed while indexing",
                ));
            }
            read_total += read;
        }
        file_hasher.update(&buffer[..read_total]);
        let sha256 = digest_bytes(&buffer[..read_total]);
        descriptors.push(PieceDescriptor {
            piece_id: digest_bytes(
                format!("piece:{index}:{offset}:{read_total}:{sha256}").as_bytes(),
            ),
            object_id: "pending".to_string(),
            index,
            offset,
            length: read_total as u64,
            sha256,
        });
        offset += read_total as u64;
        index += 1;
    }
    if file.metadata()?.len() != size {
        return Err(invalid("source changed while indexing"));
    }
    let sha256 = format_digest(file_hasher.finalize().as_slice());
    let object_id =
        digest_bytes(format!("file:{relative}:{size}:{sha256}:{}", profile.profile_id).as_bytes());
    for descriptor in &mut descriptors {
        descriptor.object_id = object_id.clone();
    }
    let (pages, first_page) = build_piece_pages(&object_id, descriptors, page_bytes)?;
    let file_object = FileObject {
        kind: "zapdrop_file_object".to_string(),
        version: SWARM_PROTOCOL_VERSION,
        object_id,
        relative_path: relative.to_string(),
        size,
        sha256,
        piece_count: size.div_ceil(profile.piece_size),
        piece_index_page: first_page,
    };
    file_object
        .validate(profile)
        .map_err(|error| invalid(error.to_string()))?;
    Ok((file_object, pages))
}

fn build_piece_pages(
    file_object_id: &str,
    descriptors: Vec<PieceDescriptor>,
    page_bytes: usize,
) -> io::Result<(Vec<PieceIndexPage>, String)> {
    if descriptors.is_empty() {
        return Ok((Vec::new(), String::new()));
    }
    let mut groups = Vec::<Vec<PieceDescriptor>>::new();
    let mut current = Vec::new();
    let mut current_bytes = 2usize;
    for descriptor in descriptors {
        let descriptor_bytes = serde_json::to_vec(&descriptor).map_err(invalid)?.len();
        let added = descriptor_bytes + usize::from(!current.is_empty());
        if descriptor_bytes + 2 > page_bytes {
            return Err(invalid("piece descriptor cannot fit in an index page"));
        }
        if !current.is_empty() && current_bytes + added > page_bytes {
            groups.push(current);
            current = Vec::new();
            current_bytes = 2;
        }
        current.push(descriptor);
        current_bytes += descriptor_bytes + usize::from(current.len() > 1);
    }
    if !current.is_empty() {
        groups.push(current);
    }

    let mut pages = Vec::with_capacity(groups.len());
    let mut next = None;
    for pieces in groups.into_iter().rev() {
        let mut page = PieceIndexPage {
            kind: "zapdrop_piece_index_page".to_string(),
            version: SWARM_PROTOCOL_VERSION,
            page_id: "pending".to_string(),
            file_object_id: file_object_id.to_string(),
            pieces,
            next_page: next.clone(),
        };
        page.page_id = digest_json(&page)?;
        next = Some(page.page_id.clone());
        pages.push(page);
    }
    pages.reverse();
    Ok((pages, next.expect("non-empty page list")))
}

pub fn normalize_component(value: &OsStr) -> io::Result<String> {
    let raw = value
        .to_str()
        .ok_or_else(|| invalid("path is not valid UTF-8"))?;
    let normalized: String = raw.nfc().collect();
    if normalized.is_empty()
        || normalized == "."
        || normalized == ".."
        || normalized.contains('/')
        || normalized.contains('\\')
        || normalized.chars().any(char::is_control)
    {
        return Err(invalid("invalid normalized path component"));
    }
    Ok(normalized)
}

pub fn normalize_relative_path(value: &str) -> io::Result<String> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') {
        return Err(invalid("invalid relative snapshot path"));
    }
    let components = value
        .split('/')
        .map(|component| normalize_component(OsStr::new(component)))
        .collect::<io::Result<Vec<_>>>()?;
    if components.is_empty() {
        return Err(invalid("empty relative snapshot path"));
    }
    Ok(components.join("/"))
}

impl TransferJournal {
    pub fn new(job_id: String, snapshot_root: String) -> Self {
        Self {
            kind: "zapdrop_transfer_journal".to_string(),
            version: 1,
            job_id,
            snapshot_root,
            updated_at: epoch_seconds(),
            items: Vec::new(),
        }
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let journal: Self = serde_json::from_slice(&bytes).map_err(invalid)?;
        if journal.kind != "zapdrop_transfer_journal" || journal.version != 1 {
            return Err(invalid("unsupported transfer journal"));
        }
        if journal
            .items
            .iter()
            .map(|item| item.verified_ranges.len())
            .sum::<usize>()
            > MAX_JOURNAL_RANGES
        {
            return Err(invalid("transfer journal range limit exceeded"));
        }
        Ok(journal)
    }

    pub fn save_atomic(&mut self, path: &Path) -> io::Result<()> {
        self.updated_at = epoch_seconds();
        let bytes = serde_json::to_vec_pretty(self).map_err(invalid)?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("journal has no parent directory"))?;
        fs::create_dir_all(parent)?;
        let temp = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temp, path)?;
        Ok(())
    }

    pub fn mark_verified(
        &mut self,
        object_id: &str,
        source_sha256: &str,
        destination_path: &str,
        range: ByteRange,
    ) -> io::Result<()> {
        if range.length == 0
            || self
                .items
                .iter()
                .map(|item| item.verified_ranges.len())
                .sum::<usize>()
                >= MAX_JOURNAL_RANGES
        {
            return Err(invalid("transfer journal range limit exceeded"));
        }
        let index = if let Some(index) = self
            .items
            .iter()
            .position(|item| item.object_id == object_id)
        {
            index
        } else {
            self.items.push(JournalItem {
                object_id: object_id.to_string(),
                source_sha256: source_sha256.to_string(),
                destination_path: destination_path.to_string(),
                verified_ranges: Vec::new(),
                complete: false,
            });
            self.items.len() - 1
        };
        self.items[index].verified_ranges.push(range);
        Ok(())
    }

    pub fn mark_complete(&mut self, object_id: &str, source_sha256: &str, destination_path: &str) {
        if let Some(item) = self
            .items
            .iter_mut()
            .find(|item| item.object_id == object_id)
        {
            item.source_sha256 = source_sha256.to_string();
            item.destination_path = destination_path.to_string();
            item.complete = true;
        }
    }

    pub fn reset_item(&mut self, object_id: &str) {
        self.items.retain(|item| item.object_id != object_id);
    }

    pub fn verified_bytes(&self, object_id: &str, total_bytes: u64) -> u64 {
        total_bytes.saturating_sub(
            self.missing_ranges(object_id, total_bytes, total_bytes.max(1))
                .map(|ranges| ranges.iter().map(|range| range.length).sum())
                .unwrap_or(total_bytes),
        )
    }

    pub fn contiguous_offset(&self, object_id: &str, total_bytes: u64) -> u64 {
        let Some(item) = self.items.iter().find(|item| item.object_id == object_id) else {
            return 0;
        };
        let mut ranges = item.verified_ranges.clone();
        ranges.sort_by_key(|range| range.offset);
        let mut cursor = 0u64;
        for range in ranges {
            if range.offset > cursor {
                break;
            }
            cursor = cursor.max(range.offset.saturating_add(range.length));
            if cursor >= total_bytes {
                return total_bytes;
            }
        }
        cursor.min(total_bytes)
    }

    pub fn missing_ranges(
        &self,
        object_id: &str,
        total_bytes: u64,
        piece_size: u64,
    ) -> io::Result<Vec<ByteRange>> {
        if piece_size == 0 {
            return Err(invalid("piece size cannot be zero"));
        }
        let Some(item) = self.items.iter().find(|item| item.object_id == object_id) else {
            return Ok(vec![ByteRange {
                offset: 0,
                length: total_bytes,
            }]);
        };
        let mut ranges = item.verified_ranges.clone();
        ranges.sort_by_key(|range| range.offset);
        let mut cursor = 0u64;
        let mut missing = Vec::new();
        for range in ranges {
            let start = range.offset.min(total_bytes);
            if start > cursor {
                missing.push(ByteRange {
                    offset: cursor,
                    length: start - cursor,
                });
            }
            cursor = cursor.max(start.saturating_add(range.length).min(total_bytes));
        }
        if cursor < total_bytes {
            missing.push(ByteRange {
                offset: cursor,
                length: total_bytes - cursor,
            });
        }
        Ok(missing
            .into_iter()
            .flat_map(|range| split_range(range, piece_size))
            .collect())
    }
}

fn split_range(range: ByteRange, piece_size: u64) -> Vec<ByteRange> {
    let mut result = Vec::new();
    let mut offset = range.offset;
    let end = range.offset.saturating_add(range.length);
    while offset < end {
        let length = (end - offset).min(piece_size);
        result.push(ByteRange { offset, length });
        offset = offset.saturating_add(length);
    }
    result
}

pub fn journal_path(root: &Path, job_id: &str) -> PathBuf {
    root.join(".zapdrop-journals")
        .join(format!("job-{}.json", digest_bytes(job_id.as_bytes())))
}

fn metadata_page_base_size(has_next: bool) -> usize {
    serde_json::to_vec(&SnapshotMetadataPage {
        kind: "zapdrop_snapshot_metadata_page".to_string(),
        version: SWARM_PROTOCOL_VERSION,
        page_id: "0".repeat(64),
        objects: Vec::new(),
        next_page: has_next.then(|| "0".repeat(64)),
    })
    .map(|bytes| bytes.len())
    .unwrap_or(usize::MAX)
}

fn digest_json<T: Serialize>(value: &T) -> io::Result<String> {
    Ok(digest_bytes(&serde_json::to_vec(value).map_err(invalid)?))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format_digest(Sha256::digest(bytes).as_slice())
}

fn format_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn modified_at_nanos(path: &Path) -> io::Result<u128> {
    let modified = fs::metadata(path)?.modified().unwrap_or(UNIX_EPOCH);
    Ok(modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos())
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_canonical_snapshot_and_pages() {
        let root = std::env::temp_dir().join(format!("zapdrop-snapshot-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("folder")).unwrap();
        fs::write(root.join("folder/b.txt"), b"b").unwrap();
        fs::write(root.join("folder/a.txt"), b"a").unwrap();
        let result = build_snapshot(
            &[SnapshotSource {
                path: root.join("folder"),
                relative_path: "folder".to_string(),
            }],
            &SnapshotOptions::default(),
        )
        .unwrap();
        assert_eq!(result.root.total_files, 2);
        assert_eq!(result.root.total_bytes, 2);
        assert_eq!(result.files.len(), 2);
        assert_eq!(result.piece_pages.len(), 2);
        assert!(result.files.iter().all(|file| !file.object_id.is_empty()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn normalizes_unicode_and_rejects_traversal() {
        assert_eq!(
            normalize_relative_path("e\u{301}/file.txt").unwrap(),
            "é/file.txt"
        );
        assert!(normalize_relative_path("../escape").is_err());
        assert!(normalize_relative_path("a\\b").is_err());
    }

    #[test]
    fn builds_bounded_metadata_pages_and_reuses_exact_subtree_generation() {
        let root = std::env::temp_dir().join(format!("zapdrop-metadata-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("folder")).unwrap();
        fs::write(root.join("folder/file.txt"), b"payload").unwrap();
        let snapshot = build_snapshot(
            &[SnapshotSource {
                path: root.join("folder"),
                relative_path: "folder".to_string(),
            }],
            &SnapshotOptions::default(),
        )
        .unwrap();
        let pages = build_metadata_pages(&snapshot, 4096).unwrap();
        assert!(!pages.is_empty());
        assert!(pages.iter().all(|page| page.page_id.len() == 64));
        let cache = SubtreeReuseIndex::from_snapshot(&snapshot);
        let entry = snapshot
            .subtree_cache
            .iter()
            .find(|entry| entry.relative_path == "folder")
            .unwrap();
        assert!(cache.reusable("folder", entry.modified_at_nanos).is_some());
        assert!(cache
            .reusable("folder", entry.modified_at_nanos.saturating_add(1))
            .is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qualifies_large_fixture_determinism_and_bounded_metadata() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-large-fixture-{}", uuid::Uuid::new_v4()));
        let fixture = root.join("fixture");
        fs::create_dir_all(&fixture).unwrap();
        for directory in 0..16 {
            fs::create_dir_all(fixture.join(format!("dir-{directory:02}"))).unwrap();
        }
        for index in 0..512 {
            let directory = fixture.join(format!("dir-{:02}", index % 16));
            let payload = vec![(index % 251) as u8; 4096];
            fs::write(directory.join(format!("file-{index:04}.bin")), payload).unwrap();
        }
        let options = SnapshotOptions {
            page_bytes: 64 * 1024,
            ..Default::default()
        };
        let first = build_snapshot(
            &[SnapshotSource {
                path: fixture.clone(),
                relative_path: "fixture".to_string(),
            }],
            &options,
        )
        .unwrap();
        assert_eq!(first.root.total_files, 512);
        assert_eq!(first.root.total_bytes, 512 * 4096);
        assert_eq!(first.files.len(), 512);
        assert!(first.piece_pages.len() >= 512);
        let metadata_pages = build_metadata_pages(&first, options.page_bytes).unwrap();
        assert!(metadata_pages.len() > 1);
        assert!(metadata_pages
            .iter()
            .all(|page| { serde_json::to_vec(page).unwrap().len() <= options.page_bytes }));

        let second = build_snapshot(
            &[SnapshotSource {
                path: fixture.clone(),
                relative_path: "fixture".to_string(),
            }],
            &options,
        )
        .unwrap();
        assert_eq!(first.root.root_id, second.root.root_id);
        assert_eq!(first.files[0].object_id, second.files[0].object_id);
        let cache = SubtreeReuseIndex::from_snapshot(&first);
        let subtree = first
            .subtree_cache
            .iter()
            .find(|entry| entry.relative_path == "fixture/dir-00")
            .unwrap();
        assert_eq!(
            cache
                .reusable(&subtree.relative_path, subtree.modified_at_nanos)
                .unwrap()
                .object_id,
            subtree.object_id
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persists_sparse_resume_ranges_for_large_file_fixture() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-sparse-fixture-{}", uuid::Uuid::new_v4()));
        let journal_path = root.join("nested/journal.json");
        let mut journal = TransferJournal::new("large-job".to_string(), "root-1".to_string());
        for offset in [0, 4 * 1024 * 1024, 8 * 1024 * 1024] {
            journal
                .mark_verified(
                    "large-object",
                    &"b".repeat(64),
                    "fixture/large.bin",
                    ByteRange {
                        offset,
                        length: 1024 * 1024,
                    },
                )
                .unwrap();
        }
        assert_eq!(
            journal.contiguous_offset("large-object", 12 * 1024 * 1024),
            1024 * 1024
        );
        assert_eq!(
            journal.verified_bytes("large-object", 12 * 1024 * 1024),
            3 * 1024 * 1024
        );
        journal.save_atomic(&journal_path).unwrap();
        let loaded = TransferJournal::load(&journal_path).unwrap();
        let missing = loaded
            .missing_ranges("large-object", 12 * 1024 * 1024, 1024 * 1024)
            .unwrap();
        assert_eq!(missing.first().unwrap().offset, 1024 * 1024);
        assert_eq!(missing.last().unwrap().offset, 11 * 1024 * 1024);
        assert_eq!(loaded.items[0].verified_ranges.len(), 3);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_source_mutation_and_preflights_destination_space() {
        let root =
            std::env::temp_dir().join(format!("zapdrop-generation-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source.bin");
        fs::write(&source, b"original").unwrap();
        let generation = capture_source_generation(&source).unwrap();
        disk_space_preflight(&root, 1, Some(1)).unwrap();
        fs::write(&source, b"changed").unwrap();
        assert!(verify_source_generation(&source, &generation).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn journal_exposes_contiguous_and_sparse_missing_ranges() {
        let mut journal = TransferJournal::new("job-1".to_string(), "root-1".to_string());
        journal
            .mark_verified(
                "object-1",
                "a".repeat(64).as_str(),
                "file.bin",
                ByteRange {
                    offset: 0,
                    length: 4,
                },
            )
            .unwrap();
        journal
            .mark_verified(
                "object-1",
                "a".repeat(64).as_str(),
                "file.bin",
                ByteRange {
                    offset: 8,
                    length: 4,
                },
            )
            .unwrap();
        assert_eq!(journal.contiguous_offset("object-1", 16), 4);
        assert_eq!(
            journal
                .missing_ranges("object-1", 16, 4)
                .unwrap()
                .iter()
                .map(|range| (range.offset, range.length))
                .collect::<Vec<_>>(),
            vec![(4, 4), (12, 4)]
        );
    }

    #[test]
    fn journal_round_trips_atomically() {
        let root = std::env::temp_dir().join(format!("zapdrop-journal-{}", uuid::Uuid::new_v4()));
        let path = root.join("nested/journal.json");
        let mut journal = TransferJournal::new("job-1".to_string(), "sha256:root".to_string());
        journal
            .mark_verified(
                "object-1",
                "a".repeat(64).as_str(),
                "file.txt",
                ByteRange {
                    offset: 0,
                    length: 4,
                },
            )
            .unwrap();
        journal.save_atomic(&path).unwrap();
        let loaded = TransferJournal::load(&path).unwrap();
        assert_eq!(loaded.items[0].verified_ranges[0].length, 4);
        fs::remove_dir_all(root).unwrap();
    }
}

#[allow(dead_code)]
fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format_digest(hasher.finalize().as_slice()))
}

#[allow(dead_code)]
fn verify_source_unchanged(path: &Path, expected: &str) -> io::Result<()> {
    if hash_file(path)? != expected {
        return Err(invalid("source changed since snapshot creation"));
    }
    Ok(())
}
