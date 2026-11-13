//! 修复可由序号证明的过期祖先 EOF 截止点；保留原始文件及全部解码字节位置。
use super::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    ops::Range,
    time::SystemTime,
};
use tempfile::{NamedTempFile, TempPath};

/// 元数据头的解析上限；正文始终以固定大小缓冲复制。
const HEADER_LIMIT: u64 = 1024 * 1024;

/// 一条已备份并暂存的修正，以及提交/回滚前必须保持的源文件身份。
struct Replacement {
    /// 当前实例原始 rollout 路径，同时也是原子发布的目标。
    path: PathBuf,
    /// 原始压缩或普通文件的只新增备份副本。
    backup: PathBuf,
    /// 与源文件处于同一目录的暂存文件，未发布时由 TempPath 自动清理。
    staged: TempPath,
    /// 原始文件 SHA256，用于确认回滚副本未被更改。
    original_hash: [u8; 32],
    /// 原始文件的身份、长度及时间戳，用于拒绝应用期间的外部替换。
    original_identity: files::Identity,
    original_length: u64,
    original_modified: SystemTime,
    /// 替换文件的身份、长度及时间戳，用于提交和回滚前核对当前路径。
    staged_identity: files::Identity,
    staged_length: u64,
    staged_modified: SystemTime,
    // 在替换及 SQLite 事务结束前保留读锁；Windows 拒绝其他句柄写入。
    _original: File,
    _replacement: File,
    /// 仅在原子替换成功后置 true，决定错误返回前哪些文件需要回滚。
    published: bool,
}

pub(super) struct Prepared {
    /// 本次经扫描证明可修复的文件，顺序用于提交，逆序用于回滚。
    replacements: Vec<Replacement>,
}

impl Prepared {
    /// 在任何源文件变化前备份原始压缩字节，并准备同目录的原子替换文件。
    ///
    /// `plan` 提供源哈希和已证明的 EOF 修正，`backup` 保存恢复副本，`budget`
    /// 限制备份与重编码时长；任一步失败均不发布暂存文件。
    pub fn new(plan: &Plan, backup: &Path, budget: &mut Budget) -> Result<Self, String> {
        let mut replacements = Vec::new();
        if !plan.lineage_repairs.is_empty() {
            fs::create_dir(backup.join("rollouts")).map_err(|e| error("BACKUP", e))?;
        }
        for repair in &plan.lineage_repairs {
            budget.check()?;
            let source = &plan.sources[&repair.source_id];
            let mut original = locked_read(&source.path)?;
            source.recheck(budget)?;
            let original_metadata = original.metadata().map_err(|e| error("IO", e))?;
            let filename = source
                .path
                .file_name()
                .ok_or_else(|| error("UNSAFE_PATH", "rollout has no filename"))?;
            let original_backup = backup.join("rollouts").join(filename);
            let mut output = private_new(&original_backup)?;
            let (_, hash) = copy_checked(&mut original, &mut output, budget)?;
            output.sync_all().map_err(|e| error("BACKUP", e))?;
            if hash != source.raw_hash() {
                return Err(error("CHANGED", "rollout changed while backing up lineage"));
            }
            let mut checksum = private_new(
                &original_backup.with_file_name(format!("{}.sha256", filename.to_string_lossy())),
            )?;
            writeln!(checksum, "{}  {}", hex(&hash), filename.to_string_lossy())
                .map_err(|e| error("BACKUP", e))?;
            checksum.sync_all().map_err(|e| error("BACKUP", e))?;
            let parent = source
                .path
                .parent()
                .ok_or_else(|| error("UNSAFE_PATH", "rollout has no directory"))?;
            let mut staged = NamedTempFile::new_in(parent).map_err(|e| error("IO", e))?;
            let input = File::open(&source.path).map_err(|e| error("IO", e))?;
            let decoded: Box<dyn Read> = if source.path.extension().is_some_and(|e| e == "zst") {
                let mut decoder = zstd::stream::read::Decoder::new(input)
                    .map_err(|e| error("UNSAFE_HISTORY", e))?;
                decoder
                    .window_log_max(27)
                    .map_err(|e| error("UNSAFE_HISTORY", e))?;
                Box::new(decoder)
            } else {
                Box::new(input)
            };
            let mut reader = BufReader::new(decoded);
            let mut header = Vec::new();
            // 仅检查第一个非空 JSONL 头；正文经流式复制，既不重排也不重新序列化。
            loop {
                let mut line = Vec::new();
                let remaining = HEADER_LIMIT.saturating_sub(header.len() as u64);
                let count = reader
                    .by_ref()
                    .take(remaining + 1)
                    .read_until(b'\n', &mut line)
                    .map_err(|e| error("IO", e))?;
                header.extend_from_slice(&line);
                if count == 0 || header.len() as u64 > HEADER_LIMIT || line.last() != Some(&b'\n') {
                    return Err(error(
                        "UNSAFE_HISTORY",
                        "lineage metadata is incomplete or exceeds 1 MiB",
                    ));
                }
                if !line.iter().all(u8::is_ascii_whitespace) {
                    break;
                }
            }
            patch_cutoff(&mut header, repair)?;
            let copied = if source.path.extension().is_some_and(|e| e == "zst") {
                let mut encoder = zstd::stream::write::Encoder::new(staged.as_file_mut(), 0)
                    .map_err(|e| error("IO", e))?;
                encoder.write_all(&header).map_err(|e| error("IO", e))?;
                let (count, _) = copy_checked(&mut reader, &mut encoder, budget)?;
                encoder.finish().map_err(|e| error("IO", e))?;
                count
            } else {
                staged.write_all(&header).map_err(|e| error("IO", e))?;
                copy_checked(&mut reader, staged.as_file_mut(), budget)?.0
            };
            if header.len() as u64 + copied != source.decoded_bytes {
                return Err(error(
                    "CHANGED",
                    "rollout decoded length changed while preparing lineage",
                ));
            }
            staged.as_file().sync_all().map_err(|e| error("IO", e))?;
            source.check_stamp()?;
            let staged = staged.into_temp_path();
            let replacement = locked_read(&staged)?;
            let metadata = replacement.metadata().map_err(|e| error("IO", e))?;
            replacements.push(Replacement {
                path: source.path.clone(),
                backup: original_backup,
                staged_identity: files::identity(&staged)?,
                staged_length: metadata.len(),
                staged_modified: metadata.modified().map_err(|e| error("IO", e))?,
                staged,
                original_hash: source.raw_hash(),
                original_identity: files::identity(&source.path)?,
                original_length: original_metadata.len(),
                original_modified: original_metadata.modified().map_err(|e| error("IO", e))?,
                _original: original,
                _replacement: replacement,
                published: false,
            });
        }
        Ok(Self { replacements })
    }

    /// 在 SQLite 写事务提交前发布全部修正；调用方负责在错误时恢复原文件。
    pub fn publish(&mut self) -> Result<(), String> {
        for replacement in &mut self.replacements {
            // 持有原文件读锁期间仍核对路径身份，拒绝压缩或迁移造成的外部替换。
            let current = fs::metadata(&replacement.path).map_err(|e| error("CHANGED", e))?;
            if files::identity(&replacement.path)? != replacement.original_identity
                || current.len() != replacement.original_length
                || current.modified().map_err(|e| error("CHANGED", e))?
                    != replacement.original_modified
            {
                return Err(error(
                    "CHANGED",
                    "lineage source changed before replacement",
                ));
            }
            fs::rename(&replacement.staged, &replacement.path).map_err(|e| error("IO", e))?;
            replacement.published = true;
            sync_parent(&replacement.path)?;
        }
        Ok(())
    }

    /// 提交前区分已替换文件与只读祖先，核对各自对应的文件身份和时间戳。
    pub fn check_sources(&self, plan: &Plan) -> Result<(), String> {
        for source in plan.sources.values() {
            if let Some(replacement) = self
                .replacements
                .iter()
                .find(|r| r.published && r.path == source.path)
            {
                replacement.check_published()?;
            } else {
                source.check_stamp()?;
            }
        }
        Ok(())
    }

    /// SQLite 失败后逐个恢复原始字节；若路径已被外部替换则保留备份并拒绝覆盖。
    pub fn rollback(&mut self) -> Result<(), String> {
        for replacement in self.replacements.iter_mut().rev().filter(|r| r.published) {
            replacement
                .check_published()
                .map_err(|e| error("ROLLBACK", e))?;
            let parent = replacement
                .path
                .parent()
                .ok_or_else(|| error("ROLLBACK", "rollout has no directory"))?;
            let mut restored = NamedTempFile::new_in(parent).map_err(|e| error("ROLLBACK", e))?;
            let mut original = File::open(&replacement.backup).map_err(|e| error("ROLLBACK", e))?;
            let mut hasher = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = [0; 64 * 1024];
            // 即使主操作预算用尽，也完成有限的原始文件恢复；不读取超出原始长度的备份。
            loop {
                let count = Read::by_ref(&mut original)
                    .take(replacement.original_length.saturating_sub(copied) + 1)
                    .read(&mut buffer)
                    .map_err(|e| error("ROLLBACK", e))?;
                if count == 0 {
                    break;
                }
                copied += count as u64;
                if copied > replacement.original_length {
                    return Err(error("ROLLBACK", "original rollout backup length changed"));
                }
                hasher.update(&buffer[..count]);
                restored
                    .write_all(&buffer[..count])
                    .map_err(|e| error("ROLLBACK", e))?;
            }
            if copied != replacement.original_length
                || <[u8; 32]>::from(hasher.finalize()) != replacement.original_hash
            {
                return Err(error(
                    "ROLLBACK",
                    "original rollout backup checksum changed",
                ));
            }
            restored
                .as_file()
                .sync_all()
                .map_err(|e| error("ROLLBACK", e))?;
            let restored = restored.into_temp_path();
            fs::rename(&restored, &replacement.path).map_err(|e| error("ROLLBACK", e))?;
            replacement.published = false;
            sync_parent(&replacement.path)?;
        }
        Ok(())
    }
}

impl Replacement {
    fn check_published(&self) -> Result<(), String> {
        let metadata = fs::metadata(&self.path).map_err(|e| error("CHANGED", e))?;
        if files::identity(&self.path)? != self.staged_identity
            || metadata.len() != self.staged_length
            || metadata.modified().map_err(|e| error("CHANGED", e))? != self.staged_modified
        {
            return Err(error(
                "CHANGED",
                "repaired lineage rollout changed before commit",
            ));
        }
        Ok(())
    }
}

fn locked_read(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
        // 允许同目录原子替换，拒绝其他进程在源或替换文件上打开写句柄。
        options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0);
    }
    let file = options.open(path).map_err(|e| error("BUSY", e))?;
    #[cfg(not(windows))]
    fs2::FileExt::try_lock_exclusive(&file).map_err(|e| error("BUSY", e))?;
    Ok(file)
}

fn private_new(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| error("BACKUP", e))
}

fn copy_checked(
    input: &mut impl Read,
    output: &mut impl Write,
    budget: &Budget,
) -> Result<(u64, [u8; 32]), String> {
    let mut hash = Sha256::new();
    let mut copied = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        budget.check()?;
        let count = input.read(&mut buffer).map_err(|e| error("IO", e))?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|e| error("IO", e))?;
        hash.update(&buffer[..count]);
        copied += count as u64;
    }
    Ok((copied, hash.finalize().into()))
}

fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        File::open(
            path.parent()
                .ok_or_else(|| error("IO", "rollout has no directory"))?,
        )
        .and_then(|f| f.sync_all())
        .map_err(|e| error("IO", e))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// 只改 history_base 的数字 token，用空格补齐旧宽度，所有后续记录 byte offset 保持不变。
fn patch_cutoff(header: &mut [u8], repair: &files::LineageRepair) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_slice(header).map_err(|e| error("UNSAFE_HISTORY", e))?;
    if value["type"] != "session_meta"
        || value["payload"]["history_base"]["end_byte_offset"].as_u64()
            != Some(repair.previous_offset)
    {
        return Err(error("CHANGED", "lineage cutoff changed since scan"));
    }
    let payload = member(header, 0..header.len(), "payload")?;
    let base = member(header, payload, "history_base")?;
    let token = member(header, base, "end_byte_offset")?;
    let previous = serde_json::from_slice::<u64>(&header[token.clone()])
        .map_err(|e| error("UNSAFE_HISTORY", e))?;
    let next = repair.repaired_offset.to_string();
    if previous != repair.previous_offset || next.len() > token.len() {
        return Err(error(
            "UNSAFE_HISTORY",
            "lineage cutoff cannot preserve its original byte span",
        ));
    }
    header[token.clone()].fill(b' ');
    header[token.start..token.start + next.len()].copy_from_slice(next.as_bytes());
    Ok(())
}

fn skip_space(input: &[u8], mut at: usize, end: usize) -> usize {
    while at < end && input[at].is_ascii_whitespace() {
        at += 1;
    }
    at
}

// 输入已由 serde 完整验证；这里只定位原始 token，避免重新序列化会话元数据。
fn value_end(input: &[u8], start: usize, end: usize) -> Result<usize, String> {
    let mut at = start;
    let mut depth = 0;
    let mut string = false;
    let mut escaped = false;
    while at < end {
        let byte = input[at];
        if string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
                if depth == 0 {
                    return Ok(at + 1);
                }
            }
        } else {
            match byte {
                b'"' => string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    if depth == 0 {
                        return Ok(at);
                    }
                    depth -= 1;
                    if depth == 0 {
                        return Ok(at + 1);
                    }
                }
                b',' if depth == 0 => return Ok(at),
                b if b.is_ascii_whitespace() && depth == 0 => return Ok(at),
                _ => {}
            }
        }
        at += 1;
    }
    Ok(at)
}

fn member(input: &[u8], object: Range<usize>, name: &str) -> Result<Range<usize>, String> {
    let mut at = skip_space(input, object.start, object.end);
    if input.get(at) != Some(&b'{') {
        return Err(error("UNSAFE_HISTORY", "lineage metadata is not an object"));
    }
    at += 1;
    let mut found = None;
    loop {
        at = skip_space(input, at, object.end);
        if input.get(at) == Some(&b'}') {
            break;
        }
        let key_end = value_end(input, at, object.end)?;
        let key: String =
            serde_json::from_slice(&input[at..key_end]).map_err(|e| error("UNSAFE_HISTORY", e))?;
        at = skip_space(input, key_end, object.end);
        if input.get(at) != Some(&b':') {
            return Err(error("UNSAFE_HISTORY", "invalid lineage member"));
        }
        at = skip_space(input, at + 1, object.end);
        let end = value_end(input, at, object.end)?;
        if key == name {
            if found.is_some() {
                return Err(error("UNSAFE_HISTORY", "duplicate lineage member"));
            }
            found = Some(at..end);
        }
        at = skip_space(input, end, object.end);
        if input.get(at) == Some(&b',') {
            at += 1;
        } else {
            break;
        }
    }
    found.ok_or_else(|| error("UNSAFE_HISTORY", format!("missing lineage member {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_projection_repair_metadata_patch_preserves_layout_and_unrelated_fields() {
        let mut header = br#" {"type":"session_meta","payload":{"end_byte_offset":999999999,"note":"escaped \"end_byte_offset\":999999999","history_base":{"thread_id":"parent","end_byte_offset":999999999,"end_ordinal_exclusive":3}}}
"#.to_vec();
        let original = header.clone();
        patch_cutoff(
            &mut header,
            &files::LineageRepair {
                source_id: "child".into(),
                previous_offset: 999999999,
                repaired_offset: 37,
            },
        )
        .unwrap();
        assert_eq!(header.len(), original.len());
        let before: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let mut after: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(after["payload"]["history_base"]["end_byte_offset"], 37);
        after["payload"]["history_base"]["end_byte_offset"] =
            before["payload"]["history_base"]["end_byte_offset"].clone();
        assert_eq!(after, before);
        let changed = original.iter().zip(&header).filter(|(a, b)| a != b).count();
        assert_eq!(changed, 9);
    }
}
