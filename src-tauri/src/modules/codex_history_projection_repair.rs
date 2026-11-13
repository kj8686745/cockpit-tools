//! 手动恢复 Codex 历史派生索引；仅重置投影时允许客户端保持运行。
//! 经序号证明的过期祖先 EOF 截止点须先停止实例，再备份并修正，保持全部解码字节跨度。
//! 任何其它源内容或并发变化均不得被本模块覆盖。
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};

#[path = "codex_history_projection_repair/files.rs"]
mod files;
#[path = "codex_history_projection_repair/lineage.rs"]
mod lineage;
pub(super) use files::file_ids as rollout_file_ids;
#[path = "codex_history_projection_repair/storage.rs"]
mod storage;

const HISTORY_DB: &str = "thread_history_1.sqlite";
const STATE_DB: &str = "state_5.sqlite";
const MAX_ENTRIES: usize = 100_000;
const MAX_CANDIDATES: usize = 64;
pub(crate) const MIN_SCAN_BUDGET_MINUTES: u16 = 1;
pub(crate) const DEFAULT_SCAN_BUDGET_MINUTES: u16 = 10;
pub(crate) const MAX_SCAN_BUDGET_MINUTES: u16 = 240;

#[derive(Debug)]
pub(crate) struct Plan {
    profile: PathBuf,
    schema: storage::Schema,
    db_identity: files::Identity,
    sources: HashMap<String, files::Evidence>,
    selected_paths: Vec<(String, String)>,
    candidates: Vec<Checkpoint>,
    /// 仅修正经连续序号证明的祖先 EOF 截止点，不改正文或记录字节位置。
    lineage_repairs: Vec<files::LineageRepair>,
    /// 保留扫描时限，以同一预算保护后续备份和索引事务。
    scan_budget: Duration,
    // Requested/projected ID and missing source ID. Their existing indexes are retained.
    pub(crate) skipped_sources: Vec<(String, String)>,
    pub(crate) duplicate_ordinals: Vec<(String, String, u64)>,
}

impl Plan {
    pub(crate) fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    pub(crate) fn scanned_files(&self) -> usize {
        self.sources.len()
    }

    pub(crate) fn lineage_repair_count(&self) -> usize {
        self.lineage_repairs.len()
    }

    pub(crate) fn has_changes(&self) -> bool {
        !self.candidates.is_empty() || !self.lineage_repairs.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Checkpoint {
    id: String,
    offset: i64,
    ordinal: i64,
}

struct Budget {
    /// 当前扫描阶段开始时间，所有 rollout 共用一个总时限。
    started: Instant,
    /// 从界面传入并经后端限制后的阶段时限。
    timeout: Duration,
}

impl Budget {
    /// 为历史扫描或写入阶段建立独立总时限。
    ///
    /// # Arguments
    /// * `timeout` - 当前阶段的最长运行时间。
    fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    /// 在昂贵的目录、文件或数据库操作之间检查阶段总时限。
    ///
    /// # Returns
    /// 剩余时间有效时返回 `Ok(())`，超时后返回可供界面显示的限制错误。
    fn check(&self) -> Result<(), String> {
        if self.started.elapsed() > self.timeout {
            return Err(error(
                "LIMIT",
                "history scan exceeded the configured time budget; increase the limit or select fewer sessions",
            ));
        }
        Ok(())
    }
}

fn error(code: &str, detail: impl std::fmt::Display) -> String {
    format!("CODEX_HISTORY_REPAIR_{code}: {detail}")
}

fn database(profile: &Path, name: &str, writable: bool) -> Result<Connection, String> {
    let path = profile.join(name);
    files::regular_file(&path)?;
    for suffix in ["-wal", "-shm"] {
        let side = profile.join(format!("{name}{suffix}"));
        if side.symlink_metadata().is_ok() {
            files::regular_file(&side)?;
        }
    }
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = Connection::open_with_flags(path, flags).map_err(|e| error("DATABASE", e))?;
    db.busy_timeout(Duration::from_millis(250))
        .map_err(|e| error("DATABASE", e))?;
    db.execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(|e| error("DATABASE", e))?;
    Ok(db)
}

fn checkpoint(db: &Connection, id: &str) -> Result<Option<Checkpoint>, String> {
    db.query_row(
        "SELECT thread_id,next_rollout_byte_offset,next_rollout_ordinal FROM thread_history_projection_state WHERE thread_id=?1",
        [id],
        |row| Ok(Checkpoint { id: row.get(0)?, offset: row.get(1)?, ordinal: row.get(2)? }),
    ).optional().map_err(|e| error("DATABASE", e))
}

/// Scan on a blocking maintenance worker. Preview is read-only, including while the client runs.
pub(crate) fn scan(
    profile: &Path,
    selected_session_ids: Option<&HashSet<String>>,
    on_progress: &dyn Fn(usize, usize),
) -> Result<Plan, String> {
    scan_with_budget(
        profile,
        selected_session_ids,
        Duration::from_secs(u64::from(DEFAULT_SCAN_BUDGET_MINUTES) * 60),
        on_progress,
    )
}

/// 在 blocking worker 上只读扫描 Codex 历史索引，并使用调用方配置的阶段时限。
///
/// # Arguments
/// * `profile` - Codex 实例的数据目录。
/// * `selected_session_ids` - 指定时只检查这些会话；为空时检查全部投影会话。
/// * `scan_budget` - 本实例完整扫描及后续应用阶段各自的最大运行时间。
/// * `on_progress` - 按已扫描投影数报告进度。
pub(crate) fn scan_with_budget(
    profile: &Path,
    selected_session_ids: Option<&HashSet<String>>,
    scan_budget: Duration,
    on_progress: &dyn Fn(usize, usize),
) -> Result<Plan, String> {
    let mut budget = Budget::new(scan_budget);
    let profile = files::profile_root(profile)?;
    let history_path = profile.join(HISTORY_DB);
    if matches!(history_path.symlink_metadata(), Err(e) if e.kind()==std::io::ErrorKind::NotFound) {
        return Ok(Plan {
            profile,
            schema: storage::Schema::empty(),
            db_identity: files::Identity::default(),
            sources: HashMap::new(),
            selected_paths: vec![],
            candidates: vec![],
            lineage_repairs: vec![],
            scan_budget,
            skipped_sources: vec![],
            duplicate_ordinals: vec![],
        });
    }
    let db = database(&profile, HISTORY_DB, false)?;
    let schema = storage::schema(&db)?;
    let db_identity = files::identity(&history_path)?;
    let registry = files::registry(&profile, &budget)?;
    let mut roots = Vec::new();
    let mut selected_sources = Vec::new();
    let mut skipped_sources = Vec::new();
    if let Some(selected) = selected_session_ids {
        let state = database(&profile, STATE_DB, false)?;
        let mut selected = selected.iter().collect::<Vec<_>>();
        selected.sort();
        for id in selected {
            budget.check()?;
            let path: Option<String> = state
                .query_row(
                    "SELECT rollout_path FROM threads WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| error("DATABASE", e))?;
            let Some(path) = path else {
                skipped_sources.push((id.clone(), id.clone()));
                continue;
            };
            let physical = match files::selected_source(&profile, &path, &registry) {
                Ok(id) => id,
                Err(files::SourceError::Missing(missing)) => {
                    skipped_sources.push((id.clone(), missing));
                    continue;
                }
                Err(files::SourceError::DuplicateOrdinal { source_id, ordinal }) => {
                    return Err(error(
                        "DUPLICATE_ORDINAL",
                        format!("{source_id}: {ordinal}"),
                    ));
                }
                Err(files::SourceError::Invalid(error)) => return Err(error),
            };
            roots.push(physical.clone());
            selected_sources.push((id.to_owned(), path, physical));
        }
    } else {
        let mut stmt = db.prepare("SELECT thread_id FROM thread_history_projection_state ORDER BY thread_id LIMIT 100001").map_err(|e| error("DATABASE", e))?;
        roots = stmt
            .query_map([], |row| row.get(0))
            .map_err(|e| error("DATABASE", e))?
            .collect::<rusqlite::Result<Vec<String>>>()
            .map_err(|e| error("DATABASE", e))?;
    }
    if roots.len() > MAX_ENTRIES {
        return Err(error("LIMIT", "too many projected sessions"));
    }
    roots.sort();
    roots.dedup();
    let mut sources = HashMap::new();
    let mut duplicate_ordinals = Vec::new();
    for (index, id) in roots.iter().enumerate() {
        match files::load_chain(
            id,
            &registry,
            &mut sources,
            &mut HashSet::new(),
            &mut budget,
        ) {
            Ok(()) => {}
            Err(files::SourceError::Missing(missing)) => {
                skipped_sources.push((id.clone(), missing));
            }
            Err(files::SourceError::DuplicateOrdinal { source_id, ordinal }) => {
                duplicate_ordinals.push((id.clone(), source_id, ordinal));
            }
            Err(files::SourceError::Invalid(error)) => return Err(error),
        }
        on_progress(index + 1, roots.len());
        std::thread::yield_now();
    }
    // Only repairable chains participate in the transaction's selection checks.
    let selected_paths = selected_sources
        .into_iter()
        .filter(|(_, _, physical)| sources.contains_key(physical))
        .map(|(id, path, _)| (id, path))
        .collect();
    let mut candidates = Vec::new();
    for (id, source) in &sources {
        budget.check()?;
        let Some(saved) = checkpoint(&db, id)? else {
            continue;
        };
        if saved.offset < 0 || saved.ordinal < 0 {
            return Err(error(
                "UNSAFE_HISTORY",
                format!("negative projection cursor for {id}"),
            ));
        }
        if saved.offset as u64 <= source.decoded_bytes {
            continue;
        }
        if !source.has_ordinals
            || saved.ordinal as u64 > source.next_ordinal
            || (saved.ordinal as u64) < source.initial_ordinal
        {
            return Err(error(
                "MISSING_RECORDS",
                format!("durable records do not cover the projection for {id}"),
            ));
        }
        candidates.push(saved);
    }
    candidates.sort_by(|a, b| a.id.cmp(&b.id));
    let mut lineage_repairs = sources
        .values()
        .filter_map(files::Evidence::lineage_repair)
        .collect::<Vec<_>>();
    lineage_repairs.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    if candidates.len() > MAX_CANDIDATES {
        return Err(error(
            "LIMIT",
            "too many damaged projections; select fewer sessions",
        ));
    }
    if lineage_repairs.len() > MAX_CANDIDATES {
        return Err(error(
            "LIMIT",
            "too many stale lineage cutoffs; select fewer sessions",
        ));
    }
    Ok(Plan {
        profile,
        schema,
        db_identity,
        sources,
        selected_paths,
        candidates,
        lineage_repairs,
        scan_budget,
        skipped_sources,
        duplicate_ordinals,
    })
}

/// 先持久化有界备份，再修复已证明的祖先截止点及派生投影。
///
/// 调用方在 `lineage_repair_count() > 0` 时必须先确认目标 Codex 实例已停止；
/// 纯投影修复仍通过源哈希及 SQLite 事务保护在线客户端。
pub(crate) fn apply(profile: &Path, plan: &Plan, backup_dir: &Path) -> Result<usize, String> {
    apply_with_checkpoints(profile, plan, backup_dir, &|| {})
}

// Checkpoints let concurrency tests schedule real writes at transaction boundaries.
fn apply_with_checkpoints(
    profile: &Path,
    plan: &Plan,
    backup_dir: &Path,
    checkpoint: &dyn Fn(),
) -> Result<usize, String> {
    if files::profile_root(profile)? != plan.profile {
        return Err(error("CHANGED", "profile changed since scan"));
    }
    if !plan.has_changes() {
        return Ok(0);
    }
    let mut budget = Budget::new(plan.scan_budget);
    for source in plan.sources.values() {
        source.recheck(&mut budget)?;
    }
    validate_selection(plan)?;
    if files::identity(&plan.profile.join(HISTORY_DB))? != plan.db_identity {
        return Err(error("CHANGED", "history database was replaced"));
    }
    let mut db = database(&plan.profile, HISTORY_DB, true)?;
    if storage::schema(&db)? != plan.schema {
        return Err(error("CHANGED", "history database schema changed"));
    }
    let snapshots = {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|e| error("DATABASE", e))?;
        validate_cursors(&tx, plan)?;
        let rows = storage::capture(&tx, &plan.schema, &plan.candidates, &mut budget)?;
        tx.commit().map_err(|e| error("DATABASE", e))?;
        rows
    };
    storage::backup(backup_dir, plan, &snapshots, &mut budget)?;
    // 原始 rollout 先校验并备份，再准备保持解码字节跨度不变的替换文件。
    let mut lineage = lineage::Prepared::new(plan, backup_dir, &mut budget)?;
    checkpoint();
    // Expensive decompression and hashing finished before acquiring the write transaction.
    for source in plan.sources.values() {
        source.check_stamp()?;
    }
    validate_selection(plan)?;
    let result = (|| {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| error("DATABASE", e))?;
        if storage::schema(&tx)? != plan.schema {
            return Err(error("CHANGED", "history database schema changed"));
        }
        validate_cursors(&tx, plan)?;
        if storage::capture(&tx, &plan.schema, &plan.candidates, &mut budget)? != snapshots {
            return Err(error("CHANGED", "derived history changed after backup"));
        }
        for candidate in &plan.candidates {
            for table in storage::TABLES {
                budget.check()?;
                tx.execute(
                    &format!("DELETE FROM {table} WHERE thread_id=?1"),
                    [&candidate.id],
                )
                .map_err(|e| error("DATABASE", e))?;
            }
        }
        // 文件替换位于 SQLite 提交前；任何后续错误先回滚 SQLite，再恢复原始文件。
        lineage.publish()?;
        checkpoint();
        lineage.check_sources(plan)?;
        if files::identity(&plan.profile.join(HISTORY_DB))? != plan.db_identity {
            return Err(error(
                "CHANGED",
                "history database was replaced during repair",
            ));
        }
        budget.check()?;
        tx.commit().map_err(|e| error("DATABASE", e))?;
        Ok(plan.candidates.len())
    })();
    match result {
        Ok(count) => Ok(count),
        Err(failure) => match lineage.rollback() {
            Ok(()) => Err(failure),
            Err(rollback) => Err(format!(
                "{failure}; {rollback}; backup={}",
                backup_dir.display()
            )),
        },
    }
}

fn validate_cursors(db: &Connection, plan: &Plan) -> Result<(), String> {
    for expected in &plan.candidates {
        if checkpoint(db, &expected.id)?.as_ref() != Some(expected) {
            return Err(error(
                "CHANGED",
                format!("projection changed for {}", expected.id),
            ));
        }
    }
    Ok(())
}

fn validate_selection(plan: &Plan) -> Result<(), String> {
    if plan.selected_paths.is_empty() {
        return Ok(());
    }
    let db = database(&plan.profile, STATE_DB, false)?;
    for (id, path) in &plan.selected_paths {
        let current: Option<String> = db
            .query_row(
                "SELECT rollout_path FROM threads WHERE id=?1",
                [id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| error("DATABASE", e))?;
        if current.as_deref() != Some(path.as_str()) {
            return Err(error(
                "CHANGED",
                format!("selected session changed for {id}"),
            ));
        }
    }
    Ok(())
}
#[cfg(test)]
#[path = "codex_history_projection_repair/tests.rs"]
mod tests;
