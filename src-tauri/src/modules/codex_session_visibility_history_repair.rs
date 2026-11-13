// Manual, isolated history-index recovery. Automatic launch/visibility repair never enters here.
fn history_repair_message(key: &str, args: &[(&str, &str)]) -> String {
    modules::i18n::translate(
        &modules::config::get_user_config().language,
        &format!("codex.sessionManager.repairModal.{key}"),
        args,
    )
}

fn history_repair_error(error: String) -> String {
    modules::logger::log_warn(&format!("[Codex History Index] {error}"));
    if error.starts_with("CODEX_HISTORY_REPAIR_CHANGED") {
        history_repair_message("historyChanged", &[])
    } else if error.starts_with("CODEX_HISTORY_REPAIR_STOP_REQUIRED") {
        history_repair_message("stopInstanceHint", &[])
    } else {
        history_repair_message("historyFailed", &[("error", &error)])
    }
}

fn scan_history_projections_for_instances(
    options: CodexSessionVisibilityRepairOptions,
    run_id: &Option<String>,
    progress_reporter: ProgressReporter<'_>,
    selection: &RepairTargetSelection,
    instances: &[CodexSyncInstance],
) -> Result<Vec<(modules::codex_history_projection_repair::Plan, bool)>, String> {
    use modules::codex_history_projection_repair as history;

    if instances.is_empty() {
        return Err(history_repair_error(
            "CODEX_HISTORY_REPAIR_NO_INSTANCE".into(),
        ));
    }
    // Validate every selected instance before the first mutation.
    let mut plans = Vec::with_capacity(instances.len());
    // Running state is informational; SQLite transactions and source checks
    // protect the repair without requiring the desktop client or CLI to stop.
    let process_entries = modules::process::collect_codex_process_entries();
    for (index, instance) in instances.iter().enumerate() {
        let progress = |current: usize, total: usize| {
            report_repair_progress(
                progress_reporter,
                run_id,
                options,
                "scan_history_index",
                instance_progress_percent(index, instances.len(), 0, 4),
                current,
                total,
                Some(instance),
            );
        };
        let scan_budget =
            std::time::Duration::from_secs(u64::from(options.history_scan_budget_minutes) * 60);
        let plan = history::scan_with_budget(
            &instance.data_dir,
            selection.session_ids(),
            scan_budget,
            &progress,
        )
        .map_err(history_repair_error)?;
        let running = is_instance_running(instance, &process_entries);
        plans.push((plan, running));
    }
    Ok(plans)
}

fn history_duplicate_ordinals_warning(
    instances: &[CodexSyncInstance],
    plans: &[(modules::codex_history_projection_repair::Plan, bool)],
) -> Option<String> {
    let affected = instances
        .iter()
        .zip(plans)
        .flat_map(|(instance, (plan, _))| {
            plan.duplicate_ordinals
                .iter()
                .map(move |(id, source, ordinal)| {
                    format!("{}: {id} → {source} ({ordinal})", instance.name)
                })
        })
        .collect::<Vec<_>>();
    (!affected.is_empty()).then(|| {
        history_repair_message(
            "historyDuplicateOrdinals",
            &[("details", &affected.join("\n"))],
        )
    })
}

fn repair_history_projections_for_instances(
    options: CodexSessionVisibilityRepairOptions,
    run_id: Option<String>,
    progress_reporter: ProgressReporter<'_>,
    selection: RepairTargetSelection,
    instances: Vec<CodexSyncInstance>,
) -> Result<CodexSessionVisibilityRepairSummary, String> {
    let plans = scan_history_projections_for_instances(
        options,
        &run_id,
        progress_reporter,
        &selection,
        &instances,
    )?;
    apply_history_projection_plans(options, run_id, progress_reporter, &instances, plans)
}

fn apply_history_projection_plans(
    options: CodexSessionVisibilityRepairOptions,
    run_id: Option<String>,
    progress_reporter: ProgressReporter<'_>,
    instances: &[CodexSyncInstance],
    plans: Vec<(modules::codex_history_projection_repair::Plan, bool)>,
) -> Result<CodexSessionVisibilityRepairSummary, String> {
    use modules::codex_history_projection_repair as history;
    let mut summary = CodexSessionVisibilityRepairSummary {
        instance_count: instances.len(),
        history_projection_count: Some(0),
        history_lineage_repair_count: Some(0),
        history_repair_warning: history_duplicate_ordinals_warning(instances, &plans),
        ..Default::default()
    };
    let mut total = 0;
    let mut lineage_total = 0;
    let mut skipped = Vec::new();
    for (index, (instance, (plan, running))) in instances.iter().zip(plans).enumerate() {
        for (id, missing) in &plan.skipped_sources {
            skipped.push(format!("{}: {id} → {missing}", instance.name));
            modules::logger::log_warn(&format!(
                "[Codex History Index] instance_id={}, skipped_source={id}, missing_source={missing}",
                instance.id,
            ));
        }
        let candidates = plan.candidate_count();
        let lineage_repairs = plan.lineage_repair_count();
        if !options.dry_run && running && lineage_repairs > 0 {
            return Err(history_repair_error(format!(
                "CODEX_HISTORY_REPAIR_STOP_REQUIRED: {} validated history lineage boundaries need metadata correction; close the Codex instance and retry",
                lineage_repairs,
            )));
        }
        let mut backup_dir = None;
        if plan.has_changes() && !options.dry_run {
            let scope = modules::backup_storage::scope_for_path(&instance.data_dir);
            let backup = modules::backup_storage::behavior_backup_dir(
                "codex",
                &scope,
                &format!(
                    "history-index-{}-{}",
                    Utc::now().format("%Y%m%d-%H%M%S"),
                    uuid::Uuid::new_v4()
                ),
            )
            .map_err(history_repair_error)?;
            report_repair_progress(
                progress_reporter,
                &run_id,
                options,
                "reset_history_index",
                instance_progress_percent(index, instances.len(), 2, 4),
                index + 1,
                instances.len(),
                Some(instance),
            );
            let repaired = history::apply(&instance.data_dir, &plan, &backup).map_err(|error| {
                // A later instance can change after preflight. Keep completed
                // repairs and their backups observable rather than claiming an
                // all-or-nothing outcome across independent SQLite databases.
                let context = format!(
                    "{error}; repaired_projections={total}; repaired_lineage_boundaries={lineage_total}; completed_backups={:?}; backup={}",
                    summary.backup_dirs,
                    backup.display(),
                );
                history_repair_error(if total > 0 || lineage_total > 0 {
                    format!("CODEX_HISTORY_REPAIR_PARTIAL: {context}")
                } else {
                    context
                })
            })?;
            total += repaired;
            lineage_total += lineage_repairs;
            let path = backup.to_string_lossy().into_owned();
            modules::logger::log_info(&format!(
                "[Codex History Index] backup={}, reset_projections={repaired}, repaired_lineage_boundaries={lineage_repairs}",
                path,
            ));
            summary.backup_dirs.push(path.clone());
            backup_dir = Some(path);
        } else {
            total += candidates;
            lineage_total += lineage_repairs;
        }
        if plan.has_changes() {
            summary.mutated_instance_count += 1;
        }
        summary.items.push(CodexSessionVisibilityRepairItem {
            instance_id: instance.id.clone(),
            instance_name: instance.name.clone(),
            running,
            backup_dir,
            history_projection_count: Some(candidates),
            history_lineage_repair_count: Some(lineage_repairs),
            ..Default::default()
        });
        modules::logger::log_info(&format!(
            "[Codex History Index] instance_id={}, preview={}, scanned_files={}, affected_projections={candidates}, lineage_repairs={lineage_repairs}",
            instance.id, options.dry_run, plan.scanned_files(),
        ));
    }
    summary.history_projection_count = Some(total);
    summary.history_lineage_repair_count = Some(lineage_total);
    if !skipped.is_empty() {
        let missing = history_repair_message(
            "historySkippedSources",
            &[
                ("count", &skipped.len().to_string()),
                ("details", &skipped.join("\n")),
            ],
        );
        summary.history_repair_warning = Some(match summary.history_repair_warning.take() {
            Some(warning) => format!("{warning}\n\n{missing}"),
            None => missing,
        });
    }
    summary.message = history_repair_message(
        if total == 0 && lineage_total == 0 {
            "historyNoChanges"
        } else if options.dry_run {
            "historyPreview"
        } else {
            "historySuccess"
        },
        &[
            ("count", &(total + lineage_total).to_string()),
            ("lineageCount", &lineage_total.to_string()),
        ],
    );
    report_repair_progress(
        progress_reporter,
        &run_id,
        options,
        "done",
        100,
        instances.len(),
        instances.len(),
        None,
    );
    Ok(summary)
}
