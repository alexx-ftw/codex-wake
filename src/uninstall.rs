use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

pub const DATABASE_ID: i32 = 0x43574b45;

pub fn validate_external_database(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && metadata.uid() == current_uid()?,
        "Database is not an owned regular file"
    );
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let id: i32 = db.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let unrelated: i64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('waits','subscriptions','rules','rule_deliveries','github_poll_state','github_poll_generation','observers','native_observers','native_condition_observers','steers','obligations','obligation_transfers','validation_evidence','validation_scope_links','result_reports','circular_waits','circular_notices','coordinators','coordinator_alerts','coordinator_hook_events','dependency_notice_uncertainties','delivery_evidence','user_message_observations','condition_groups','condition_members','condition_completions','condition_publications','condition_pending_events','condition_publication_collisions','condition_alerts')", [], |row| row.get(0))?;
    ensure!(
        id == DATABASE_ID && unrelated == 0,
        "Database ownership could not be verified; unrelated data was preserved"
    );
    Ok(())
}

pub fn remove_external_database(path: &Path) -> Result<()> {
    validate_external_database(path)?;
    if !path.try_exists()? {
        return Ok(());
    }
    let _poll_guard = crate::polling::lock_database_parent(&path.canonicalize()?, true)?;
    validate_external_database(path)?;
    fs::remove_file(path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        match fs::remove_file(sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn current_uid() -> Result<u32> {
    Ok(fs::metadata("/proc/self")?.uid())
}

fn has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| component == Component::ParentDir)
}

/// Remove an owned codex-wake directory without following links inside it.
pub fn validate_owned_tree(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Cleanup path must be absolute");
    ensure!(
        !has_parent_component(path),
        "Cleanup path cannot contain '..'"
    );
    ensure!(
        path.file_name().is_some_and(|name| name == "codex-wake"),
        "Cleanup path must end in 'codex-wake'"
    );

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_dir(),
        "Cleanup root must be a nonsymlink directory"
    );
    ensure!(
        metadata.uid() == current_uid()?,
        "Cleanup root is not owned by this user"
    );
    Ok(())
}

pub fn remove_owned_tree(path: &Path) -> Result<()> {
    validate_owned_tree(path)?;
    if !path.try_exists()? {
        return Ok(());
    }
    fs::remove_dir_all(path).with_context(|| format!("Removing owned tree {}", path.display()))
}

/// Return the marketplace directory for an exact installed plugin root.
pub fn plugin_base(codex_home: &Path, root: &Path) -> Result<PathBuf> {
    ensure!(codex_home.is_absolute(), "CODEX_HOME must be absolute");
    ensure!(root.is_absolute(), "Plugin root must be absolute");
    ensure!(
        !has_parent_component(codex_home) && !has_parent_component(root),
        "Plugin paths cannot contain '..'"
    );
    let relative = root
        .strip_prefix(codex_home)
        .context("Plugin root is outside CODEX_HOME")?;
    let components: Vec<_> = relative.components().collect();
    ensure!(
        components.len() == 5
            && components[0] == Component::Normal("plugins".as_ref())
            && components[1] == Component::Normal("cache".as_ref())
            && matches!(components[2], Component::Normal(_))
            && components[3] == Component::Normal("codex-wake".as_ref())
            && matches!(components[4], Component::Normal(_)),
        "Plugin root must be CODEX_HOME/plugins/cache/<marketplace>/codex-wake/<version>"
    );
    Ok(codex_home
        .join("plugins/cache")
        .join(components[2].as_os_str())
        .join("codex-wake"))
}

/// Remove a unit file only when it is an owned regular file with exact contents.
pub fn remove_unit_file(path: &Path, expected: &str) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_file(),
        "Unit path must be a nonsymlink regular file"
    );
    ensure!(
        metadata.uid() == current_uid()?,
        "Unit file is not owned by this user"
    );
    ensure!(
        fs::read(path)? == expected.as_bytes(),
        "Unit file contents do not match"
    );
    fs::remove_file(path).with_context(|| format!("Removing unit file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn cleanup_refuses_active_poll_lock_and_leaves_no_lock_sidecar() {
        fn wait_for(path: &Path) {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !path.exists() {
                assert!(std::time::Instant::now() < deadline, "timed out");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        if let Some(dir) = std::env::var_os("WAKE_CLEANUP_LOCK_TEST_DIR") {
            let dir = PathBuf::from(dir);
            let _held =
                crate::polling::lock_database_parent(&dir.join("state.sqlite3"), false).unwrap();
            std::fs::write(dir.join("held"), b"").unwrap();
            wait_for(&dir.join("release"));
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite3");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.pragma_update(None, "application_id", DATABASE_ID)
            .unwrap();
        drop(db);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "uninstall::tests::cleanup_refuses_active_poll_lock_and_leaves_no_lock_sidecar",
            ])
            .env("WAKE_CLEANUP_LOCK_TEST_DIR", dir.path())
            .spawn()
            .unwrap();
        wait_for(&dir.path().join("held"));
        assert!(remove_external_database(&path).is_err());
        assert!(path.exists());
        assert!(!dir.path().join("state.sqlite3.poll.lock").exists());
        std::fs::write(dir.path().join("release"), b"").unwrap();
        assert!(child.wait().unwrap().success());
        remove_external_database(&path).unwrap();
        assert!(!path.exists());
        assert!(!dir.path().join("state.sqlite3.poll.lock").exists());
    }
    #[test]
    fn external_database_cleanup_preserves_foreign_data() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("custom.sqlite");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE personal(value TEXT)")
            .unwrap();
        drop(db);
        assert!(remove_external_database(&path).is_err());
        assert!(path.exists());
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("DROP TABLE personal; CREATE TABLE waits(value TEXT)")
            .unwrap();
        db.pragma_update(None, "application_id", DATABASE_ID)
            .unwrap();
        drop(db);
        remove_external_database(&path).unwrap();
        assert!(!path.exists());
        remove_external_database(&path).unwrap();
    }

    #[test]
    fn evidence_named_foreign_table_does_not_acquire_ownership() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("foreign.sqlite");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE validation_evidence(value TEXT)")
            .unwrap();
        drop(db);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(crate::bridge::connect(&path).unwrap());
        assert!(remove_external_database(&path).is_err());
        assert!(path.exists());
    }

    #[test]
    fn polling_schema_cleanup_removes_only_plugin_state() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("state.sqlite3");
        let artifact = temp.path().join("user-artifact");
        fs::write(&artifact, b"keep").unwrap();
        let db = crate::bridge::connect(&path).unwrap();
        crate::subscriptions::initialize(&db).unwrap();
        crate::conditions::initialize(&db).unwrap();
        crate::condition_alerts::initialize(&db).unwrap();
        crate::rules::initialize(&db).unwrap();
        crate::polling::initialize(&db).unwrap();
        crate::native_poll::initialize(&db).unwrap();
        crate::observers::initialize(&db).unwrap();
        crate::steer::initialize(&db).unwrap();
        crate::obligations::initialize(&db).unwrap();
        crate::validation_obligations::initialize(&db).unwrap();
        crate::circular_waits::initialize(&db).unwrap();
        let application_id: i32 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        assert_eq!(application_id, DATABASE_ID);
        let transfer_table: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='obligation_transfers')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(transfer_table);
        for table in [
            "coordinators",
            "coordinator_alerts",
            "dependency_notice_uncertainties",
            "condition_groups",
            "condition_members",
            "condition_completions",
            "condition_publications",
            "condition_pending_events",
            "condition_publication_collisions",
            "condition_alerts",
            "native_condition_observers",
        ] {
            let exists: bool = db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "{table}");
        }
        crate::result_conflicts::record(
            &db,
            "ci",
            "build",
            "run",
            1,
            "success",
            &serde_json::json!({}),
        )
        .unwrap();
        let id = crate::subscriptions::subscribe(
            &db,
            "artifact",
            "build",
            "package",
            "available",
            "11111111-1111-4111-8111-111111111111",
        )
        .unwrap();
        crate::observers::attach(
            &db,
            &id,
            &crate::observers::Observation::File {
                path: artifact.to_str().unwrap().into(),
            },
        )
        .unwrap();
        drop(db);
        validate_external_database(&path).unwrap();
        remove_external_database(&path).unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read(&artifact).unwrap(), b"keep");
    }

    #[test]
    fn foreign_result_reports_table_does_not_establish_ownership() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("foreign.sqlite3");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE result_reports(value TEXT)")
            .unwrap();
        drop(db);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let db = crate::bridge::connect(&path).unwrap();
        let id: i32 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        assert_eq!(id, 0);
        drop(db);
        assert!(remove_external_database(&path).is_err());
        assert!(path.exists());
    }

    #[test]
    fn foreign_validation_scope_links_table_does_not_establish_ownership() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("foreign.sqlite3");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE validation_scope_links(value TEXT)")
            .unwrap();
        drop(db);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let db = crate::bridge::connect(&path).unwrap();
        let id: i32 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        assert_eq!(id, 0);
        drop(db);
        assert!(validate_external_database(&path).is_err());
        assert!(path.exists());
    }

    #[test]
    fn wake_validation_scope_links_table_is_accepted_for_uninstall() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("state").join("state.sqlite3");
        let db = crate::bridge::connect(&path).unwrap();
        crate::obligations::initialize(&db).unwrap();
        crate::validation_obligations::initialize(&db).unwrap();
        let id: i32 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        assert_eq!(id, DATABASE_ID);
        let has_scope_links: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='validation_scope_links')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(has_scope_links);
        drop(db);
        validate_external_database(&path).unwrap();
    }

    #[test]
    fn transfer_table_does_not_bypass_application_id_check() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("foreign.sqlite3");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE obligation_transfers(id TEXT)")
            .unwrap();
        drop(db);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(remove_external_database(&path).is_err());
        assert!(path.exists());
        let db = rusqlite::Connection::open(&path).unwrap();
        let application_id: i32 = db
            .pragma_query_value(None, "application_id", |row| row.get(0))
            .unwrap();
        assert_eq!(application_id, 0);
    }

    #[test]
    fn wake_metadata_tables_are_allowed_for_uninstall_only_when_database_is_identified() {
        for table in [
            "coordinators",
            "coordinator_alerts",
            "coordinator_hook_events",
            "dependency_notice_uncertainties",
            "condition_alerts",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("state.sqlite3");
            let db = rusqlite::Connection::open(&path).unwrap();
            db.execute_batch(&format!("CREATE TABLE {table} (value TEXT)"))
                .unwrap();
            drop(db);

            assert!(validate_external_database(&path).is_err(), "{table}");
            assert!(path.exists());

            let db = rusqlite::Connection::open(&path).unwrap();
            db.pragma_update(None, "application_id", DATABASE_ID)
                .unwrap();
            drop(db);
            validate_external_database(&path).unwrap();
            remove_external_database(&path).unwrap();
            assert!(!path.exists());
        }
    }

    #[test]
    fn removes_owned_tree_and_unlinks_nested_symlinks_without_following() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("codex-wake");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/file"), "owned").unwrap();
        let outside = temp.path().join("outside");
        fs::write(&outside, "keep").unwrap();
        symlink(&outside, root.join("nested/link")).unwrap();

        remove_owned_tree(&root).unwrap();

        assert!(!root.exists());
        assert_eq!(fs::read_to_string(outside).unwrap(), "keep");
    }

    #[test]
    fn missing_tree_and_unit_are_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        remove_owned_tree(&temp.path().join("codex-wake")).unwrap();
        remove_unit_file(&temp.path().join("codex-wake.service"), "expected").unwrap();
    }

    #[test]
    fn rejects_unowned_tree_names_and_root_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let unrelated = temp.path().join("unrelated");
        fs::create_dir(&unrelated).unwrap();
        assert!(remove_owned_tree(&unrelated).is_err());
        assert!(unrelated.is_dir());

        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let root = temp.path().join("codex-wake");
        symlink(&target, &root).unwrap();
        assert!(remove_owned_tree(&root).is_err());
        assert!(target.is_dir());
    }

    #[test]
    fn accepts_only_the_exact_plugin_install_layout() {
        let home = Path::new("/tmp/codex");
        assert_eq!(
            plugin_base(home, &home.join("plugins/cache/example/codex-wake/1.2.3")).unwrap(),
            home.join("plugins/cache/example/codex-wake")
        );
        assert!(plugin_base(home, &home.join("plugins/cache/other/1.2.3")).is_err());
        assert!(plugin_base(home, &home.join("plugins/cache/../codex-wake/1")).is_err());
    }

    #[test]
    fn preserves_foreign_or_linked_unit_files() {
        let temp = tempfile::tempdir().unwrap();
        let unit = temp.path().join("codex-wake.service");
        fs::write(&unit, "foreign").unwrap();
        assert!(remove_unit_file(&unit, "expected").is_err());
        assert_eq!(fs::read_to_string(&unit).unwrap(), "foreign");

        let target = temp.path().join("target");
        fs::write(&target, "expected").unwrap();
        fs::remove_file(&unit).unwrap();
        symlink(&target, &unit).unwrap();
        assert!(remove_unit_file(&unit, "expected").is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "expected");
    }
}
