use std::{path::Path, process::Command};

fn git(root: &Path, args: &[&str]) {
    let mut command = Command::new("git");
    for (key, _) in std::env::vars().filter(|(key, _)| key.starts_with("GIT_")) {
        command.env_remove(key);
    }
    let output = command
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn release_packaging_is_deterministic_and_requires_clean_source() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("source");
    std::fs::create_dir_all(root.join("scripts")).unwrap();
    std::fs::write(
        root.join("scripts/package-release.sh"),
        include_str!("../scripts/package-release.sh"),
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"codex-wake\"\nversion = \"0.2.0-alpha.1\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.98.0\"\n",
    )
    .unwrap();
    let binary = temp.path().join("binary");
    std::fs::write(&binary, "fixture binary bytes").unwrap();
    let tools = temp.path().join("tools");
    std::fs::create_dir(&tools).unwrap();
    // Mock toolchain notices and architecture detection to test archive construction.
    let docs = tools.join("share/doc/rust");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(
        docs.join("COPYRIGHT-library.html"),
        "fixture toolchain notices\n",
    )
    .unwrap();
    std::fs::write(
        tools.join("rustup"),
        format!("#!/bin/sh\nprintf '%s\\n' '{}'\n", tools.display()),
    )
    .unwrap();
    std::fs::set_permissions(tools.join("rustup"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        tools.join("file"),
        "#!/bin/sh\necho 'ELF 64-bit LSB executable, x86-64, statically linked'\n",
    )
    .unwrap();
    std::fs::set_permissions(tools.join("file"), std::fs::Permissions::from_mode(0o700)).unwrap();
    git(&root, &["init", "--quiet"]);
    git(&root, &["add", "."]);
    git(
        &root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
    );
    let package = |out: &str| {
        Command::new("sh")
            .arg(root.join("scripts/package-release.sh"))
            .arg(&binary)
            .arg(temp.path().join(out))
            .env("PATH", format!("{}:/usr/bin:/bin", tools.display()))
            .output()
            .unwrap()
    };
    assert!(package("internal-unlicensed").status.success());
    std::fs::write(
        root.join("LICENSE"),
        "Test fixture license; not a project license.\n",
    )
    .unwrap();
    git(&root, &["add", "LICENSE"]);
    git(
        &root,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture license",
        ],
    );
    for out in ["one", "two"] {
        let result = package(out);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let archive = "codex-wake-0.2.0-alpha.1-linux-x86_64.tar.gz";
    assert_eq!(
        std::fs::read(temp.path().join("one").join(archive)).unwrap(),
        std::fs::read(temp.path().join("two").join(archive)).unwrap()
    );
    let checksum = Command::new("sha256sum")
        .args(["--check", "SHA256SUMS"])
        .current_dir(temp.path().join("one"))
        .output()
        .unwrap();
    assert!(checksum.status.success());
    std::fs::write(root.join("Cargo.toml"), "dirty\n").unwrap();
    assert!(!package("dirty").status.success());
}
