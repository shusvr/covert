use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Resolve paths through Git to support both regular checkouts and worktrees.
    for name in [
        Some("HEAD".to_owned()),
        git(&["symbolic-ref", "-q", "HEAD"]),
        Some("packed-refs".to_owned()),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(path) = git(&["rev-parse", "--git-path", &name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let hash = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    println!(
        "cargo:rustc-env=COVERT_VERSION={} ({hash})",
        env!("CARGO_PKG_VERSION")
    );
}
