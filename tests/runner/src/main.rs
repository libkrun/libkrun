use anyhow::Context;
use clap::Parser;
use nix::sys::resource::{Resource, getrlimit, setrlimit};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::panic::catch_unwind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempdir::TempDir;
use test_cases::{Report, ShouldRun, Test, TestCase, TestOutcome, TestSetup, test_cases};

struct TestResult {
    name: String,
    outcome: TestOutcome,
    log_path: Option<PathBuf>,
}

fn get_test(name: &str) -> anyhow::Result<Box<dyn Test>> {
    let tests = test_cases();
    tests
        .into_iter()
        .find(|t| t.name() == name)
        .with_context(|| format!("No such test: {name}"))
        .map(|t| t.test)
}

fn start_vm(test_setup: TestSetup) -> anyhow::Result<()> {
    // Raise soft fd limit up to the hard limit
    let (_soft_limit, hard_limit) =
        getrlimit(Resource::RLIMIT_NOFILE).context("getrlimit RLIMIT_NOFILE")?;
    setrlimit(Resource::RLIMIT_NOFILE, hard_limit, hard_limit)
        .context("setrlimit RLIMIT_NOFILE")?;

    let test = get_test(&test_setup.test_case)?;
    test.start_vm(test_setup.clone())
        .with_context(|| format!("testcase: {test_setup:?}"))?;
    Ok(())
}

/// Kill background processes registered for cleanup via
/// [`TestSetup::register_cleanup_pid`]. Sends SIGTERM first, waits up to 5s
/// for graceful exit, then SIGKILL any survivors.
fn kill_cleanup_pids(test_dir: &Path) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use std::io::BufRead;

    let Ok(file) = File::open(test_dir.join("cleanup.pids")) else {
        return;
    };

    let mut pids = Vec::new();
    for line in std::io::BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        if let Ok(raw) = line.trim().parse::<i32>() {
            pids.push(Pid::from_raw(raw));
        }
    }

    for &pid in &pids {
        let _ = kill(pid, Signal::SIGTERM);
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        pids.retain(|&pid| kill(pid, None).is_ok());
        if pids.is_empty() || std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    for &pid in &pids {
        eprintln!(
            "WARNING: cleanup process {} did not exit after SIGTERM, sending SIGKILL",
            pid
        );
        let _ = kill(pid, Signal::SIGKILL);
    }
}

fn run_single_test(
    test_case: &TestCase,
    base_dir: &Path,
    keep_all: bool,
    max_name_len: usize,
) -> anyhow::Result<TestResult> {
    eprint!(
        "[{}] {:.<width$} ",
        test_case.name,
        "",
        width = max_name_len - test_case.name.len() + 3
    );

    // Check if test should run
    if let ShouldRun::No(reason) = test_case.should_run() {
        eprintln!("SKIP ({})", reason);
        return Ok(TestResult {
            name: test_case.name.to_string(),
            outcome: TestOutcome::Skip(reason),
            log_path: None,
        });
    }

    let executable = env::current_exe().context("Failed to detect current executable")?;
    let test_dir = base_dir.join(test_case.name);
    fs::create_dir(&test_dir).context("Failed to create test directory")?;

    // Prepare rootfs: build from container image if needed, otherwise create empty dir
    let rootfs_dir = test_dir.join("rootfs");
    if let Some(containerfile) = test_case.rootfs_image() {
        use test_cases::rootfs;
        if let Err(e) = rootfs::prepare_rootfs(containerfile, &rootfs_dir) {
            eprintln!("SKIP ({e})");
            return Ok(TestResult {
                name: test_case.name.to_string(),
                outcome: TestOutcome::Skip("rootfs image build failed"),
                log_path: None,
            });
        }
    } else {
        fs::create_dir(&rootfs_dir).context("Failed to create rootfs directory")?;
    }

    let log_path = test_dir.join("log.txt");
    let log_file = File::create(&log_path).context("Failed to create log file")?;
    let stdout_path = test_dir.join("stdout.txt");
    let stdout_file = File::create(&stdout_path).context("Failed to create stdout file")?;

    // Use `buildah unshare` for full subuid/subgid mapping + `unshare --net`
    // for network namespace isolation.
    // Fall back to running directly (with a warning) if buildah or unshare isn't available.
    let has_cmd = |cmd: &str| {
        Command::new(cmd)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    let use_buildah_unshare = cfg!(target_os = "linux")
        && std::env::var_os("KRUN_NO_UNSHARE").is_none()
        && has_cmd("buildah")
        && has_cmd("unshare");

    let child = if use_buildah_unshare {
        let exe = executable.display();
        let name = test_case.name;
        let dir = test_dir.display();
        Command::new("buildah")
            .args(["unshare", "--", "unshare", "--net", "--", "sh", "-c"])
            .arg(format!(
                "echo '=== namespace debug ===' >&2; id >&2; cat /proc/self/uid_map >&2; cat /proc/self/gid_map >&2; ip link >&2; ip addr add 127.0.0.1/8 dev lo && ip link set lo up; echo '=== lo setup exit: '$?' ===' >&2; ip addr >&2; echo '=== end debug ===' >&2; exec {exe} start-vm --test-case {name} --tmp-dir {dir}"
            ))
            .stdin(Stdio::piped())
            .stdout(stdout_file)
            .stderr(log_file)
            .spawn()
            .context("Failed to start subprocess for test")?
    } else {
        if cfg!(target_os = "linux") {
            eprintln!("WARNING: buildah not available, running without namespace isolation.");
            eprintln!("Tests may fail if the required network ports are already in use.");
        }
        let mut cmd = Command::new(&executable);
        cmd.arg("start-vm")
            .arg("--test-case")
            .arg(test_case.name)
            .arg("--tmp-dir")
            .arg(&test_dir)
            .stdin(Stdio::piped())
            .stdout(stdout_file)
            .stderr(log_file);
        if cfg!(target_os = "linux") {
            cmd.env("KRUN_NO_UNSHARE", "1");
        }
        cmd.spawn().context("Failed to start subprocess for test")?
    };

    // Enforce a per-test timeout. If the child doesn't exit within the
    // deadline, kill it so we don't hang the entire suite.
    let timeout = std::time::Duration::from_secs(test_case.timeout_secs());
    let mut child = child;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap_or(None).is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            eprintln!("TIMEOUT ({}s)", timeout.as_secs());
            let _ = child.kill();
            let _ = child.wait();
            kill_cleanup_pids(&test_dir);
            return Ok(TestResult {
                name: test_case.name.to_string(),
                outcome: TestOutcome::Timeout,
                log_path: Some(log_path),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let stdout = fs::read(&stdout_path).unwrap_or_default();

    let test_name = test_case.name.to_string();
    let test_dir_clone = test_dir.clone();
    let outcome = match catch_unwind(|| {
        let test = get_test(&test_name).unwrap();
        let test_setup = TestSetup {
            test_case: test_name,
            tmp_dir: test_dir_clone,
        };
        test.check(stdout, test_setup)
    }) {
        Ok(outcome) => outcome,
        Err(_) => TestOutcome::Fail("test.check() panicked".to_string()),
    };

    // Kill any background processes registered for cleanup (e.g. gvproxy).
    // Runs after check() regardless of outcome, so leaked processes are
    // cleaned up even if the test crashed.
    kill_cleanup_pids(&test_dir);

    match &outcome {
        TestOutcome::Pass => {
            eprintln!("OK");
            if !keep_all {
                let _ = fs::remove_dir_all(&test_dir);
            }
        }
        TestOutcome::Fail(reason) => {
            eprintln!("FAIL:");
            eprintln!("{reason}");
        }
        TestOutcome::Skip(reason) => {
            eprintln!("SKIP ({})", reason);
        }
        TestOutcome::Timeout => {
            eprintln!("TIMEOUT");
        }
        TestOutcome::Report(report) => {
            eprintln!("REPORT");
            eprintln!("{:2}", report.text());
            if !keep_all {
                let _ = fs::remove_dir_all(&test_dir);
            }
        }
    }

    Ok(TestResult {
        name: test_case.name.to_string(),
        outcome,
        log_path: Some(log_path),
    })
}

fn write_github_summary(
    results: &[TestResult],
    num_pass: usize,
    num_fail: usize,
    num_skip: usize,
    num_report: usize,
) -> anyhow::Result<()> {
    let summary_path = env::var("GITHUB_STEP_SUMMARY")
        .context("GITHUB_STEP_SUMMARY environment variable not set")?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&summary_path)
        .context("Failed to open GITHUB_STEP_SUMMARY")?;

    let num_ran = num_pass + num_fail;
    let status = if num_fail == 0 { "✅" } else { "❌" };
    let mut extra = Vec::new();
    if num_skip > 0 {
        extra.push(format!("{num_skip} skipped"));
    }
    if num_report > 0 {
        extra.push(format!("{num_report} reports"));
    }
    let extra_msg = if extra.is_empty() {
        String::new()
    } else {
        format!(" ({})", extra.join(", "))
    };

    writeln!(
        file,
        "## {status} Integration Tests - {num_pass}/{num_ran} passed{extra_msg}\n"
    )?;

    for result in results {
        let (icon, status_text) = match &result.outcome {
            TestOutcome::Pass => ("✅", String::new()),
            TestOutcome::Fail(_) => ("❌", String::new()),
            TestOutcome::Skip(reason) => ("⏭️", format!(" - {}", reason)),
            TestOutcome::Timeout => ("⏳", String::from(" - Timeout")),
            TestOutcome::Report(_) => ("📊", String::new()),
        };

        writeln!(file, "<details>")?;
        writeln!(
            file,
            "<summary>{icon} {}{}</summary>\n",
            result.name, status_text
        )?;

        if let TestOutcome::Fail(reason) = &result.outcome {
            writeln!(file, "**Error:**\n```\n{reason}\n```\n---\n")?;
        }

        if let TestOutcome::Report(report) = &result.outcome {
            writeln!(file, "{}", report.gh_markdown())?;
        } else if let Some(log_path) = &result.log_path {
            let log_content = fs::read_to_string(log_path).unwrap_or_default();
            writeln!(file, "```")?;
            // Limit log size to avoid huge summaries (2 MiB limit)
            const MAX_LOG_SIZE: usize = 2 * 1024 * 1024;
            let truncated = if log_content.len() > MAX_LOG_SIZE {
                format!(
                    "... (truncated, showing last 1 MiB) ...\n{}",
                    &log_content[log_content.len() - MAX_LOG_SIZE..]
                )
            } else {
                log_content
            };
            writeln!(file, "{truncated}")?;
            writeln!(file, "```")?;
        }

        writeln!(file, "</details>\n")?;
    }

    Ok(())
}

fn run_tests(
    test_case: &str,
    base_dir: Option<PathBuf>,
    keep_all: bool,
    github_summary: bool,
) -> anyhow::Result<()> {
    // Create the base directory - either use provided path or create a temp one
    let base_dir = match base_dir {
        Some(path) => {
            fs::create_dir_all(&path).context("Failed to create base directory")?;
            path
        }
        None => TempDir::new_in("/tmp", "libkrun-tests")
            .context("Failed to create temp base directory")?
            .into_path(),
    };

    let mut results: Vec<TestResult> = Vec::new();
    let all_tests = test_cases();

    let tests_to_run: Vec<_> = if test_case == "all" {
        all_tests
    } else {
        all_tests
            .into_iter()
            .filter(|t| t.name == test_case)
            .collect()
    };

    if tests_to_run.is_empty() {
        anyhow::bail!("No such test: {test_case}");
    }

    let max_name_len = tests_to_run.iter().map(|t| t.name.len()).max().unwrap_or(0);

    for tc in &tests_to_run {
        results.push(run_single_test(tc, &base_dir, keep_all, max_name_len).context(tc.name)?);
    }

    let num_pass = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Pass))
        .count();
    let num_fail = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Fail(_)))
        .count();
    let num_skip = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Skip(_)))
        .count();
    let num_report = results
        .iter()
        .filter(|r| matches!(r.outcome, TestOutcome::Report(_)))
        .count();
    let num_ran = num_pass + num_fail;

    // Write GitHub Actions summary if requested
    if github_summary {
        write_github_summary(&results, num_pass, num_fail, num_skip, num_report)?;
    }

    let mut extra = Vec::new();
    if num_skip > 0 {
        extra.push(format!("{num_skip} skipped"));
    }
    if num_report > 0 {
        extra.push(format!("{num_report} reports"));
    }
    let extra_msg = if extra.is_empty() {
        String::new()
    } else {
        format!(" ({})", extra.join(", "))
    };

    if num_fail > 0 {
        eprintln!("(See test artifacts at: {})", base_dir.display());
        println!("\nFAIL - {num_pass}/{num_ran} passed{extra_msg}");
        anyhow::bail!("")
    } else {
        if keep_all {
            eprintln!("(See test artifacts at: {})", base_dir.display());
        }
        eprintln!("\nOK - {num_pass}/{num_ran} passed{extra_msg}");
    }

    Ok(())
}

#[derive(clap::Subcommand, Clone, Debug)]
enum CliCommand {
    Test {
        /// Specify which test to run or "all"
        #[arg(long, default_value = "all")]
        test_case: String,
        /// Base directory for test artifacts
        #[arg(long)]
        base_dir: Option<PathBuf>,
        /// Keep all test artifacts even on success
        #[arg(long)]
        keep_all: bool,
        /// Write test results to GitHub Actions job summary ($GITHUB_STEP_SUMMARY)
        #[arg(long)]
        github_summary: bool,
    },
    StartVm {
        #[arg(long)]
        test_case: String,
        #[arg(long)]
        tmp_dir: PathBuf,
    },
}

impl Default for CliCommand {
    fn default() -> Self {
        Self::Test {
            test_case: "all".to_string(),
            base_dir: None,
            keep_all: false,
            github_summary: false,
        }
    }
}

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or_default();

    match command {
        CliCommand::StartVm { test_case, tmp_dir } => start_vm(TestSetup { test_case, tmp_dir }),
        CliCommand::Test {
            test_case,
            base_dir,
            keep_all,
            github_summary,
        } => run_tests(&test_case, base_dir, keep_all, github_summary),
    }
}
