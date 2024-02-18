use log::{debug, info};
use serde_with::{serde_as, DurationMilliSeconds};
use std::collections::BTreeMap;
use std::time::Duration;
use std::{path::PathBuf, process::Command, time::Instant};
use wait_timeout::ChildExt;

use anyhow::Result;
use clap::Parser;
use git2::{DiffOptions, Oid, Repository};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    repository: String,

    // File where to write the latest processed commit
    #[arg(long)]
    commit_file: String,

    // The input file to be read by the solution
    #[arg(long)]
    input_file: String,

    // Location of the expected answer file
    #[arg(long)]
    expected_output: String,

    // Location where to write the results
    #[arg(long)]
    results_file: String,

    // How long to let the submission run before declaring it slow
    #[arg(long)]
    timeout_sec: u64,
}

// Extract the changed files in a repository between `from_commit` and the current head commit.
fn extract_changed(repo: &Repository, from_commit: &str) -> Result<Vec<PathBuf>> {
    let current_commit = repo.head()?.peel_to_commit()?.id();

    info!("Latest processed commit: {from_commit}");
    info!("Current commit: {current_commit}");

    let old_tree = repo.find_commit(Oid::from_str(from_commit)?)?.tree()?;
    let current_tree = repo.find_commit(current_commit)?.tree()?;

    let mut diff_opts = DiffOptions::new();
    let diff =
        repo.diff_tree_to_tree(Some(&old_tree), Some(&current_tree), Some(&mut diff_opts))?;

    Ok(diff
        .deltas()
        .filter(|delta| {
            // Only care about changed files inside the submissions directory
            let new_file_path = delta.new_file().path().unwrap();
            new_file_path.starts_with("submissions")
        })
        .map(|delta| delta.new_file().path().map(|p| p.to_owned()).unwrap())
        .collect())
}

// Recursively list all the fiels in the `root` directory
fn list_paths(root: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut result = vec![];
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.path().is_file() {
            result.push(entry.path());
        } else if let Ok(sub_dir_res) = list_paths(entry.path().as_path()) {
            result.extend(sub_dir_res)
        }
    }

    Ok(result)
}

#[derive(Debug)]
enum Verdict {
    Ac,
    Wa,
    Tle,
    UnknownExt,
}

#[derive(Debug)]
struct ExecResult {
    verdict: Verdict,
    times: Vec<Duration>,
}

impl ExecResult {
    pub fn avg_time(&self) -> Duration {
        if self.times.is_empty() {
            return Duration::from_millis(0);
        }
        let sum: Duration = self.times.iter().sum();
        sum / (self.times.len() as u32)
    }

    pub fn median(&self) -> Duration {
        if self.times.is_empty() {
            return Duration::from_millis(0);
        }
        let mut times = self.times.clone();
        times.sort();
        times[times.len() / 2]
    }
}

fn compute_verdict(output: &Path, expected_output: &Path) -> Result<Verdict> {
    debug!("Comparing output {output:?} vs {expected_output:?}");
    let mut output = File::open(output)?;
    let mut expected_output = File::open(expected_output)?;
    let output_len = output.metadata()?.len();
    let expected_output_len = expected_output.metadata()?.len();
    if expected_output_len != output_len {
        debug!("Output size is different: expected {expected_output_len}, Got {output_len}");
        return Ok(Verdict::Wa);
    }

    // TODO: depending on the size of the input, we might want to make these buffers larger.
    let mut b1 = [0u8; 4096];
    let mut b2 = [0u8; 4096];

    let mut reads = 1;
    loop {
        debug!("Executing read-loop #{reads}");
        reads += 1;
        let bytes_read1 = output.read(&mut b1)?;
        let bytes_read2 = expected_output.read(&mut b2)?;

        if bytes_read1 != bytes_read2 || b1[..bytes_read1] != b2[..bytes_read2] {
            return Ok(Verdict::Wa);
        }

        if bytes_read1 == 0 {
            break;
        }
    }

    Ok(Verdict::Ac)
}

fn run_cpp(context: &RunContext) -> Result<ExecResult> {
    // let tmp_dir = tempfile::tempdir()?;
    let tmp_dir = PathBuf::from("/tmp/work");

    let mut output_path = tmp_dir.clone();
    output_path.push("sol");

    let mut res = Command::new("/usr/bin/g++")
        .args(vec![
            "-Wall",
            "--std=c++17",
            "-O3",
            context.abs_solution().to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
        ])
        .spawn()?;

    match res.wait() {
        Ok(status) => {
            info!("Finished compilation of the target: {output_path:?} with exit code: {status}");
            if let Some(code) = status.code() {
                if code != 0 {
                    return Err(anyhow::anyhow!(
                        "Failed to compile solution file: none-zero exit code"
                    ));
                }
            }
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to compile solution file: {e:?}")),
    }

    let mut input_file = tmp_dir.clone();
    input_file.push("input.txt");
    let mut output_file = tmp_dir.clone();
    output_file.push("output.txt");

    info!(
        "Symlinking file from: {:?} to {:?}",
        context.input_file, input_file
    );

    std::os::unix::fs::symlink(context.input_file, &input_file)?;

    let mut times = vec![];
    for i in 0..10 {
        debug!("Starting execution #{i}");
        let start_time = Instant::now();
        let mut child = Command::new(output_path.to_str().unwrap())
            .current_dir(&tmp_dir)
            .spawn()?;

        match child.wait_timeout(context.timeout) {
            Ok(Some(result)) => {
                info!(
                    "Finished execution of the solution with status: {:?}",
                    result.code()
                );
                if let Some(code) = result.code() {
                    if code != 0 {
                        return Err(anyhow::anyhow!(
                            "Failed to run the solution file: none-zero exit code"
                        ));
                    }
                }
            }
            Ok(None) => {
                debug!("Child process timed out");
                child.kill().unwrap();
                let code = child.wait()?.code();
                debug!("Killed with exit code: {code:?}");
                return Ok(ExecResult {
                    verdict: Verdict::Tle,
                    times,
                });
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to run the solution file: {e:?}"));
            }
        }

        let elapsed = Instant::now() - start_time;
        debug!("Execution #{i} finished in: {elapsed:?}");
        times.push(elapsed);

        debug!(
            "Computing verdict using {output_file:?} and {:?}",
            context.expected_output
        );
        let verdict = compute_verdict(&output_file, context.expected_output)?;
        if !matches!(verdict, Verdict::Ac) {
            debug!("Submission is not correct, aborting further runs");
            return Ok(ExecResult {
                verdict: Verdict::Wa,
                times,
            });
        }
    }

    Ok(ExecResult {
        verdict: Verdict::Ac,
        times,
    })
}

fn run_java(context: &RunContext) -> Result<ExecResult> {
    let tmp_dir = tempfile::tempdir()?;

    let mut src_path = tmp_dir.path().to_path_buf();
    src_path.push("Main.java");

    // Copy the source file to the compilation directory
    std::fs::copy(context.abs_solution(), &src_path)?;
    let mut res = Command::new("javac")
        .current_dir(tmp_dir.path())
        .args(vec![&src_path])
        .spawn()?;

    match res.wait() {
        Ok(status) => {
            debug!("Finished compilation of the target: {src_path:?} with exit code: {status}");
            if let Some(code) = status.code() {
                if code != 0 {
                    return Err(anyhow::anyhow!(
                        "Failed to compile solution file: none-zero exit code"
                    ));
                }
            }
        }
        Err(e) => return Err(anyhow::anyhow!("Failed to compile solution file: {e:?}")),
    }

    let mut input_file = tmp_dir.path().to_path_buf();
    input_file.push("input.txt");

    let mut output_file = tmp_dir.path().to_path_buf();
    output_file.push("output.txt");
    let mut main_class = tmp_dir.path().to_path_buf();
    main_class.push("Main");

    info!(
        "Symlinking file from: {:?} to {:?}",
        context.input_file, input_file
    );

    std::os::unix::fs::symlink(context.input_file, &input_file)?;

    let mut times = vec![];
    for i in 0..10 {
        debug!("Starting execution run #{i}");
        let start_time = Instant::now();
        let mut child = Command::new("java")
            .args(vec!["Main"])
            .current_dir(&tmp_dir)
            .spawn()?;

        match child.wait_timeout(context.timeout) {
            Ok(Some(result)) => {
                info!(
                    "Finished execution of the solution with status: {:?}",
                    result.code()
                );
                if let Some(code) = result.code() {
                    if code != 0 {
                        return Err(anyhow::anyhow!(
                            "Failed to run the solution file: none-zero exit code"
                        ));
                    }
                }
            }
            Ok(None) => {
                debug!("Child process timed out");
                child.kill().unwrap();
                let code = child.wait()?.code();
                debug!("Killed with exit code: {code:?}");
                return Ok(ExecResult {
                    verdict: Verdict::Tle,
                    times,
                });
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to run the solution file: {e:?}"));
            }
        }

        let elapsed = Instant::now() - start_time;
        debug!("Execution #{i} finished in: {elapsed:?}");
        times.push(elapsed);

        debug!(
            "Computing verdict using {output_file:?} and {:?}",
            context.expected_output
        );
        let verdict = compute_verdict(&output_file, context.expected_output)?;
        if !matches!(verdict, Verdict::Ac) {
            debug!("Submission is not correct, aborting further runs");
            return Ok(ExecResult {
                verdict: Verdict::Wa,
                times,
            });
        }
    }

    Ok(ExecResult {
        verdict: Verdict::Ac,
        times,
    })
}

fn run_python(context: &RunContext) -> Result<ExecResult> {
    let tmp_dir = tempfile::tempdir()?;

    let mut src_path = tmp_dir.path().to_path_buf();
    src_path.push("main.py");

    // Copy the source file to the compilation directory
    std::fs::copy(context.abs_solution(), &src_path)?;

    let mut input_file = tmp_dir.path().to_path_buf();
    input_file.push("input.txt");

    let mut output_file = tmp_dir.path().to_path_buf();
    output_file.push("output.txt");

    info!(
        "Symlinking file from: {:?} to {:?}",
        context.input_file, input_file
    );

    std::os::unix::fs::symlink(context.input_file, input_file)?;

    let mut times = vec![];
    for i in 0..10 {
        let start_time = Instant::now();
        let mut child = Command::new("python3")
            .args(vec!["main.py"])
            .current_dir(&tmp_dir)
            .spawn()?;

        match child.wait_timeout(context.timeout) {
            Ok(Some(result)) => {
                info!(
                    "Finished execution of the solution with status: {:?}",
                    result.code()
                );
                if let Some(code) = result.code() {
                    if code != 0 {
                        return Err(anyhow::anyhow!(
                            "Failed to run the solution file: none-zero exit code"
                        ));
                    }
                }
            }
            Ok(None) => {
                debug!("Child process timed out");
                child.kill().unwrap();
                let code = child.wait()?.code();
                debug!("Killed with exit code: {code:?}");
                return Ok(ExecResult {
                    verdict: Verdict::Tle,
                    times,
                });
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to run the solution file: {e:?}"));
            }
        }

        let elapsed = Instant::now() - start_time;
        debug!("Execution #{i} finished in: {elapsed:?}");
        times.push(elapsed);

        let verdict = compute_verdict(&output_file, context.expected_output)?;
        // Exit early
        if !matches!(verdict, Verdict::Ac) {
            debug!("Submission is not correct, aborting further runs");
            return Ok(ExecResult {
                verdict: Verdict::Wa,
                times,
            });
        }
    }

    Ok(ExecResult {
        verdict: Verdict::Ac,
        times,
    })
}

fn run_node(context: &RunContext) -> Result<ExecResult> {
    let tmp_dir = tempfile::tempdir()?;

    let mut src_path = tmp_dir.path().to_path_buf();
    src_path.push("main.js");

    // Copy the source file to the compilation directory
    std::fs::copy(context.abs_solution(), &src_path)?;

    let mut input_file = tmp_dir.path().to_path_buf();
    input_file.push("input.txt");

    let mut output_file = tmp_dir.path().to_path_buf();
    output_file.push("output.txt");

    info!(
        "Symlinking file from: {:?} to {:?}",
        context.input_file, input_file
    );

    std::os::unix::fs::symlink(context.input_file, input_file)?;

    let mut times = vec![];
    for i in 0..10 {
        let start_time = Instant::now();
        let mut child = Command::new("node")
            .args(vec!["main.js"])
            .current_dir(&tmp_dir)
            .spawn()?;

        match child.wait_timeout(context.timeout) {
            Ok(Some(result)) => {
                info!(
                    "Finished execution of the solution with status: {:?}",
                    result.code()
                );
                if let Some(code) = result.code() {
                    if code != 0 {
                        return Err(anyhow::anyhow!(
                            "Failed to run the solution file: none-zero exit code"
                        ));
                    }
                }
            }
            Ok(None) => {
                debug!("Child process timed out");
                child.kill().unwrap();
                let code = child.wait()?.code();
                debug!("Killed with exit code: {code:?}");
                return Ok(ExecResult {
                    verdict: Verdict::Tle,
                    times,
                });
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to run the solution file: {e:?}"));
            }
        }

        let elapsed = Instant::now() - start_time;
        debug!("Execution #{i} finished in: {elapsed:?}");
        times.push(elapsed);

        let verdict = compute_verdict(&output_file, context.expected_output)?;
        if !matches!(verdict, Verdict::Ac) {
            debug!("Submission is not correct, aborting further runs");
            return Ok(ExecResult {
                verdict: Verdict::Wa,
                times,
            });
        }
    }

    Ok(ExecResult {
        verdict: Verdict::Ac,
        times,
    })
}

fn extract_language(context: &RunContext) -> String {
    context
        .solution_file
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn run_file(context: &RunContext) -> Result<ExecResult> {
    let extension = context
        .solution_file
        .extension()
        .ok_or(anyhow::anyhow!("failed to get file extension"))?;

    let mut source_file = context.root.to_path_buf();
    source_file.push(context.solution_file);
    match extension.to_str().unwrap() {
        "cpp" => run_cpp(context),
        "java" => run_java(context),
        "py" => run_python(context),
        "js" => run_node(context),
        _ => Ok(ExecResult {
            verdict: Verdict::UnknownExt,
            times: vec![],
        }),
    }
}

#[derive(Debug)]
struct RunContext<'a> {
    input_file: &'a Path,
    expected_output: &'a Path,
    solution_file: &'a Path,
    timeout: Duration,
    root: &'a Path,
    user: &'a str,
}

impl<'a> RunContext<'a> {
    fn abs_solution(&self) -> PathBuf {
        let mut result = self.root.to_path_buf();
        result.push(self.solution_file);
        result
    }
}

#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Clone)]
struct Record {
    username: String,
    #[serde_as(as = "DurationMilliSeconds<String>")]
    avg: Duration,

    #[serde_as(as = "DurationMilliSeconds<String>")]
    median: Duration,

    lang: String,
}

impl PartialOrd for Record {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Record {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if !matches!(self.avg.cmp(&other.avg), std::cmp::Ordering::Equal) {
            return self.avg.cmp(&other.avg);
        }
        if !matches!(self.median.cmp(&other.median), std::cmp::Ordering::Equal) {
            return self.median.cmp(&other.median);
        }
        self.username.cmp(&other.username)
    }
}

fn extract_user(path: &Path) -> Result<String> {
    Ok(path
        .parent()
        .ok_or(anyhow::anyhow!("could not get parent"))?
        .file_name()
        .ok_or(anyhow::anyhow!("could not get filename"))?
        .to_str()
        .ok_or(anyhow::anyhow!("could not transform to str"))?
        .to_owned())
}

fn load_existing_stats(res_file: &str) -> Result<Vec<Record>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(res_file)?;
    let mut rdr = csv::Reader::from_reader(file);
    let mut values = vec![];
    for record in rdr.deserialize() {
        let record = record?;
        values.push(record)
    }
    values.sort();
    Ok(values)
}

fn write_latest_commit(repo: &Repository, args: &Args) -> Result<()> {
    let mut commit_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&args.commit_file)?;

    let current_commit = repo.head()?.peel_to_commit()?.id();
    info!("Writing latest commit: {current_commit:?}");
    commit_file.write_all(format!("{current_commit:?}").as_bytes())?;
    commit_file.sync_all()?;
    Ok(())
}

fn main() {
    let args = Args::parse();

    env_logger::init();

    let repo = match Repository::init(&args.repository) {
        Ok(repo) => repo,
        Err(e) => panic!("failed to init: {}", e),
    };

    debug!("Results file is: {}", args.results_file);
    let mut current_records =
        load_existing_stats(&args.results_file).expect("should load existing records");

    let mut records = BTreeMap::new();
    for record in current_records.iter() {
        records.insert(record.username.clone(), record.clone());
    }

    // Ensure that if there is an existing commit file, let's use the commit as base for computing
    // the diff, otherwise, the diff should include all the files under the submissions directory.
    let changed_paths = match std::fs::read_to_string(PathBuf::from(&args.commit_file)) {
        Ok(content) => {
            let latest_commit = content.trim();
            extract_changed(&repo, latest_commit)
        }
        Err(_) => {
            let mut root = repo.workdir().unwrap().to_owned();
            root.push("submissions");
            list_paths(root.as_path())
        }
    };

    let mut new_records = vec![];
    for path in changed_paths.expect("Should extract diffs") {
        debug!("Changed path: {path:?}");
        let user = extract_user(&path).expect("should extract user");
        let run_context = RunContext {
            input_file: &PathBuf::from(&args.input_file),
            expected_output: &PathBuf::from(&args.expected_output),
            root: repo.workdir().unwrap(),
            solution_file: &path,
            user: user.as_ref(),
            timeout: Duration::from_secs(args.timeout_sec),
        };

        match run_file(&run_context) {
            Ok(exec_result) => {
                info!("Submission from user: {} has finished with verdict: {:?} and with an AVG execution time of: {:?} and MED of {:?}", run_context.user, exec_result.verdict, exec_result.avg_time(), exec_result.median());
                if matches!(exec_result.verdict, Verdict::Ac) {
                    new_records.push(Record {
                        username: run_context.user.to_owned(),
                        median: exec_result.median(),
                        avg: exec_result.avg_time(),
                        lang: extract_language(&run_context),
                    })
                }
            }
            Err(e) => {
                info!("Failed to run {run_context:?} with error: {e:?}")
            }
        };
    }

    for rec in new_records.into_iter() {
        if records.contains_key(&rec.username) {
            let existing_record = records.get(&rec.username).unwrap();
            if matches!(existing_record.cmp(&rec), std::cmp::Ordering::Greater) {
                // Update if the new time is better than the old time.
                records.insert(rec.username.clone(), rec);
            }
        } else {
            records.insert(rec.username.clone(), rec);
        }
    }

    let updated_records = records.values().collect::<Vec<_>>();

    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(&args.results_file)
        .expect("should open results file");

    current_records.sort();
    let mut writer = csv::Writer::from_writer(file);
    for rec in updated_records {
        writer.serialize(rec).expect("should write csv");
    }
    writer.flush().expect("should flush");

    write_latest_commit(&repo, &args).expect("should write commit data");
}
