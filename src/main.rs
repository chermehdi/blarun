use std::{path::PathBuf, process::Command, time::Instant};

use anyhow::Result;
use clap::Parser;
use git2::{DiffOptions, Oid, Repository};
use std::path::Path;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    repository: String,

    // File where to write the latest processed commit
    #[arg(short, long)]
    commit_file: String,

    // The input file to be read by the solution
    #[arg(short, long)]
    input_file: String,
}

// Extract the changed files in a repository between `from_commit` and the current head commit.
fn extract_changed(repo: &Repository, from_commit: &str) -> Result<Vec<PathBuf>> {
    let current_commit = repo.head()?.peel_to_commit()?.id();

    println!("Latest processed commit: {from_commit}");
    println!("Current commit: {current_commit}");

    let old_tree = repo.find_commit(Oid::from_str(from_commit)?)?.tree()?;
    let current_tree = repo.find_commit(current_commit)?.tree()?;

    let mut diff_opts = DiffOptions::new();
    let diff =
        repo.diff_tree_to_tree(Some(&old_tree), Some(&current_tree), Some(&mut diff_opts))?;

    Ok(diff
        .deltas()
        .into_iter()
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
        } else {
            if let Ok(sub_dir_res) = list_paths(entry.path().as_path()) {
                result.extend(sub_dir_res)
            }
        }
    }

    Ok(result)
}

#[derive(Debug)]
enum Verdict {
    Ac,
    Wa,
    UnknownExt,
}

#[derive(Debug)]
struct ExecResult {
    verdict: Verdict,
    times: Vec<u128>,
}

fn run_cpp(context: RunContext) -> Result<ExecResult> {
    let tmp_dir = tempfile::tempdir()?;

    let mut output_path = tmp_dir.path().to_path_buf();
    output_path.push("sol");

    let mut res = Command::new("g++")
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
            println!(
                "Finished compilation of the target: {output_path:?} with exit code: {status}"
            );
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

    println!(
        "Copying file from: {:?} to {:?}",
        context.input_file, input_file
    );

    // Copy the input file to the same directory as the executable
    std::fs::copy(context.input_file, input_file)?;

    let mut times = vec![];
    for i in 0..10 {
        let start_time = Instant::now();
        let res = Command::new(output_path.to_str().unwrap()).output()?;
        println!(
            "Finished execution of the solution with status: {:?}",
            res.status.code()
        );
        if let Some(code) = res.status.code() {
            if code != 0 {
                return Err(anyhow::anyhow!(
                    "Failed to run the solution file: none-zero exit code"
                ));
            }
        }

        let elapsed = Instant::now() - start_time;
        println!("Execution #{i} finished in: {elapsed:?}");
        times.push(elapsed.as_millis());
    }

    return Ok(ExecResult {
        verdict: Verdict::Ac,
        times,
    });
}

fn run_file(context: RunContext) -> Result<ExecResult> {
    //- [x] deduce language from extension
    //- [ ] Prepare run directory
    //- [ ] Compiler (if needed)
    //- [ ] copy binary and input to run directory
    //- [ ] run and compute time
    let extension = context
        .solution_file
        .extension()
        .ok_or(anyhow::anyhow!("failed to get file extension"))?;

    let mut source_file = context.root.to_path_buf();
    source_file.push(context.solution_file);
    match extension.to_str().unwrap() {
        "cpp" => run_cpp(context),
        _ => Ok(ExecResult {
            verdict: Verdict::UnknownExt,
            times: vec![],
        }),
    }
}

struct RunContext<'a> {
    input_file: &'a Path,
    solution_file: &'a Path,
    root: &'a Path,
}

impl<'a> RunContext<'a> {
    fn abs_solution(&self) -> PathBuf {
        let mut result = self.root.to_path_buf();
        result.push(self.solution_file);
        result
    }
}

fn main() {
    let args = Args::parse();

    let repo = match Repository::init(args.repository) {
        Ok(repo) => repo,
        Err(e) => panic!("failed to init: {}", e),
    };

    // Ensure that if there is an existing commit file, let's use the commit as base for computing
    // the diff, otherwise, the diff should include all the files under the submissions directory.
    let changed_paths = match std::fs::read_to_string(PathBuf::from(&args.commit_file)) {
        Ok(content) => {
            let latest_commit = content.trim();
            extract_changed(&repo, &latest_commit)
        }
        Err(_) => {
            let mut root = repo.workdir().unwrap().to_owned();
            root.push("submissions");
            list_paths(root.as_path())
        }
    };

    for ele in changed_paths.expect("") {
        println!("Changed path: {ele:?}");
        let run_context = RunContext {
            input_file: &PathBuf::from(&args.input_file),
            root: repo.workdir().unwrap(),
            solution_file: &ele,
        };
        match run_file(run_context) {
            Ok(exec_result) => {
                println!("Result is: {exec_result:?}");
            }
            Err(e) => {
                println!("Failed {e:?}")
            }
        }
    }
}
