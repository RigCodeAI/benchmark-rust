mod catalog;
mod input;
mod render;
mod scorecard;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
pub(super) struct PublicTruth {
    pub(super) suite_id: String,
    pub(super) categories: Vec<PublicCategory>,
    pub(super) repositories: Vec<PublicRepository>,
    #[serde(default)]
    pub(super) product_cases: Vec<CaseDetail>,
    #[serde(default)]
    pub(super) controller_cases: Vec<CaseDetail>,
}

#[derive(Deserialize)]
pub(super) struct PublicCategory {
    pub(super) category: String,
    pub(super) required_evidence_grade: String,
}

#[derive(Deserialize)]
pub(super) struct PublicRepository {
    pub(super) repository_id: String,
    pub(super) path: String,
}

#[derive(Clone, Deserialize)]
pub(super) struct CaseDetail {
    pub(super) case_id: String,
    pub(super) repository_id: String,
    #[serde(default)]
    pub(super) route: Option<String>,
    #[serde(default)]
    pub(super) sink_family: Option<String>,
    #[serde(default)]
    pub(super) report: Option<String>,
    #[serde(default)]
    pub(super) test_id: Option<String>,
    #[serde(default)]
    pub(super) rule_id: Option<String>,
    #[serde(default)]
    pub(super) reason_code: Option<String>,
}

#[derive(Clone, Serialize)]
pub(super) struct CatalogEntry {
    pub(super) case_id: String,
    pub(super) category: String,
    pub(super) control: String,
    pub(super) expected_disposition: String,
    pub(super) scored_in_accuracy: bool,
    pub(super) required_evidence_grade: String,
    pub(super) repository_path: String,
    pub(super) route: Option<String>,
    pub(super) source_location: String,
    pub(super) sink_location: String,
    pub(super) rule_id: Option<String>,
    pub(super) reason_code: Option<String>,
}

#[derive(Clone)]
pub(super) struct NormalizedFinding {
    pub(super) category: String,
    pub(super) case_id: Option<String>,
    pub(super) route: Option<String>,
    pub(super) path: Option<String>,
    pub(super) line: Option<u64>,
    pub(super) rule_id: Option<String>,
}

pub(super) struct ScannerRun {
    pub(super) tool_name: String,
    pub(super) tool_version: String,
    pub(super) tool_kind: String,
    pub(super) findings: Vec<NormalizedFinding>,
}

struct ScoreArguments {
    truth: PathBuf,
    results: PathBuf,
    format: Option<String>,
    output_dir: PathBuf,
}

pub fn command(
    arguments: &[String],
    program: &'static str,
    default_truth: &'static str,
) -> Option<Result<bool, String>> {
    match arguments.first().map(String::as_str) {
        None | Some("help" | "--help" | "-h") => Some(help(program)),
        Some("score")
            if arguments
                .get(1)
                .is_some_and(|value| value == "--help" || value == "-h") =>
        {
            Some(help(program))
        }
        Some("score-results")
            if arguments
                .get(1)
                .is_some_and(|value| value == "--help" || value == "-h") =>
        {
            println!(
                "Usage: {program} score-results --results PATH [--format json|sarif|csv] [--output-dir DIR] [--truth PATH]"
            );
            Some(Ok(true))
        }
        Some("score-results") => Some(score_results(&arguments[1..], program, default_truth)),
        Some("catalog") => Some(catalog_command(&arguments[1..], default_truth)),
        Some("verify") => Some(verify_command(&arguments[1..], default_truth)),
        Some("version" | "--version" | "-V") => {
            println!("{program} {}", env!("CARGO_PKG_VERSION"));
            Some(Ok(true))
        }
        _ => None,
    }
}

fn help(program: &str) -> Result<bool, String> {
    println!(
        "{program} — independent security benchmark scorer\n\n\
Usage:\n  \
{program} score-results --results PATH [--format json|sarif|csv] [--output-dir DIR]\n  \
{program} score --evidence PATH [--held-out PATH] [--require-promotion]\n  \
{program} catalog [--output-dir DIR] [--check]\n  \
{program} verify\n\n\
Public scoring accepts scanner-neutral JSON, SARIF 2.1.0, or CSV.\n\
The score command is the separate high-assurance qualification interface."
    );
    Ok(true)
}

fn score_results(arguments: &[String], program: &str, default_truth: &str) -> Result<bool, String> {
    let arguments = parse_score_arguments(arguments, default_truth)?;
    let truth: PublicTruth = read_json(&arguments.truth)?;
    validate_public_truth(&truth)?;
    let catalog = catalog::build(&truth);
    let scanner = input::read(
        &arguments.results,
        arguments.format.as_deref(),
        &truth.suite_id,
    )?;
    let scorecard = scorecard::score(&truth, &catalog, scanner);
    render::write_all(&arguments.output_dir, &scorecard)?;
    println!(
        "{}: TP={} FP={} FN={} TN={} TPR={:.4} FPR={:.4} score={:.4}",
        scorecard.tool.name,
        scorecard.summary.tp,
        scorecard.summary.fp,
        scorecard.summary.fn_count,
        scorecard.summary.tn,
        scorecard.summary.tpr,
        scorecard.summary.fpr,
        scorecard.summary.balanced_accuracy
    );
    println!("wrote {}/scorecard.json", arguments.output_dir.display());
    println!("wrote {}/scorecard.csv", arguments.output_dir.display());
    println!("wrote {}/scorecard.html", arguments.output_dir.display());
    let _ = program;
    Ok(true)
}

fn parse_score_arguments(
    arguments: &[String],
    default_truth: &str,
) -> Result<ScoreArguments, String> {
    let mut values = arguments.iter();
    let mut truth = PathBuf::from(default_truth);
    let mut results = None;
    let mut format = None;
    let mut output_dir = PathBuf::from("results/scorecard");
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--truth" => truth = PathBuf::from(values.next().ok_or("--truth requires PATH")?),
            "--results" => {
                results = Some(PathBuf::from(
                    values.next().ok_or("--results requires PATH")?,
                ))
            }
            "--format" => format = Some(values.next().ok_or("--format requires VALUE")?.clone()),
            "--output-dir" => {
                output_dir = PathBuf::from(values.next().ok_or("--output-dir requires DIR")?)
            }
            "--help" | "-h" => return Err("use the top-level --help output".to_owned()),
            _ => return Err(format!("unknown score-results argument: {argument}")),
        }
    }
    Ok(ScoreArguments {
        truth,
        results: results.ok_or("--results is required")?,
        format,
        output_dir,
    })
}

fn catalog_command(arguments: &[String], default_truth: &str) -> Result<bool, String> {
    let (truth_path, output_dir, check) = parse_catalog_arguments(arguments, default_truth)?;
    let truth: PublicTruth = read_json(&truth_path)?;
    validate_public_truth(&truth)?;
    let outputs = catalog::render(&truth)?;
    if check {
        catalog::check(&output_dir, &outputs)?;
        println!("catalog is current: {}", output_dir.display());
    } else {
        catalog::write(&output_dir, &outputs)?;
        println!("wrote {}/catalog.json", output_dir.display());
        println!("wrote {}/expected-results.csv", output_dir.display());
    }
    Ok(true)
}

fn verify_command(arguments: &[String], default_truth: &str) -> Result<bool, String> {
    if !arguments.is_empty() {
        return Err("verify does not accept arguments".to_owned());
    }
    let truth_path = PathBuf::from(default_truth);
    let truth: PublicTruth = read_json(&truth_path)?;
    validate_public_truth(&truth)?;
    let outputs = catalog::render(&truth)?;
    catalog::check(Path::new("cases"), &outputs)?;
    if std::fs::read("product-evidence-v1.schema.json").map_err(|error| error.to_string())?
        != std::fs::read("schemas/qualification-evidence-v1.schema.json")
            .map_err(|error| error.to_string())?
    {
        return Err("qualification schema copy is stale".to_owned());
    }
    for (path, format) in [
        ("results/examples/example-sast.sarif", "sarif"),
        ("results/examples/example-scanner.json", "json"),
        ("results/examples/example-scanner.csv", "csv"),
    ] {
        input::validate_example(Path::new(path), format, &truth.suite_id)?;
    }
    println!(
        "verified {} categories, {} public accuracy cases, and the scanner-neutral example",
        truth.categories.len(),
        truth.categories.len() * 2
    );
    Ok(true)
}

fn parse_catalog_arguments(
    arguments: &[String],
    default_truth: &str,
) -> Result<(PathBuf, PathBuf, bool), String> {
    let mut values = arguments.iter();
    let mut truth = PathBuf::from(default_truth);
    let mut output_dir = PathBuf::from("cases");
    let mut check = false;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--truth" => truth = PathBuf::from(values.next().ok_or("--truth requires PATH")?),
            "--output-dir" => {
                output_dir = PathBuf::from(values.next().ok_or("--output-dir requires DIR")?)
            }
            "--check" => check = true,
            _ => return Err(format!("unknown catalog argument: {argument}")),
        }
    }
    Ok((truth, output_dir, check))
}

fn validate_public_truth(truth: &PublicTruth) -> Result<(), String> {
    if truth.suite_id.is_empty() || truth.categories.is_empty() {
        return Err("public truth denominator is empty".to_owned());
    }
    let mut categories = BTreeMap::new();
    for category in &truth.categories {
        if categories.insert(&category.category, ()).is_some() {
            return Err(format!("duplicate category: {}", category.category));
        }
    }
    Ok(())
}

pub(super) fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_INPUT_BYTES
    {
        return Err(format!("unsafe input: {}", path.display()));
    }
    serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}
