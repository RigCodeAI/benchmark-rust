use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Deserialize)]
struct Truth {
    suite_id: String,
    exact_family: Value,
    source_digests: BTreeMap<String, String>,
    categories: Vec<Category>,
    repositories: Vec<Repository>,
    promotion_requirements: Requirements,
}

#[derive(Deserialize)]
struct Category {
    category: String,
    mapping: String,
    required_evidence_grade: String,
}

#[derive(Deserialize)]
struct Repository {
    repository_id: String,
    role: String,
}

#[derive(Deserialize)]
struct Requirements {
    minimum_held_out_applications: u64,
    minimum_held_out_vulnerable_categories: u64,
    minimum_held_out_safe_categories: u64,
    required_publication_state: String,
    required_coverage_verdict: String,
    maximum_false_positives: u64,
    maximum_false_negatives: u64,
}

#[derive(Deserialize)]
struct Evidence {
    schema_version: String,
    suite_id: String,
    layer: String,
    repository_id: String,
    independent_truth_digest: Option<String>,
    runtime_coordinate: String,
    framework_coordinate: String,
    ordinary_product_path: bool,
    publication_state: String,
    coverage_verdict: String,
    sealed_transcripts_verified: bool,
    authenticated_readback_verified: bool,
    failed_requests: u64,
    unexpected_facts: u64,
    unresolved_obligations: u64,
    observations: Vec<Observation>,
    evidence_digest: String,
}

#[derive(Deserialize)]
struct Observation {
    case_id: String,
    disposition: String,
    evidence_grade: String,
    repository_path: String,
    sink_identity: String,
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    suite_id: String,
    evidence_digest: String,
    evidence_envelope_closed: bool,
    held_out_applications_passed: bool,
    promotion_eligible: bool,
    score: Score,
    category_scores: Vec<CategoryScore>,
    reason_codes: Vec<String>,
}

#[derive(Default, Serialize)]
struct Score {
    tp: u64,
    fp: u64,
    #[serde(rename = "fn")]
    fn_count: u64,
    tn: u64,
    unknown_controls_passed: u64,
    unsupported_controls_passed: u64,
    evidence_grade_mismatches: u64,
    unresolved: u64,
    unexpected_observations: u64,
    passed: bool,
}

#[derive(Serialize)]
struct CategoryScore {
    category: String,
    mapping: String,
    required_evidence_grade: String,
    tp: u64,
    fp: u64,
    #[serde(rename = "fn")]
    fn_count: u64,
    tn: u64,
    evidence_grade_mismatches: u64,
    unresolved: u64,
    passed: bool,
}

struct Arguments {
    truth: PathBuf,
    evidence: PathBuf,
    held_out: Vec<PathBuf>,
    output: Option<PathBuf>,
    require_promotion: bool,
}

fn main() {
    match run() {
        Ok(true) => {}
        Ok(false) => std::process::exit(30),
        Err(error) => {
            eprintln!("benchmark_error: {error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<bool, String> {
    let arguments = parse_arguments()?;
    let truth: Truth = read_json(&arguments.truth)?;
    validate_truth(&truth, &arguments.truth)?;
    let evidence = read_evidence(&arguments.evidence, &truth, "LOCKED")?;
    let held_out = arguments
        .held_out
        .iter()
        .map(|path| read_evidence(path, &truth, "HELD_OUT"))
        .collect::<Result<Vec<_>, _>>()?;
    let report = score(&truth, evidence, &held_out);
    let encoded = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    if let Some(output) = arguments.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(output, [&encoded[..], b"\n"].concat())
            .map_err(|error| error.to_string())?;
    } else {
        println!(
            "{}",
            String::from_utf8(encoded).map_err(|error| error.to_string())?
        );
    }
    Ok(!arguments.require_promotion || report.promotion_eligible)
}

fn parse_arguments() -> Result<Arguments, String> {
    let mut values = std::env::args().skip(1);
    if values.next().as_deref() != Some("score") {
        return Err("usage: benchmark-rust score --evidence PATH [--truth PATH] [--held-out PATH] [--output PATH] [--require-promotion]".to_owned());
    }
    let mut truth = PathBuf::from("truth-v1.json");
    let mut evidence = None;
    let mut held_out = Vec::new();
    let mut output = None;
    let mut require_promotion = false;
    while let Some(argument) = values.next() {
        match argument.as_str() {
            "--truth" => truth = PathBuf::from(values.next().ok_or("--truth requires PATH")?),
            "--evidence" => {
                evidence = Some(PathBuf::from(
                    values.next().ok_or("--evidence requires PATH")?,
                ))
            }
            "--held-out" => held_out.push(PathBuf::from(
                values.next().ok_or("--held-out requires PATH")?,
            )),
            "--output" => {
                output = Some(PathBuf::from(
                    values.next().ok_or("--output requires PATH")?,
                ))
            }
            "--require-promotion" => require_promotion = true,
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(Arguments {
        truth,
        evidence: evidence.ok_or("--evidence is required")?,
        held_out,
        output,
        require_promotion,
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
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

fn validate_truth(truth: &Truth, truth_path: &Path) -> Result<(), String> {
    if truth.suite_id.is_empty() || truth.categories.is_empty() || truth.source_digests.is_empty() {
        return Err("truth denominator is empty".to_owned());
    }
    let categories = truth
        .categories
        .iter()
        .map(|category| category.category.as_str())
        .collect::<BTreeSet<_>>();
    if categories.len() != truth.categories.len() {
        return Err("truth contains duplicate categories".to_owned());
    }
    let root = truth_path.parent().unwrap_or_else(|| Path::new("."));
    for (relative, expected) in &truth.source_digests {
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(format!("unsafe source path: {relative}"));
        }
        let candidate = root.join(relative_path);
        let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_INPUT_BYTES
        {
            return Err(format!("unsafe source: {relative}"));
        }
        let observed = format!(
            "sha256:{:x}",
            Sha256::digest(std::fs::read(&candidate).map_err(|error| error.to_string())?)
        );
        if &observed != expected {
            return Err(format!("source digest mismatch: {relative}"));
        }
    }
    Ok(())
}

fn read_evidence(path: &Path, truth: &Truth, layer: &str) -> Result<Evidence, String> {
    let mut value: Value = read_json(path)?;
    let evidence: Evidence =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    let expected_schema = truth
        .suite_id
        .strip_suffix("-v1")
        .map(|prefix| format!("{prefix}-product-evidence/v1"))
        .ok_or("suite id must end in -v1")?;
    let runtimes = string_list(&truth.exact_family, "runtime_coordinates")?;
    let frameworks = if truth.exact_family.get("framework_coordinates").is_some() {
        string_list(&truth.exact_family, "framework_coordinates")?
    } else {
        string_list(&truth.exact_family, "framework_coordinate")?
    };
    let repository_valid = if layer == "LOCKED" {
        truth.repositories.iter().any(|repository| {
            repository.repository_id == evidence.repository_id
                && repository.role == "ORDINARY_PRODUCT_APPLICATION"
        })
    } else {
        !truth
            .repositories
            .iter()
            .any(|repository| repository.repository_id == evidence.repository_id)
            && evidence
                .independent_truth_digest
                .as_deref()
                .is_some_and(valid_digest)
    };
    let claimed = evidence.evidence_digest.clone();
    value["evidence_digest"] = Value::String(String::new());
    if evidence.schema_version != expected_schema
        || evidence.suite_id != truth.suite_id
        || evidence.layer != layer
        || !repository_valid
        || !runtimes.contains(&evidence.runtime_coordinate)
        || !frameworks.contains(&evidence.framework_coordinate)
        || claimed != digest(&value)?
    {
        return Err(format!("invalid evidence envelope: {}", path.display()));
    }
    let ids = evidence
        .observations
        .iter()
        .map(|observation| observation.case_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != evidence.observations.len()
        || evidence.observations.iter().any(|observation| {
            observation.repository_path.is_empty()
                || observation.repository_path.starts_with('/')
                || observation
                    .repository_path
                    .split('/')
                    .any(|part| part == "..")
                || observation.sink_identity.is_empty()
        })
    {
        return Err(format!("invalid observations: {}", path.display()));
    }
    Ok(evidence)
}

fn score(truth: &Truth, evidence: Evidence, held_out: &[Evidence]) -> Report {
    let expected = expected_cases(truth);
    let observed = evidence
        .observations
        .iter()
        .map(|observation| (observation.case_id.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let mut score = Score::default();
    let mut rows = Vec::new();
    for category in &truth.categories {
        let mut row = CategoryScore {
            category: category.category.clone(),
            mapping: category.mapping.clone(),
            required_evidence_grade: category.required_evidence_grade.clone(),
            tp: 0,
            fp: 0,
            fn_count: 0,
            tn: 0,
            evidence_grade_mismatches: 0,
            unresolved: 0,
            passed: false,
        };
        for (control, disposition, grade) in controls(category) {
            let case_id = format!("{}-{control}", category.category.to_ascii_lowercase());
            let actual = observed.get(case_id.as_str());
            let grade_ok = actual.is_some_and(|item| item.evidence_grade == grade);
            if actual.is_some() && !grade_ok {
                score.evidence_grade_mismatches += 1;
                row.evidence_grade_mismatches += 1;
            }
            match (
                control,
                actual.map(|item| item.disposition.as_str()),
                grade_ok,
            ) {
                ("vulnerable", Some("FINDING"), true) => {
                    score.tp += 1;
                    row.tp += 1;
                }
                ("vulnerable", _, _) => {
                    score.fn_count += 1;
                    row.fn_count += 1;
                }
                ("safe", Some("CLEAN"), true) => {
                    score.tn += 1;
                    row.tn += 1;
                }
                ("safe", Some("FINDING"), _) => {
                    score.fp += 1;
                    row.fp += 1;
                }
                ("unknown", Some("UNKNOWN"), true) => score.unknown_controls_passed += 1,
                ("unsupported", Some("UNSUPPORTED"), true) => {
                    score.unsupported_controls_passed += 1
                }
                _ => {
                    score.unresolved += 1;
                    row.unresolved += 1;
                }
            }
            let _ = disposition;
        }
        row.passed = row.tp == 1
            && row.tn == 1
            && row.fp == 0
            && row.fn_count == 0
            && row.evidence_grade_mismatches == 0
            && row.unresolved == 0;
        rows.push(row);
    }
    score.unexpected_observations = observed
        .keys()
        .filter(|case_id| !expected.contains_key(**case_id))
        .count() as u64;
    score.fp += score.unexpected_observations;
    let required = truth.categories.len() as u64;
    score.passed = score.tp == required
        && score.tn == required
        && score.fp <= truth.promotion_requirements.maximum_false_positives
        && score.fn_count <= truth.promotion_requirements.maximum_false_negatives
        && score.unknown_controls_passed == required
        && score.unsupported_controls_passed == required
        && score.evidence_grade_mismatches == 0
        && score.unresolved == 0;
    let envelope_closed = closed(&evidence, &truth.promotion_requirements);
    let held_out_passed = held_out_passed(truth, &expected, held_out);
    let promotion_eligible = score.passed && envelope_closed && held_out_passed;
    let mut reasons = Vec::new();
    if !score.passed {
        reasons.push("qualification_score_incomplete".to_owned());
    }
    if !envelope_closed {
        reasons.push("evidence_envelope_not_closed".to_owned());
    }
    if !held_out_passed {
        reasons.push("held_out_application_evidence_missing".to_owned());
    }
    Report {
        schema_version: "security-benchmark-score/v1",
        suite_id: truth.suite_id.clone(),
        evidence_digest: evidence.evidence_digest,
        evidence_envelope_closed: envelope_closed,
        held_out_applications_passed: held_out_passed,
        promotion_eligible,
        score,
        category_scores: rows,
        reason_codes: reasons,
    }
}

fn controls(category: &Category) -> [(&'static str, &'static str, &str); 4] {
    [
        (
            "vulnerable",
            "FINDING",
            category.required_evidence_grade.as_str(),
        ),
        ("safe", "CLEAN", "CLOSED_DENOMINATOR"),
        ("unknown", "UNKNOWN", "CAPABILITY_GAP"),
        ("unsupported", "UNSUPPORTED", "UNSUPPORTED_COORDINATE"),
    ]
}

fn expected_cases(truth: &Truth) -> BTreeMap<String, (String, String)> {
    truth
        .categories
        .iter()
        .flat_map(|category| {
            controls(category)
                .into_iter()
                .map(|(control, disposition, grade)| {
                    (
                        format!("{}-{control}", category.category.to_ascii_lowercase()),
                        (disposition.to_owned(), grade.to_owned()),
                    )
                })
        })
        .collect()
}

fn closed(evidence: &Evidence, requirements: &Requirements) -> bool {
    evidence.ordinary_product_path
        && evidence.publication_state == requirements.required_publication_state
        && evidence.coverage_verdict == requirements.required_coverage_verdict
        && evidence.sealed_transcripts_verified
        && evidence.authenticated_readback_verified
        && evidence.failed_requests == 0
        && evidence.unexpected_facts == 0
        && evidence.unresolved_obligations == 0
}

fn held_out_passed(
    truth: &Truth,
    expected: &BTreeMap<String, (String, String)>,
    evidence: &[Evidence],
) -> bool {
    let requirements = &truth.promotion_requirements;
    if evidence.len() < requirements.minimum_held_out_applications as usize
        || evidence.iter().any(|item| !closed(item, requirements))
    {
        return false;
    }
    let mut vulnerable = BTreeSet::new();
    let mut safe = BTreeSet::new();
    for item in evidence {
        for observation in &item.observations {
            let Some((disposition, grade)) = expected.get(&observation.case_id) else {
                return false;
            };
            if &observation.disposition != disposition || &observation.evidence_grade != grade {
                return false;
            }
            let category = observation
                .case_id
                .rsplit_once('-')
                .map(|value| value.0)
                .unwrap_or("");
            match disposition.as_str() {
                "FINDING" => {
                    vulnerable.insert(category);
                }
                "CLEAN" => {
                    safe.insert(category);
                }
                _ => {}
            }
        }
    }
    vulnerable.len() as u64 >= requirements.minimum_held_out_vulnerable_categories
        && safe.len() as u64 >= requirements.minimum_held_out_safe_categories
}

fn string_list(value: &Value, field: &str) -> Result<BTreeSet<String>, String> {
    match value.get(field) {
        Some(Value::String(item)) if !item.is_empty() => Ok([item.clone()].into_iter().collect()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| format!("invalid {field}"))
            })
            .collect(),
        _ => Err(format!("invalid {field}")),
    }
}

fn digest(value: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn truth_path() -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let v1 = root.join("truth-v1.json");
        if v1.is_file() {
            v1
        } else {
            root.join("truth-v2.json")
        }
    }

    fn loaded_truth() -> Truth {
        let path = truth_path();
        let truth: Truth = read_json(&path).unwrap();
        validate_truth(&truth, &path).unwrap();
        truth
    }

    #[test]
    fn locked_truth_sources_are_digest_closed() {
        let truth = loaded_truth();
        assert!(!truth.source_digests.is_empty());
    }

    #[test]
    fn complete_four_state_evidence_scores_the_closed_denominator() {
        let truth = loaded_truth();
        let observations = truth
            .categories
            .iter()
            .flat_map(|category| {
                controls(category)
                    .into_iter()
                    .map(|(control, disposition, grade)| Observation {
                        case_id: format!("{}-{control}", category.category.to_ascii_lowercase()),
                        disposition: disposition.to_owned(),
                        evidence_grade: grade.to_owned(),
                        repository_path: format!("src/{control}/{}.rs", category.category),
                        sink_identity: format!("{}-{control}", category.category),
                    })
            })
            .collect();
        let evidence = Evidence {
            schema_version: String::new(),
            suite_id: truth.suite_id.clone(),
            layer: "LOCKED".to_owned(),
            repository_id: String::new(),
            independent_truth_digest: None,
            runtime_coordinate: String::new(),
            framework_coordinate: String::new(),
            ordinary_product_path: true,
            publication_state: truth
                .promotion_requirements
                .required_publication_state
                .clone(),
            coverage_verdict: truth
                .promotion_requirements
                .required_coverage_verdict
                .clone(),
            sealed_transcripts_verified: true,
            authenticated_readback_verified: true,
            failed_requests: 0,
            unexpected_facts: 0,
            unresolved_obligations: 0,
            observations,
            evidence_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let report = score(&truth, evidence, &[]);
        let categories = truth.categories.len() as u64;
        assert_eq!(
            (
                report.score.tp,
                report.score.fp,
                report.score.fn_count,
                report.score.tn,
            ),
            (categories, 0, 0, categories)
        );
        assert!(report.score.passed);
        assert!(report.evidence_envelope_closed);
        assert!(!report.promotion_eligible);
    }
}
