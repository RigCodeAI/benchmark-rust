use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use super::{CaseDetail, CatalogEntry, PublicTruth};

pub(super) struct Outputs {
    json: Vec<u8>,
    csv: Vec<u8>,
}

#[derive(Serialize)]
struct Catalog<'a> {
    schema_version: &'static str,
    benchmark_id: &'a str,
    accuracy_controls: [&'static str; 2],
    assurance_controls: [&'static str; 2],
    cases: &'a [CatalogEntry],
}

pub(super) fn build(truth: &PublicTruth) -> Vec<CatalogEntry> {
    let details = truth
        .product_cases
        .iter()
        .chain(&truth.controller_cases)
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let repositories = truth
        .repositories
        .iter()
        .map(|repository| (repository.repository_id.as_str(), repository.path.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut entries = Vec::with_capacity(truth.categories.len() * 4);
    for category in &truth.categories {
        for control in ["vulnerable", "safe", "unknown", "unsupported"] {
            let case_id = format!("{}-{control}", category.category.to_ascii_lowercase());
            let detail = details.get(case_id.as_str()).copied();
            let repository_path = detail
                .and_then(|case| repositories.get(case.repository_id.as_str()).copied())
                .unwrap_or_else(|| {
                    if control == "unsupported" {
                        "controls/unqualified-coordinate"
                    } else {
                        "application"
                    }
                })
                .to_owned();
            entries.push(entry(
                case_id,
                &category.category,
                control,
                &category.required_evidence_grade,
                repository_path,
                detail,
            ));
        }
    }
    entries
}

fn entry(
    case_id: String,
    category: &str,
    control: &str,
    vulnerable_grade: &str,
    repository_path: String,
    detail: Option<&CaseDetail>,
) -> CatalogEntry {
    let (disposition, grade, scored) = match control {
        "vulnerable" => ("FINDING", vulnerable_grade, true),
        "safe" => ("CLEAN", "CLOSED_DENOMINATOR", true),
        "unknown" => ("UNKNOWN", "CAPABILITY_GAP", false),
        "unsupported" => ("UNSUPPORTED", "UNSUPPORTED_COORDINATE", false),
        _ => unreachable!("fixed control set"),
    };
    let route = detail.and_then(|case| case.route.clone());
    let source_location = route
        .clone()
        .or_else(|| detail.and_then(|case| case.test_id.clone()))
        .unwrap_or_else(|| repository_path.clone());
    let sink_location = detail
        .and_then(|case| case.sink_family.clone().or_else(|| case.report.clone()))
        .unwrap_or_else(|| {
            if control == "unsupported" {
                "unqualified runtime or framework coordinate".to_owned()
            } else {
                "security-relevant operation".to_owned()
            }
        });
    CatalogEntry {
        case_id,
        category: category.to_owned(),
        control: control.to_owned(),
        expected_disposition: disposition.to_owned(),
        scored_in_accuracy: scored,
        required_evidence_grade: grade.to_owned(),
        repository_path,
        route,
        source_location,
        sink_location,
        rule_id: detail.and_then(|case| case.rule_id.clone()),
        reason_code: detail.and_then(|case| case.reason_code.clone()),
    }
}

pub(super) fn render(truth: &PublicTruth) -> Result<Outputs, String> {
    let entries = build(truth);
    let value = Catalog {
        schema_version: "security-benchmark-case-catalog/v1",
        benchmark_id: &truth.suite_id,
        accuracy_controls: ["vulnerable", "safe"],
        assurance_controls: ["unknown", "unsupported"],
        cases: &entries,
    };
    let mut json = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    json.push(b'\n');
    let mut csv = String::from(
        "case_id,category,control,expected_disposition,scored_in_accuracy,required_evidence_grade,repository_path,route,source_location,sink_location,rule_id,reason_code\n",
    );
    for entry in &entries {
        let fields = [
            entry.case_id.as_str(),
            entry.category.as_str(),
            entry.control.as_str(),
            entry.expected_disposition.as_str(),
            if entry.scored_in_accuracy {
                "true"
            } else {
                "false"
            },
            entry.required_evidence_grade.as_str(),
            entry.repository_path.as_str(),
            entry.route.as_deref().unwrap_or(""),
            entry.source_location.as_str(),
            entry.sink_location.as_str(),
            entry.rule_id.as_deref().unwrap_or(""),
            entry.reason_code.as_deref().unwrap_or(""),
        ];
        csv.push_str(
            &fields
                .into_iter()
                .map(csv_field)
                .collect::<Vec<_>>()
                .join(","),
        );
        csv.push('\n');
    }
    Ok(Outputs {
        json,
        csv: csv.into_bytes(),
    })
}

pub(super) fn write(output_dir: &Path, outputs: &Outputs) -> Result<(), String> {
    std::fs::create_dir_all(output_dir).map_err(|error| error.to_string())?;
    std::fs::write(output_dir.join("catalog.json"), &outputs.json)
        .map_err(|error| error.to_string())?;
    std::fs::write(output_dir.join("expected-results.csv"), &outputs.csv)
        .map_err(|error| error.to_string())?;
    Ok(())
}

pub(super) fn check(output_dir: &Path, outputs: &Outputs) -> Result<(), String> {
    check_file(&output_dir.join("catalog.json"), &outputs.json)?;
    check_file(&output_dir.join("expected-results.csv"), &outputs.csv)
}

fn check_file(path: &Path, expected: &[u8]) -> Result<(), String> {
    let observed = std::fs::read(path).map_err(|error| error.to_string())?;
    if observed != expected {
        return Err(format!(
            "generated catalog is stale: {}; run catalog to refresh it",
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}
