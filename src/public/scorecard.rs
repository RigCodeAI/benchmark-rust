use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{CatalogEntry, PublicTruth, ScannerRun};

#[derive(Serialize)]
pub(super) struct Scorecard {
    pub(super) schema_version: &'static str,
    pub(super) benchmark_id: String,
    pub(super) scoring_scope: &'static str,
    pub(super) assurance_note: &'static str,
    pub(super) tool: Tool,
    pub(super) summary: Summary,
    pub(super) categories: Vec<CategoryScore>,
}

#[derive(Serialize)]
pub(super) struct Tool {
    pub(super) name: String,
    pub(super) version: String,
    pub(super) kind: String,
}

#[derive(Serialize)]
pub(super) struct Summary {
    pub(super) tp: u64,
    pub(super) fp: u64,
    #[serde(rename = "fn")]
    pub(super) fn_count: u64,
    pub(super) tn: u64,
    pub(super) tpr: f64,
    pub(super) fpr: f64,
    pub(super) balanced_accuracy: f64,
    pub(super) input_findings: u64,
    pub(super) matched_findings: u64,
    pub(super) duplicate_findings: u64,
    pub(super) unscored_assurance_findings: u64,
    pub(super) unmapped_findings: u64,
}

#[derive(Serialize)]
pub(super) struct CategoryScore {
    pub(super) category: String,
    pub(super) tp: u64,
    pub(super) fp: u64,
    #[serde(rename = "fn")]
    pub(super) fn_count: u64,
    pub(super) tn: u64,
    pub(super) tpr: f64,
    pub(super) fpr: f64,
    pub(super) passed: bool,
}

pub(super) fn score(
    truth: &PublicTruth,
    catalog: &[CatalogEntry],
    scanner: ScannerRun,
) -> Scorecard {
    let by_id = catalog
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut detected = BTreeSet::new();
    let mut duplicates = 0;
    let mut matched = 0;
    let mut unscored = 0;
    let mut unmapped = 0;
    for finding in &scanner.findings {
        let matched_case = match_case(catalog, finding);
        match matched_case {
            Some(case) if !case.scored_in_accuracy => unscored += 1,
            Some(case) => {
                matched += 1;
                if !detected.insert(case.case_id.as_str()) {
                    duplicates += 1;
                }
            }
            None => unmapped += 1,
        }
    }

    let mut rows = Vec::with_capacity(truth.categories.len());
    let mut tp = 0;
    let mut fp = unmapped;
    let mut fn_count = 0;
    let mut tn = 0;
    for category in &truth.categories {
        let prefix = category.category.to_ascii_lowercase();
        let vulnerable = format!("{prefix}-vulnerable");
        let safe = format!("{prefix}-safe");
        debug_assert!(by_id.contains_key(vulnerable.as_str()));
        debug_assert!(by_id.contains_key(safe.as_str()));
        let vulnerable_found = detected.contains(vulnerable.as_str());
        let safe_found = detected.contains(safe.as_str());
        let row_tp = u64::from(vulnerable_found);
        let row_fn = u64::from(!vulnerable_found);
        let row_fp = u64::from(safe_found);
        let row_tn = u64::from(!safe_found);
        tp += row_tp;
        fp += row_fp;
        fn_count += row_fn;
        tn += row_tn;
        rows.push(CategoryScore {
            category: category.category.clone(),
            tp: row_tp,
            fp: row_fp,
            fn_count: row_fn,
            tn: row_tn,
            tpr: row_tp as f64,
            fpr: row_fp as f64,
            passed: row_tp == 1 && row_fp == 0,
        });
    }
    let tpr = ratio(tp, tp + fn_count);
    let fpr = ratio(fp, fp + tn);
    let balanced_accuracy = (tpr + (1.0 - fpr)) / 2.0;
    Scorecard {
        schema_version: "security-benchmark-public-scorecard/v1",
        benchmark_id: truth.suite_id.clone(),
        scoring_scope: "VULNERABLE_AND_SAFE_CONTROLS",
        assurance_note: "UNKNOWN, UNSUPPORTED, evidence grades, closed coverage, and promotion are scored only by the qualification interface.",
        tool: Tool {
            name: scanner.tool_name,
            version: scanner.tool_version,
            kind: scanner.tool_kind,
        },
        summary: Summary {
            tp,
            fp,
            fn_count,
            tn,
            tpr,
            fpr,
            balanced_accuracy,
            input_findings: scanner.findings.len() as u64,
            matched_findings: matched,
            duplicate_findings: duplicates,
            unscored_assurance_findings: unscored,
            unmapped_findings: unmapped,
        },
        categories: rows,
    }
}

fn match_case<'a>(
    catalog: &'a [CatalogEntry],
    finding: &super::NormalizedFinding,
) -> Option<&'a CatalogEntry> {
    let mut candidates = catalog
        .iter()
        .filter(|case| case.category == finding.category);
    if let Some(case_id) = finding.case_id.as_deref() {
        return candidates.find(|case| case.case_id == case_id);
    }
    if let Some(route) = finding.route.as_deref() {
        return candidates.find(|case| case.route.as_deref() == Some(route));
    }
    let path = finding.path.as_deref()?;
    let _line = finding.line;
    let _rule_id = finding.rule_id.as_deref();
    candidates.find(|case| path.contains(&case.case_id))
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public::{PublicCategory, PublicTruth};

    #[test]
    fn absence_is_fn_for_vulnerable_and_tn_for_safe() {
        let truth = PublicTruth {
            suite_id: "fixture".to_owned(),
            categories: vec![PublicCategory {
                category: "CWE-89".to_owned(),
                required_evidence_grade: "RUNTIME_SEMANTIC".to_owned(),
            }],
            repositories: Vec::new(),
            product_cases: Vec::new(),
            controller_cases: Vec::new(),
        };
        let catalog = super::super::catalog::build(&truth);
        let report = score(
            &truth,
            &catalog,
            ScannerRun {
                tool_name: "fixture".to_owned(),
                tool_version: "1".to_owned(),
                tool_kind: "SAST".to_owned(),
                findings: Vec::new(),
            },
        );
        assert_eq!((report.summary.tp, report.summary.fn_count), (0, 1));
        assert_eq!((report.summary.fp, report.summary.tn), (0, 1));
    }

    #[test]
    fn language_specific_finding_scores_by_stable_case_id() {
        let truth = PublicTruth {
            suite_id: "fixture".to_owned(),
            categories: vec![PublicCategory {
                category: "RUST-FFI-BOUNDARY".to_owned(),
                required_evidence_grade: "RUNTIME_MEMORY".to_owned(),
            }],
            repositories: Vec::new(),
            product_cases: Vec::new(),
            controller_cases: Vec::new(),
        };
        let catalog = super::super::catalog::build(&truth);
        let report = score(
            &truth,
            &catalog,
            ScannerRun {
                tool_name: "fixture".to_owned(),
                tool_version: "1".to_owned(),
                tool_kind: "SAST".to_owned(),
                findings: vec![super::super::NormalizedFinding {
                    category: "RUST-FFI-BOUNDARY".to_owned(),
                    case_id: Some("rust-ffi-boundary-vulnerable".to_owned()),
                    route: None,
                    path: None,
                    line: None,
                    rule_id: None,
                }],
            },
        );
        assert_eq!((report.summary.tp, report.summary.fn_count), (1, 0));
        assert_eq!((report.summary.fp, report.summary.tn), (0, 1));
    }
}
