mod categories;
mod model;
mod semantics;

use std::collections::{BTreeMap, BTreeSet};

pub use model::{CaseResult, CategorySpec, Control, Disposition};

pub const fn compiler_coordinate() -> &'static str {
    env!("RIG_BENCHMARK_RUSTC_COORDINATE")
}

pub fn category_specs() -> Vec<CategorySpec> {
    categories::specs()
}

pub fn execute() -> Vec<CaseResult> {
    let mut output = Vec::new();
    for category in category_specs() {
        for control in Control::ALL {
            output.push(category.execute(control));
        }
    }
    output.sort_by(|left, right| left.case_id.cmp(&right.case_id));
    output
}

pub fn validate() -> Result<(), &'static str> {
    let specs = category_specs();
    if specs.len() != 43 {
        return Err("benchmark_rust_category_count_mismatch");
    }
    let categories = specs
        .iter()
        .map(|spec| spec.category)
        .collect::<BTreeSet<_>>();
    if categories.len() != specs.len() {
        return Err("benchmark_rust_duplicate_category");
    }
    let cases = execute();
    if cases.len() != 172 {
        return Err("benchmark_rust_control_count_mismatch");
    }
    let ids = cases
        .iter()
        .map(|case| case.case_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != cases.len()
        || cases.iter().any(|case| {
            case.expected != case.observed
                || case.witness.is_empty()
                || case.case_id.is_empty()
                || case.category.is_empty()
        })
    {
        return Err("benchmark_rust_control_invalid");
    }
    let counts = cases.iter().fold(BTreeMap::new(), |mut counts, case| {
        *counts.entry(case.category).or_insert(0_usize) += 1;
        counts
    });
    if counts.values().any(|count| *count != 4) {
        return Err("benchmark_rust_control_denominator_open");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_categories_have_executable_four_way_controls() {
        validate().unwrap();
        let cases = execute();
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.observed == Disposition::Finding)
                .count(),
            43
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.observed == Disposition::Clean)
                .count(),
            43
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.observed == Disposition::Unknown)
                .count(),
            43
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| case.observed == Disposition::Unsupported)
                .count(),
            43
        );
    }
}
