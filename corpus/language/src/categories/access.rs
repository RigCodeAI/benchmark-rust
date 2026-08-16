use crate::model::CategorySpec;
use crate::semantics;

fn controller(category: &'static str, slug: &'static str, statement: &'static str) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "CONTROLLER",
        statement,
        "RUNTIME_DIFFERENTIAL",
        semantics::policy_bypassed,
        semantics::policy_enforced,
    )
}

pub fn cwe_284() -> CategorySpec {
    controller(
        "CWE-284",
        "cwe-284",
        "a principal performs an operation outside its declared access policy",
    )
}

pub fn cwe_287() -> CategorySpec {
    controller(
        "CWE-287",
        "cwe-287",
        "an invalid or absent identity is accepted as authenticated",
    )
}

pub fn cwe_306() -> CategorySpec {
    controller(
        "CWE-306",
        "cwe-306",
        "a critical action succeeds without authentication",
    )
}

pub fn cwe_352() -> CategorySpec {
    controller(
        "CWE-352",
        "cwe-352",
        "a state-changing action accepts a cross-site request without the required binding",
    )
}

pub fn cwe_639() -> CategorySpec {
    controller(
        "CWE-639",
        "cwe-639",
        "one principal can select another principal's object identifier",
    )
}

pub fn cwe_840() -> CategorySpec {
    controller(
        "CWE-840",
        "cwe-840",
        "a business invariant can be violated by an accepted request sequence",
    )
}

pub fn cwe_841() -> CategorySpec {
    controller(
        "CWE-841",
        "cwe-841",
        "a required workflow state or ordering transition can be bypassed",
    )
}

pub fn cwe_862() -> CategorySpec {
    controller(
        "CWE-862",
        "cwe-862",
        "a protected action is missing an authorization decision",
    )
}

pub fn cwe_863() -> CategorySpec {
    controller(
        "CWE-863",
        "cwe-863",
        "an authorization decision is present but accepts an unauthorized principal",
    )
}

pub fn specs() -> Vec<CategorySpec> {
    vec![
        cwe_284(),
        cwe_287(),
        cwe_306(),
        cwe_352(),
        cwe_639(),
        cwe_840(),
        cwe_841(),
        cwe_862(),
        cwe_863(),
    ]
}
