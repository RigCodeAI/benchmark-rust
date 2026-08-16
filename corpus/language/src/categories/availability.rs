use crate::model::CategorySpec;
use crate::semantics;

fn memory(category: &'static str, slug: &'static str, statement: &'static str) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "ADAPTED",
        statement,
        "RUNTIME_MEMORY",
        semantics::memory_unchecked,
        semantics::memory_checked,
    )
}

pub fn cwe_119() -> CategorySpec {
    memory(
        "CWE-119",
        "cwe-119",
        "attacker influence reaches an unchecked generic memory boundary",
    )
}

pub fn cwe_125() -> CategorySpec {
    memory(
        "CWE-125",
        "cwe-125",
        "attacker influence selects an out-of-bounds read",
    )
}

pub fn cwe_362() -> CategorySpec {
    CategorySpec::new(
        "CWE-362",
        "cwe-362",
        "CONTROLLER",
        "a controlled schedule violates a concurrent state invariant",
        "RUNTIME_DIFFERENTIAL",
        semantics::unbounded_effect,
        semantics::bounded_effect,
    )
}

pub fn cwe_400() -> CategorySpec {
    CategorySpec::new(
        "CWE-400",
        "cwe-400",
        "ADAPTED",
        "request-controlled work exceeds a declared CPU, memory, queue, or fan-out budget",
        "RUNTIME_EFFECT",
        semantics::unbounded_effect,
        semantics::bounded_effect,
    )
}

pub fn cwe_416() -> CategorySpec {
    memory(
        "CWE-416",
        "cwe-416",
        "an unsafe ownership boundary permits use after lifetime end",
    )
}

pub fn cwe_787() -> CategorySpec {
    memory(
        "CWE-787",
        "cwe-787",
        "attacker influence selects an out-of-bounds write",
    )
}

pub fn specs() -> Vec<CategorySpec> {
    vec![
        cwe_119(),
        cwe_125(),
        cwe_362(),
        cwe_400(),
        cwe_416(),
        cwe_787(),
    ]
}
