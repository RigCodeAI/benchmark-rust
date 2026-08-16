use crate::model::CategorySpec;
use crate::semantics;

fn exposure(category: &'static str, slug: &'static str, statement: &'static str) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "DIRECT",
        statement,
        "RUNTIME_VALUE_FLOW",
        semantics::secret_exposed,
        semantics::secret_redacted,
    )
}

fn primitive(category: &'static str, slug: &'static str, statement: &'static str) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "ADAPTED",
        statement,
        "RUNTIME_PROPERTY",
        semantics::weak_primitive,
        semantics::strong_primitive,
    )
}

pub fn cwe_200() -> CategorySpec {
    exposure(
        "CWE-200",
        "cwe-200",
        "classified data reaches a principal or response not authorized to receive it",
    )
}

pub fn cwe_201() -> CategorySpec {
    exposure(
        "CWE-201",
        "cwe-201",
        "classified data is inserted into a public response, analytics, or outbound message",
    )
}

pub fn cwe_328() -> CategorySpec {
    primitive(
        "CWE-328",
        "cwe-328",
        "a qualified reversible or collision-prone hash protects a security property",
    )
}

pub fn cwe_330() -> CategorySpec {
    primitive(
        "CWE-330",
        "cwe-330",
        "a predictable random source protects a security property",
    )
}

pub fn cwe_532() -> CategorySpec {
    exposure(
        "CWE-532",
        "cwe-532",
        "classified data reaches logs, traces, metrics, or diagnostics",
    )
}

pub fn cwe_614() -> CategorySpec {
    CategorySpec::new(
        "CWE-614",
        "cwe-614",
        "DIRECT",
        "a security-sensitive cookie can cross an insecure transport",
        "RUNTIME_PROPERTY",
        semantics::weak_primitive,
        semantics::strong_primitive,
    )
}

pub fn specs() -> Vec<CategorySpec> {
    vec![
        cwe_200(),
        cwe_201(),
        cwe_328(),
        cwe_330(),
        cwe_532(),
        cwe_614(),
    ]
}
