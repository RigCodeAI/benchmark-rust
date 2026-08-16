use crate::model::CategorySpec;
use crate::semantics;

fn direct(
    category: &'static str,
    slug: &'static str,
    statement: &'static str,
    evidence: &'static str,
) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "DIRECT",
        statement,
        evidence,
        semantics::structure_changed,
        semantics::structure_bound,
    )
}

fn adapted(
    category: &'static str,
    slug: &'static str,
    statement: &'static str,
    evidence: &'static str,
) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "ADAPTED",
        statement,
        evidence,
        semantics::structure_changed,
        semantics::structure_bound,
    )
}

pub fn cwe_113() -> CategorySpec {
    direct(
        "CWE-113",
        "cwe-113",
        "request data changes an HTTP header field or line structure",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_116() -> CategorySpec {
    CategorySpec::new(
        "CWE-116",
        "cwe-116",
        "DIRECT",
        "untrusted output remains active in its destination context",
        "RUNTIME_SEMANTIC",
        semantics::context_active,
        semantics::context_encoded,
    )
}

pub fn cwe_1336() -> CategorySpec {
    direct(
        "CWE-1336",
        "cwe-1336",
        "request data changes server-side template grammar",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_22() -> CategorySpec {
    CategorySpec::new(
        "CWE-22",
        "cwe-22",
        "DIRECT",
        "request data escapes a declared filesystem containment root",
        "RUNTIME_EFFECT",
        semantics::path_escaped,
        semantics::path_contained,
    )
}

pub fn cwe_501() -> CategorySpec {
    direct(
        "CWE-501",
        "cwe-501",
        "less-trusted data crosses a trust boundary without the required validation",
        "RUNTIME_VALUE_FLOW",
    )
}

pub fn cwe_502() -> CategorySpec {
    adapted(
        "CWE-502",
        "cwe-502",
        "untrusted serialized data selects a security-relevant type or action",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_601() -> CategorySpec {
    CategorySpec::new(
        "CWE-601",
        "cwe-601",
        "DIRECT",
        "request data selects an untrusted redirect authority",
        "RUNTIME_SEMANTIC",
        semantics::destination_controlled,
        semantics::destination_allowlisted,
    )
}

pub fn cwe_611() -> CategorySpec {
    adapted(
        "CWE-611",
        "cwe-611",
        "the exact XML parser configuration resolves an attacker-selected external entity",
        "RUNTIME_EFFECT",
    )
}

pub fn cwe_643() -> CategorySpec {
    adapted(
        "CWE-643",
        "cwe-643",
        "request data changes XPath grammar",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_776() -> CategorySpec {
    adapted(
        "CWE-776",
        "cwe-776",
        "the exact XML parser expands attacker-controlled entities beyond policy",
        "RUNTIME_EFFECT",
    )
}

pub fn cwe_78() -> CategorySpec {
    direct(
        "CWE-78",
        "cwe-78",
        "request data changes shell or process invocation structure",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_79() -> CategorySpec {
    CategorySpec::new(
        "CWE-79",
        "cwe-79",
        "DIRECT",
        "request data remains executable in an HTML, attribute, script, style, or URL context",
        "RUNTIME_SEMANTIC",
        semantics::context_active,
        semantics::context_encoded,
    )
}

pub fn cwe_89() -> CategorySpec {
    direct(
        "CWE-89",
        "cwe-89",
        "request data changes SQL grammar rather than remaining bound data",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_90() -> CategorySpec {
    direct(
        "CWE-90",
        "cwe-90",
        "request data changes LDAP filter or distinguished-name grammar",
        "RUNTIME_SEMANTIC",
    )
}

pub fn cwe_918() -> CategorySpec {
    CategorySpec::new(
        "CWE-918",
        "cwe-918",
        "DIRECT",
        "request data selects an outbound network destination",
        "RUNTIME_EFFECT",
        semantics::destination_controlled,
        semantics::destination_allowlisted,
    )
}

pub fn cwe_94() -> CategorySpec {
    direct(
        "CWE-94",
        "cwe-94",
        "request data changes code, expression, or plugin execution structure",
        "RUNTIME_EFFECT",
    )
}

pub fn cwe_943() -> CategorySpec {
    adapted(
        "CWE-943",
        "cwe-943",
        "request data introduces a NoSQL operator or query-structure change",
        "RUNTIME_SEMANTIC",
    )
}

pub fn specs() -> Vec<CategorySpec> {
    vec![
        cwe_113(),
        cwe_116(),
        cwe_1336(),
        cwe_22(),
        cwe_501(),
        cwe_502(),
        cwe_601(),
        cwe_611(),
        cwe_643(),
        cwe_776(),
        cwe_78(),
        cwe_79(),
        cwe_89(),
        cwe_90(),
        cwe_918(),
        cwe_94(),
        cwe_943(),
    ]
}
