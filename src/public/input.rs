use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use super::{read_json, NormalizedFinding, ScannerRun};

pub(super) fn read(
    path: &Path,
    requested_format: Option<&str>,
    suite_id: &str,
) -> Result<ScannerRun, String> {
    let format = requested_format
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            path.extension()
                .and_then(|value| value.to_str())
                .map(str::to_ascii_lowercase)
        })
        .unwrap_or_else(|| "json".to_owned());
    match format.as_str() {
        "json" => read_json_results(path, suite_id),
        "sarif" => read_sarif(path),
        "csv" => read_csv(path),
        _ => Err(format!("unsupported results format: {format}")),
    }
}

pub(super) fn validate_example(path: &Path, format: &str, suite_id: &str) -> Result<(), String> {
    let run = read(path, Some(format), suite_id)?;
    if run.findings.is_empty() || run.tool_name == "unknown" {
        return Err("scanner-neutral example is empty".to_owned());
    }
    Ok(())
}

fn read_json_results(path: &Path, suite_id: &str) -> Result<ScannerRun, String> {
    let value: Value = read_json(path)?;
    if value.get("version").and_then(Value::as_str) == Some("2.1.0") && value.get("runs").is_some()
    {
        return parse_sarif(value);
    }
    if value.get("schema_version").and_then(Value::as_str)
        != Some("security-benchmark-scanner-results/v1")
    {
        return Err("unsupported scanner JSON schema".to_owned());
    }
    if let Some(benchmark_id) = value.get("benchmark_id").and_then(Value::as_str) {
        if benchmark_id != suite_id {
            return Err(format!(
                "results target {benchmark_id}, expected {suite_id}"
            ));
        }
    }
    let tool = value.get("tool").ok_or("scanner JSON is missing tool")?;
    let findings = value
        .get("findings")
        .and_then(Value::as_array)
        .ok_or("scanner JSON is missing findings")?
        .iter()
        .map(parse_generic_finding)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScannerRun {
        tool_name: required_string(tool, "name")?.to_owned(),
        tool_version: optional_string(tool, "version")
            .unwrap_or("unknown")
            .to_owned(),
        tool_kind: optional_string(tool, "kind")
            .unwrap_or("unknown")
            .to_owned(),
        findings,
    })
}

fn parse_generic_finding(value: &Value) -> Result<NormalizedFinding, String> {
    let location = value.get("location").unwrap_or(&Value::Null);
    let finding = NormalizedFinding {
        category: normalize_category(required_string(value, "category")?)?,
        case_id: optional_string(value, "case_id").map(str::to_owned),
        route: optional_string(value, "route").map(str::to_owned),
        path: optional_string(location, "path").map(str::to_owned),
        line: location.get("line").and_then(Value::as_u64),
        rule_id: optional_string(value, "rule_id").map(str::to_owned),
    };
    require_identity(finding)
}

fn read_sarif(path: &Path) -> Result<ScannerRun, String> {
    parse_sarif(read_json(path)?)
}

fn parse_sarif(value: Value) -> Result<ScannerRun, String> {
    if value.get("version").and_then(Value::as_str) != Some("2.1.0") {
        return Err("SARIF version must be 2.1.0".to_owned());
    }
    let runs = value
        .get("runs")
        .and_then(Value::as_array)
        .ok_or("SARIF is missing runs")?;
    let first = runs.first().ok_or("SARIF has no runs")?;
    let driver = first
        .pointer("/tool/driver")
        .ok_or("SARIF is missing tool.driver")?;
    let mut findings = Vec::new();
    for run in runs {
        for result in run
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            findings.push(parse_sarif_result(result)?);
        }
    }
    Ok(ScannerRun {
        tool_name: required_string(driver, "name")?.to_owned(),
        tool_version: optional_string(driver, "semanticVersion")
            .or_else(|| optional_string(driver, "version"))
            .unwrap_or("unknown")
            .to_owned(),
        tool_kind: "SARIF".to_owned(),
        findings,
    })
}

fn parse_sarif_result(value: &Value) -> Result<NormalizedFinding, String> {
    let properties = value.get("properties").unwrap_or(&Value::Null);
    let rule_id = optional_string(value, "ruleId").map(str::to_owned);
    let category = optional_string(properties, "category")
        .or_else(|| optional_string(properties, "cwe"))
        .map(str::to_owned)
        .or_else(|| rule_id.as_deref().and_then(category_from_rule))
        .ok_or("SARIF result needs properties.category, properties.cwe, or a CWE ruleId")?;
    let physical = value.pointer("/locations/0/physicalLocation");
    let path = physical
        .and_then(|item| item.pointer("/artifactLocation/uri"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let line = physical
        .and_then(|item| item.pointer("/region/startLine"))
        .and_then(Value::as_u64);
    require_identity(NormalizedFinding {
        category: normalize_category(&category)?,
        case_id: optional_string(properties, "benchmark_case_id").map(str::to_owned),
        route: optional_string(properties, "route").map(str::to_owned),
        path,
        line,
        rule_id,
    })
}

fn read_csv(path: &Path) -> Result<ScannerRun, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 * 1024 {
        return Err("unsafe CSV input".to_owned());
    }
    let text = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    let mut rows = text.lines().filter(|line| !line.trim().is_empty());
    let headers = parse_csv_line(rows.next().ok_or("CSV is empty")?)?;
    let positions = headers
        .iter()
        .enumerate()
        .map(|(index, header)| (header.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    if !positions.contains_key("category") {
        return Err("CSV requires a category column".to_owned());
    }
    let mut findings = Vec::new();
    for line in rows {
        let fields = parse_csv_line(line)?;
        let get = |name: &str| {
            positions
                .get(name)
                .and_then(|index| fields.get(*index))
                .filter(|value| !value.is_empty())
                .map(String::as_str)
        };
        findings.push(require_identity(NormalizedFinding {
            category: normalize_category(get("category").ok_or("CSV row needs category")?)?,
            case_id: get("case_id").map(str::to_owned),
            route: get("route").map(str::to_owned),
            path: get("path").map(str::to_owned),
            line: get("line")
                .map(str::parse)
                .transpose()
                .map_err(|_| "invalid CSV line")?,
            rule_id: get("rule_id").map(str::to_owned),
        })?);
    }
    let name = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("CSV scanner")
        .to_owned();
    Ok(ScannerRun {
        tool_name: name,
        tool_version: "unknown".to_owned(),
        tool_kind: "CSV".to_owned(),
        findings,
    })
}

fn parse_csv_line(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(character) = chars.next() {
        match character {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(std::mem::take(&mut field));
            }
            _ => field.push(character),
        }
    }
    if quoted {
        return Err("unterminated quoted CSV field".to_owned());
    }
    fields.push(field);
    Ok(fields)
}

fn require_identity(finding: NormalizedFinding) -> Result<NormalizedFinding, String> {
    if finding.case_id.is_none() && finding.route.is_none() && finding.path.is_none() {
        return Err("finding requires case_id, route, or location.path".to_owned());
    }
    Ok(finding)
}

fn normalize_category(value: &str) -> Result<String, String> {
    let upper = value.trim().to_ascii_uppercase();
    if !upper.is_empty() && upper.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(format!("CWE-{upper}"));
    }
    if upper.is_empty()
        || !upper.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        || !upper
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("invalid security category: {value}"));
    }
    Ok(upper)
}

fn category_from_rule(value: &str) -> Option<String> {
    let upper = value.to_ascii_uppercase();
    let start = upper.find("CWE-")?;
    let digits = upper[start + 4..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    (!digits.is_empty()).then(|| format!("CWE-{digits}"))
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    optional_string(value, field).ok_or_else(|| format!("missing {field}"))
}

fn optional_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|item| !item.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_parser_handles_quoted_commas_and_quotes() {
        assert_eq!(
            parse_csv_line("CWE-89,\"a,b\",\"x\"\"y\"").unwrap(),
            ["CWE-89", "a,b", "x\"y"]
        );
    }

    #[test]
    fn category_can_be_recovered_from_a_sarif_rule() {
        assert_eq!(
            category_from_rule("scanner/CWE-918/ssrf").as_deref(),
            Some("CWE-918")
        );
    }

    #[test]
    fn language_specific_category_is_preserved() {
        assert_eq!(
            normalize_category("rust-ffi-boundary").as_deref(),
            Ok("RUST-FFI-BOUNDARY")
        );
    }
}
