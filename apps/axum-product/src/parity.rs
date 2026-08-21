use axum::{
    body::Body, extract::Query, http::HeaderValue, response::Redirect, routing::get, Router,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use fancy_regex::{Regex as FancyRegex, RegexBuilder as FancyRegexBuilder};
use maud::PreEscaped;
use minijinja::{context, Environment};
use serde::{Deserialize, Deserializer};
use sha2::Digest as _;
use sxd_xpath::{Context, Factory};

use crate::ApplicationState;

#[derive(Deserialize)]
struct ParityInput {
    secret: String,
}

struct EffectfulPayload(String);

impl<'de> Deserialize<'de> for EffectfulPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let _ = std::fs::write("sivere-owned-deserialization-effect", value.as_bytes());
        Ok(Self(value))
    }
}

pub(crate) fn routes() -> Router<ApplicationState> {
    Router::new()
        .route("/vulnerable", get(vulnerable))
        .route("/safe", get(safe))
        .route("/unknown", get(unknown))
}

async fn vulnerable(Query(input): Query<ParityInput>) -> &'static str {
    let value = input.secret;

    let _ = HeaderValue::from_str(&value);
    let _ = PreEscaped(value.clone());

    let environment = Environment::new();
    let _ = environment.render_str(&value, ());

    let _ = Body::from(value.clone());
    let _ = reqwest::Body::from(value.clone());
    let span = tracing::info_span!("parity", secret = tracing::field::Empty);
    span.record("secret", tracing::field::display(&value));

    let _ = md5::compute(value.as_bytes());
    let _ = fastrand::u64(..);

    let pattern = format!("(?i)((?:{0}|{0}{0})+)+(?>__sivere_no_match__)", value);
    let _ = evaluate_regex(&pattern, &value);

    let _ = CookieJar::new().add(Cookie::new("session", value.clone()));

    if let Ok(document) = serde_json::to_string(&value) {
        if let Ok(decoded) = serde_json::from_str::<EffectfulPayload>(&document) {
            let _ = decoded.0.len();
        }
    }

    let _ = Redirect::temporary(&value);
    let _ = parse_external_entities(&value);
    let _ = parse_entity_expansion(&value);

    let _ = Cookie::build(("session", value.clone()))
        .secure(false)
        .build();

    let _ = evaluate_xpath(&value);

    let filter = format!("(&(objectClass=person)(uid={value}))");
    let _ = ldap3::parse_filter(&filter);

    let script = format!("let {value} = 42; {value}");
    let _ = rhai::Engine::new().eval::<rhai::Dynamic>(&script);

    let _ = redis::cmd(&value);
    "ok"
}

async fn safe(Query(input): Query<ParityInput>) -> &'static str {
    let value = input.secret;

    let encoded_header = value.replace('\r', "%0D").replace('\n', "%0A");
    let _ = HeaderValue::from_str(&encoded_header);
    let _ = PreEscaped(html_escape::encode_text(&value).into_owned());

    let environment = Environment::new();
    let _ = environment.render_str("<main>{{ value }}</main>", context!(value => value.clone()));

    let _ = Body::from("redacted");
    let _ = reqwest::Body::from("redacted");
    let span = tracing::info_span!("parity-safe", secret = tracing::field::Empty);
    span.record("secret", tracing::field::display("[REDACTED]"));

    let _ = sha2::Sha256::digest(value.as_bytes());
    let _ = rand::random::<u64>();

    let _ = evaluate_regex_safe(r"^[a-zA-Z0-9_-]+$", &value);

    let digest = format!("{:x}", sha2::Sha256::digest(value.as_bytes()));
    let _ = CookieJar::new().add(Cookie::new("session", digest));

    if let Ok(document) = serde_json::to_string(&value) {
        let _ = serde_json::from_str::<serde_json::Value>(&document);
    }

    let _ = Redirect::temporary("/safe-target");
    let _ = parse_external_entities_safe(&value);
    let _ = parse_entity_expansion_safe(&value);

    let _ = Cookie::build(("session", value.clone()))
        .secure(true)
        .http_only(true)
        .build();

    let _ = evaluate_xpath_safe(&value);

    let escaped = ldap3::ldap_escape(value.clone());
    let filter = format!("(&(objectClass=person)(uid={escaped}))");
    let _ = ldap3::parse_filter(&filter);

    let mut scope = rhai::Scope::new();
    scope.push("value", value.clone());
    let _ = rhai::Engine::new().eval_with_scope::<rhai::Dynamic>(&mut scope, "value");

    let mut command = redis::cmd("GET");
    command.arg(value);
    "ok"
}

async fn unknown(Query(input): Query<ParityInput>) -> &'static str {
    ambiguous::header(&input.secret);
    ambiguous::output_encoding(&input.secret);
    ambiguous::template(&input.secret);
    ambiguous::sensitive_response(&input.secret);
    ambiguous::sensitive_outbound(&input.secret);
    ambiguous::sensitive_log(&input.secret);
    ambiguous::hash(&input.secret);
    ambiguous::random(&input.secret);
    ambiguous::regex(&input.secret);
    ambiguous::trust_boundary(&input.secret);
    ambiguous::deserialize(&input.secret);
    ambiguous::redirect(&input.secret);
    ambiguous::xml_external(&input.secret);
    ambiguous::cookie(&input.secret);
    ambiguous::xpath(&input.secret);
    ambiguous::xml_expansion(&input.secret);
    ambiguous::ldap(&input.secret);
    ambiguous::code(&input.secret);
    ambiguous::nosql(&input.secret);
    ambiguous::filesystem(&input.secret);
    "ok"
}

fn parse_external_entities(value: &str) -> Result<String, libxml::parser::XmlParseError> {
    parse_with_entity_substitution(value)
}

fn evaluate_regex(pattern: &str, token: &str) -> Result<String, fancy_regex::Error> {
    // Disable the literal seek prefilter so the qualified backtracking engine
    // must evaluate the source-controlled ambiguous alternatives. Its default
    // one-million-step backtrack limit remains active and bounds the probe.
    let regex = FancyRegexBuilder::new(pattern).seek(false).build()?;
    let mut elapsed = Vec::new();
    for repetitions in [4_usize, 8, 12, 24] {
        let candidate = token.repeat(repetitions);
        let started = std::time::Instant::now();
        match regex.is_match(&candidate) {
            Ok(_) => elapsed.push(started.elapsed().as_nanos().max(1)),
            Err(error) => return Ok(format!("operation_timeout:{error}")),
        }
    }
    let superlinear =
        elapsed[3] > elapsed[1].saturating_mul(3) && elapsed[2] > elapsed[0].saturating_mul(2);
    Ok(if superlinear {
        "superlinear_growth"
    } else {
        "bounded_trials_completed"
    }
    .to_owned())
}

fn evaluate_regex_safe(pattern: &str, value: &str) -> Result<String, fancy_regex::Error> {
    let regex = FancyRegex::new(pattern)?;
    let started = std::time::Instant::now();
    let _ = regex.is_match(value)?;
    Ok(format!(
        "bounded_trials_completed:{}",
        started.elapsed().as_nanos()
    ))
}

fn parse_entity_expansion(value: &str) -> Result<String, libxml::parser::XmlParseError> {
    parse_with_entity_substitution(value)
}

fn parse_with_entity_substitution(value: &str) -> Result<String, libxml::parser::XmlParseError> {
    libxml::init_parser();
    let bytes = value.as_bytes();
    let length =
        i32::try_from(bytes.len()).map_err(|_| libxml::parser::XmlParseError::GotNullPointer)?;
    // This benchmark's vulnerable coordinate intentionally selects libxml2's
    // XML_PARSE_NOENT behavior for this exact parse rather than mutating its
    // process-global parser defaults.
    let document = unsafe {
        libxml::bindings::xmlReadMemory(
            bytes.as_ptr().cast(),
            length,
            std::ptr::null(),
            std::ptr::null(),
            libxml::bindings::xmlParserOption_XML_PARSE_NOENT as i32,
        )
    };
    if document.is_null() {
        Err(libxml::parser::XmlParseError::GotNullPointer)
    } else {
        Ok(libxml::tree::Document::new_ptr(document).to_string())
    }
}

fn parse_external_entities_safe(value: &str) -> Result<(), sxd_document::parser::Error> {
    sxd_document::parser::parse(value).map(|_| ())
}

fn parse_entity_expansion_safe(value: &str) -> Result<(), sxd_document::parser::Error> {
    sxd_document::parser::parse(value).map(|_| ())
}

fn evaluate_xpath(value: &str) -> Result<(), sxd_xpath::Error> {
    let package =
        sxd_document::parser::parse("<root><item>safe</item></root>").expect("static XML document");
    let expression = format!("//item[text()='{value}']");
    let xpath = Factory::new()
        .build(&expression)?
        .expect("non-empty XPath expression");
    let _ = xpath.evaluate(&Context::new(), package.as_document().root())?;
    Ok(())
}

fn evaluate_xpath_safe(_value: &str) -> Result<(), sxd_xpath::Error> {
    let package =
        sxd_document::parser::parse("<root><item>safe</item></root>").expect("static XML document");
    let xpath = Factory::new()
        .build("//item[text()='safe']")?
        .expect("non-empty XPath expression");
    let _ = xpath.evaluate(&Context::new(), package.as_document().root())?;
    Ok(())
}

mod ambiguous {
    pub fn header(_: &str) {}
    pub fn output_encoding(_: &str) {}
    pub fn template(_: &str) {}
    pub fn sensitive_response(_: &str) {}
    pub fn sensitive_outbound(_: &str) {}
    pub fn sensitive_log(_: &str) {}
    pub fn hash(_: &str) {}
    pub fn random(_: &str) {}
    pub fn regex(_: &str) {}
    pub fn trust_boundary(_: &str) {}
    pub fn deserialize(_: &str) {}
    pub fn redirect(_: &str) {}
    pub fn xml_external(_: &str) {}
    pub fn cookie(_: &str) {}
    pub fn xpath(_: &str) {}
    pub fn xml_expansion(_: &str) {}
    pub fn ldap(_: &str) {}
    pub fn code(_: &str) {}
    pub fn nosql(_: &str) {}
    pub fn filesystem(_: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_regex_coordinate_observes_pathological_execution() {
        let token = "IASTr00000001x1234567890abcdef";
        let pattern = format!("(?i)((?:{0}|{0}{0})+)+(?>__sivere_no_match__)", token);
        let outcome = evaluate_regex(&pattern, token).unwrap();
        assert!(
            outcome.starts_with("operation_timeout") || outcome == "superlinear_growth",
            "unexpected regex outcome: {outcome}"
        );
    }

    #[test]
    fn qualified_xml_coordinate_observes_external_entity_and_expansion_effects() {
        let canary = std::env::temp_dir().join(format!(
            "sivere-rust-xxe-canary-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&canary, "SIVERE_XXE_EFFECT").unwrap();
        let external = format!(
            "<!DOCTYPE iast [<!ENTITY sivere SYSTEM \"file://{}\">]><iast>&sivere;</iast>",
            canary.display()
        );
        let external_result = parse_external_entities(&external).unwrap();
        std::fs::remove_file(&canary).unwrap();
        assert!(external_result.contains("SIVERE_XXE_EFFECT"));

        let marker = "IASTr00000001x1234567890abcdef";
        let expansion = format!(
            "<!DOCTYPE iast [<!ENTITY a \"{marker}\"><!ENTITY b \"&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;\">]><iast>&c;</iast>"
        );
        let expansion_result = parse_entity_expansion(&expansion).unwrap();
        assert!(expansion_result.matches(marker).count() > expansion.matches(marker).count());
    }
}
