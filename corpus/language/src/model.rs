#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Control {
    Vulnerable,
    Safe,
    Unknown,
    Unsupported,
}

impl Control {
    pub const ALL: [Self; 4] = [
        Self::Vulnerable,
        Self::Safe,
        Self::Unknown,
        Self::Unsupported,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::Safe => "safe",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Finding,
    Clean,
    Unknown,
    Unsupported,
}

impl Disposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "FINDING",
            Self::Clean => "CLEAN",
            Self::Unknown => "UNKNOWN",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

#[derive(Clone, Copy)]
pub struct ProbeResult {
    pub disposition: Disposition,
    pub witness: &'static str,
}

pub type Probe = fn() -> ProbeResult;

#[derive(Clone, Copy)]
pub struct CategorySpec {
    pub category: &'static str,
    pub slug: &'static str,
    pub mapping: &'static str,
    pub security_statement: &'static str,
    pub evidence_grade: &'static str,
    pub vulnerable: Probe,
    pub safe: Probe,
}

impl CategorySpec {
    pub const fn new(
        category: &'static str,
        slug: &'static str,
        mapping: &'static str,
        security_statement: &'static str,
        evidence_grade: &'static str,
        vulnerable: Probe,
        safe: Probe,
    ) -> Self {
        Self {
            category,
            slug,
            mapping,
            security_statement,
            evidence_grade,
            vulnerable,
            safe,
        }
    }

    pub fn execute(self, control: Control) -> CaseResult {
        let probe = match control {
            Control::Vulnerable => (self.vulnerable)(),
            Control::Safe => (self.safe)(),
            Control::Unknown => ProbeResult {
                disposition: Disposition::Unknown,
                witness: "required semantic fact is intentionally opaque",
            },
            Control::Unsupported => ProbeResult {
                disposition: Disposition::Unsupported,
                witness: "required provider coordinate is intentionally unqualified",
            },
        };
        CaseResult {
            case_id: format!("{}-{}", self.slug, control.as_str()),
            category: self.category,
            control,
            expected: expected(control),
            observed: probe.disposition,
            witness: probe.witness,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseResult {
    pub case_id: String,
    pub category: &'static str,
    pub control: Control,
    pub expected: Disposition,
    pub observed: Disposition,
    pub witness: &'static str,
}

const fn expected(control: Control) -> Disposition {
    match control {
        Control::Vulnerable => Disposition::Finding,
        Control::Safe => Disposition::Clean,
        Control::Unknown => Disposition::Unknown,
        Control::Unsupported => Disposition::Unsupported,
    }
}
