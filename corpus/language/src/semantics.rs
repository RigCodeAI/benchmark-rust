use crate::model::{Disposition, ProbeResult};

const fn finding(witness: &'static str) -> ProbeResult {
    ProbeResult {
        disposition: Disposition::Finding,
        witness,
    }
}

const fn clean(witness: &'static str) -> ProbeResult {
    ProbeResult {
        disposition: Disposition::Clean,
        witness,
    }
}

pub fn structure_changed() -> ProbeResult {
    let input = "' OR 1=1 --";
    let statement = format!("SELECT * FROM item WHERE name = '{input}'");
    if statement.contains(" OR 1=1 ") {
        finding("request bytes changed an interpreter grammar")
    } else {
        clean("request bytes remained data")
    }
}

pub fn structure_bound() -> ProbeResult {
    let statement = "SELECT * FROM item WHERE name = ?";
    let parameters = ["' OR 1=1 --"];
    if statement.contains(parameters[0]) {
        finding("bound value entered interpreter grammar")
    } else {
        clean("bound value remained outside interpreter grammar")
    }
}

pub fn context_active() -> ProbeResult {
    let input = "<script>globalThis.rig=1</script>";
    let body = format!("<main>{input}</main>");
    if body.contains("<script>") {
        finding("request bytes remained active in the output context")
    } else {
        clean("request bytes were inert in the output context")
    }
}

pub fn context_encoded() -> ProbeResult {
    let input = "<script>globalThis.rig=1</script>";
    let body = input.replace('<', "&lt;").replace('>', "&gt;");
    if body.contains("<script>") {
        finding("encoded bytes remained active")
    } else {
        clean("context-sensitive encoding made request bytes inert")
    }
}

pub fn path_escaped() -> ProbeResult {
    let root = "/srv/app/data";
    let requested = "../../etc/passwd";
    let resolved = format!("{root}/{requested}");
    if resolved.contains("../") {
        finding("request path escaped the declared containment root")
    } else {
        clean("request path remained under the declared root")
    }
}

pub fn path_contained() -> ProbeResult {
    let root = "/srv/app/data";
    let requested = "profile.txt";
    let resolved = format!("{root}/{requested}");
    if !resolved.starts_with(root) || requested.contains("..") {
        finding("normalized path escaped containment")
    } else {
        clean("normalized path remained under the declared root")
    }
}

pub fn destination_controlled() -> ProbeResult {
    let trusted = "https://api.example.invalid";
    let input = "http://169.254.169.254/latest/meta-data";
    if input != trusted {
        finding("request input selected the outbound authority")
    } else {
        clean("outbound authority was fixed by policy")
    }
}

pub fn destination_allowlisted() -> ProbeResult {
    let allowed = ["api.example.invalid"];
    let selected = "api.example.invalid";
    if allowed.contains(&selected) {
        clean("outbound authority matched the exact allowlist")
    } else {
        finding("outbound authority bypassed the allowlist")
    }
}

pub fn policy_bypassed() -> ProbeResult {
    let actor = "member";
    let required = "admin";
    if actor != required {
        finding("a lower-privilege principal completed the protected action")
    } else {
        clean("the protected action enforced its principal policy")
    }
}

pub fn policy_enforced() -> ProbeResult {
    let actor = "member";
    let required = "admin";
    if actor == required {
        finding("invalid control fixture")
    } else {
        clean("the lower-privilege principal was denied")
    }
}

pub fn secret_exposed() -> ProbeResult {
    let secret = "token_rig_secret";
    let response = format!("debug={secret}");
    if response.contains(secret) {
        finding("a classified secret crossed a public boundary")
    } else {
        clean("classified data was removed")
    }
}

pub fn secret_redacted() -> ProbeResult {
    let response = "debug=[REDACTED]";
    if response.contains("token_rig_secret") {
        finding("redaction failed")
    } else {
        clean("classified data was redacted before the boundary")
    }
}

pub fn weak_primitive() -> ProbeResult {
    finding("the security operation selected a qualified weak primitive")
}

pub fn strong_primitive() -> ProbeResult {
    clean("the security operation selected a qualified strong primitive")
}

pub fn unbounded_effect() -> ProbeResult {
    let requested = 1_000_000_000_usize;
    let budget = 1_000_000_usize;
    if requested > budget {
        finding("request-controlled work exceeded the declared budget")
    } else {
        clean("request-controlled work remained bounded")
    }
}

pub fn bounded_effect() -> ProbeResult {
    let requested = 4096_usize;
    let budget = 1_000_000_usize;
    if requested > budget {
        finding("bounded control exceeded its budget")
    } else {
        clean("request-controlled work was capped")
    }
}

pub fn memory_unchecked() -> ProbeResult {
    finding("an attacker-influenced value reached an unchecked memory boundary")
}

pub fn memory_checked() -> ProbeResult {
    clean("bounds, ownership, and lifetime checks preceded the memory boundary")
}

pub fn build_untrusted() -> ProbeResult {
    finding("unreviewed repository or dependency code executed during the build")
}

pub fn build_hermetic() -> ProbeResult {
    clean("the locked build denied untrusted build-time execution")
}
