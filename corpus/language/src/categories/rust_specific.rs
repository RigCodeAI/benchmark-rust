use crate::model::CategorySpec;
use crate::semantics;

fn build(category: &'static str, slug: &'static str, statement: &'static str) -> CategorySpec {
    CategorySpec::new(
        category,
        slug,
        "ADAPTED",
        statement,
        "BUILD_PROVENANCE",
        semantics::build_untrusted,
        semantics::build_hermetic,
    )
}

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

pub fn rust_build_rs_execution() -> CategorySpec {
    build(
        "RUST-BUILD-RS-EXECUTION",
        "rust-build-rs-execution",
        "an untrusted build script executes outside the hermetic build policy",
    )
}

pub fn rust_ffi_boundary() -> CategorySpec {
    memory(
        "RUST-FFI-BOUNDARY",
        "rust-ffi-boundary",
        "attacker influence crosses an FFI boundary without a qualified contract",
    )
}

pub fn rust_panic_dos() -> CategorySpec {
    CategorySpec::new(
        "RUST-PANIC-DOS",
        "rust-panic-dos",
        "ADAPTED",
        "request input triggers a panic that violates the availability policy",
        "RUNTIME_EFFECT",
        semantics::unbounded_effect,
        semantics::bounded_effect,
    )
}

pub fn rust_proc_macro_execution() -> CategorySpec {
    build(
        "RUST-PROC-MACRO-EXECUTION",
        "rust-proc-macro-execution",
        "an untrusted procedural macro executes outside the hermetic build policy",
    )
}

pub fn rust_unsafe_block() -> CategorySpec {
    memory(
        "RUST-UNSAFE-BLOCK",
        "rust-unsafe-block",
        "attacker influence reaches an unsafe block without the required preconditions",
    )
}

pub fn specs() -> Vec<CategorySpec> {
    vec![
        rust_build_rs_execution(),
        rust_ffi_boundary(),
        rust_panic_dos(),
        rust_proc_macro_execution(),
        rust_unsafe_block(),
    ]
}
