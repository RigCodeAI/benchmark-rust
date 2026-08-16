fn main() {
    if let Err(code) = rig_benchmark_rust_language_corpus::validate() {
        eprintln!("{code}");
        std::process::exit(1);
    }
    let cases = rig_benchmark_rust_language_corpus::execute();
    println!(
        "compiler={}",
        rig_benchmark_rust_language_corpus::compiler_coordinate()
    );
    println!(
        "BenchmarkRust language corpus: categories=43 controls={} vulnerable=43 safe=43 unknown=43 unsupported=43",
        cases.len()
    );
}
