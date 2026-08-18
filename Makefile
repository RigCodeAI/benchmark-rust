.PHONY: run score verify catalog

run:
	./runBenchmark.sh

score:
	@test -n "$(RESULTS)" || { echo "usage: make score RESULTS=path/to/results.sarif" >&2; exit 2; }
	./scoreBenchmark.sh --results "$(RESULTS)" $(if $(OUTPUT),--output-dir "$(OUTPUT)",)

verify:
	./verifyBenchmark.sh

catalog:
	cargo run --quiet --locked -- catalog
