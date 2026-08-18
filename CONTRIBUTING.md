# Contributing

Contributions that improve case correctness, scanner interoperability,
documentation, framework coverage, and independent validation are welcome.

Before opening a pull request:

```bash
make verify
```

Case and truth changes must follow `docs/adding-a-test.md`. Every new category
needs vulnerable, safe, unknown, and unsupported controls. Expected results cannot
be changed merely because a scanner disagrees with them.

Pull requests should state the security claim, CWE, compiler/framework coordinate,
authoritative safe behavior, affected scoring layer, and independent validation.

By contributing, you agree that your contribution is licensed under MIT.
