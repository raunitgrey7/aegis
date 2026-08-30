# Continuous Integration

`ci.yml` is the GitHub Actions workflow for Aegis: backend tests + ruff, a
benchmark smoke test with quality gates (≥90% detection, ≤10% FPR), and the
frontend build.

It lives here (rather than `.github/workflows/`) only because the initial push
was made with a token that lacked the `workflow` OAuth scope. To activate CI:

```bash
gh auth refresh -s workflow          # grant the workflow scope (one time)
mkdir -p .github/workflows
git mv ci/ci.yml .github/workflows/ci.yml
git commit -m "Enable GitHub Actions CI"
git push
```
