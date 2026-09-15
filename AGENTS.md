# AGENTS.md

Local Nessus `.audit` runners. Two independent implementations, one CSV format (`CHECK, Actual Value, Expected Value, Pass/Fail/Manual`).

## Layout

- `Invoke-AuditRunner.ps1` — main Windows runner (parser + evaluation + CSV export).
- `audit-runner.sh` — Linux/Unix runner, POSIX `sh` (not bash).
- `Invoke-AuditRunnerLegacy.ps1` — legacy wrapper (formerly `Invoke-CISWindows11Audit.ps1`); forwards only `AuditPath`/`ChecksPath`/`OutputPath` to the main runner. No catalog-export or embedded-script flags. Prefer `Invoke-AuditRunner.ps1`.
- `Invoke-AuditRunnerCli.ps1` — offline wifit3-style CLI wrapper over the main runner.
- `tests/Invoke-AuditRunner.Regression.ps1` — Windows parser/comparison checks. No Pester, no Unix-runner coverage.
- `tests/Invoke-AuditRunner.Golden.ps1` + `tests/fixtures/coverage.audit` — synthetic parser golden test (14 rows, 2 Manual); only `.audit` file that stays committed.
- `tools/Get-AuditRunnerMatrix.ps1` — prints supported type matrix for both runners; exits 2 on drift. Run after touching either runner.

## Commands

```powershell
# Run an audit (output dir must already exist)
.\Invoke-AuditRunner.ps1 -AuditPath C:\Audits\benchmark.audit -OutputPath .\results.csv
# HTML report (offline, self-contained) with white-label branding
.\Invoke-AuditRunner.ps1 -AuditPath C:\Audits\benchmark.audit -OutputPath .\results.csv -HtmlPath .\report.html -CompanyName 'Example Co' -ClientName 'Client X'
.\Invoke-AuditRunner.ps1 -ChecksPath .\benchmark_checks.csv -OutputPath .\results.csv -HtmlPath .\report.html -ReportTitle 'Hardening Review' -AssessorName 'J. Smith' -LogoPath .\logo.png
# Reusable catalog: export, then re-run without the .audit file
.\Invoke-AuditRunner.ps1 -AuditPath C:\Audits\benchmark.audit -ExportChecksPath .\benchmark_checks.csv -OutputPath .\results.csv
.\Invoke-AuditRunner.ps1 -ChecksPath .\benchmark_checks.csv -OutputPath .\results.csv
# Regression (repo root, Windows PowerShell; dot-sources functions via AST, runs no host audit)
.\tests\Invoke-AuditRunner.Regression.ps1
# Parser golden test + support-matrix drift check (run both after touching either runner)
.\tests\Invoke-AuditRunner.Golden.ps1
.\tools\Get-AuditRunnerMatrix.ps1
```

```sh
sh ./audit-runner.sh /path/to/benchmark.audit -o ./results.csv
sh ./audit-runner.sh /path/to/benchmark.audit --allow-command-exec
```

No build, lint, typecheck, CI, or package manager. No `opencode.json`.

## Rules that are easy to get wrong

- `AuditPath` wins if both `-AuditPath` and `-ChecksPath` are given.
- Default outputs are timestamped (`<input>_results_<timestamp>.csv`): beside the script on Windows, in cwd on Unix. `ExportChecksPath` is not parse-only — it still runs the checks.
- Unsupported/unparseable/erroring checks → `Manual` with the reason in `Actual Value`. Never drop them, never mark them `Fail`.
- Embedded code is opt-in only: `-AllowEmbeddedScripts` (Windows) / `--allow-command-exec` (Unix). Without the flag the check is `Manual`. Never enable by default; only run against reviewed, trusted audit files.
- Windows: run on the target in an elevated session; `secedit.exe`/`auditpol.exe`/registry/CIM don't work from a Linux shell. `SERVICE_POLICY` with expected `Disabled` passes when the service is absent (`DisabledOrNotInstalled`); Unix `FileMetadata` (mode/owner/group) always reports `Manual` with collected details.
- Unix eval depends on host tools: `awk grep sed tr` plus `dpkg-query`/`rpm`, `pgrep`, `systemctl`, `stat`. Missing tool → `Manual`, not `Fail`. `sh -c` executes the audit's command string when exec is allowed.
- `KERBEROS_POLICY` (field `kerberos_policy`: TicketValidateClient/MaxServiceAge/MaxTicketAge/MaxRenewAge/MaxClockSkew/ForceLogoffWhenHourExpire) evaluates via secedit like password/lockout policy; unknown keys → `Manual`. Catalog `Checklist` column: `0` → `Manual` ('Excluded by catalog'), row kept; audit-file runs unaffected. Missing secedit/auditpol prints one warning each, no exit-code change.
- Principals canonicalize friendly-name↔SID (unknown → `Manual`); audit tokens `Success and Failure` ≡ `Success, Failure` (unknown fragments stay literal); only `CAN_BE_NULL` passes when a registry value is missing, other missing/collection errors → `Manual`.
- `||` is alternatives (pass if any matches), `&&` is one alternative requiring all items — see `Split-AuditOrExpression` + base64 `ConvertTo-EncodedAlternatives` encoding (`,` joins AND items, `;` joins OR alternatives, empty → `~`). Keep the unary-comma array nesting; the regression test pins this.
- CSVs are UTF-8, quote-escaped. Do not commit real inputs/results: `.gitignore` covers `*.audit *.nessus *_checks.csv *_results_*.csv` — keep assessment material outside the checkout, use sanitised excerpts in issues.
- Script completion ≠ compliance: a run that writes CSV succeeded even if rows are `Fail`/`Manual`. No benchmark files are bundled; partial Nessus-format support only. No licence file in repo.
