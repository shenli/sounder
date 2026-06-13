# Sounder Agent Guide

Use Sounder to inspect Parquet files and diagnose Parquet datasets with metadata first.

## Default Commands

Inspect one Parquet file or S3 object:

```bash
sounder inspect <file-or-s3-object> --agent
```

Check one local directory or S3 prefix as a dataset:

```bash
sounder check <dir-or-s3-prefix> --agent
```

Use full JSON when the caller needs all collected details:

```bash
sounder check <dir-or-s3-prefix> --json
```

Use Markdown when posting a summary into a PR, issue, or chat:

```bash
sounder check <dir-or-s3-prefix> --agent --format markdown
```

## Rules For Agents

- Prefer `--agent` for compact bounded evidence.
- Use `--json` when a workflow needs the full stable report.
- Do not use `--head` unless the user asks to preview rows or inspect values.
- For large datasets, set `--max-files`, `--max-findings`, `--max-columns`, and `--timeout`.
- For S3, pass `--region` and `--profile` when the user provides them.
- Treat exit code `1` as a successful scan with findings that violate policy.
- Treat exit codes `2` through `7` as invalid input, missing input, unreadable data, S3 access failure, scan guardrail, or internal failure.

## Safe Defaults

Sounder does not call an LLM or external AI service. It reads Parquet metadata by default and reads data pages only when `--head` is explicitly requested.
