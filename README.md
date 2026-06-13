# Sounder

Inspect Parquet files and check dataset health on local disk or S3 using metadata only.

A metadata-first Parquet inspector and dataset doctor for humans, CI, and AI agents.

```bash
cargo install --path .

# Inspect file metadata
sounder inspect ./events.parquet

# Peek at rows only when you ask to read data pages
sounder inspect ./events.parquet --head 20

# Check a dataset
sounder check ./events/ --agent --format markdown
```

![Sounder demo](demo/sounder-local.gif)

Find schema drift, row-count skew, suspicious row groups, missing statistics, corrupt files, and simple min/max outliers without scanning data pages by default.

## Commands

```bash
sounder inspect <local-parquet-file-or-s3-object>
sounder check <local-directory-or-s3-prefix>
sounder version
sounder help
```

Aliases:

```bash
sounder file <local-parquet-file-or-s3-object>
sounder dataset <local-directory-or-s3-prefix>
sounder doctor <local-directory-or-s3-prefix>
```

## Output Modes

Human text is the default:

```bash
sounder check ./out
```

Full JSON report for scripts and CI:

```bash
sounder check ./out --json
```

Compact agent evidence packet:

```bash
sounder check ./out --agent
```

Markdown summary for PR comments and issues:

```bash
sounder check ./out --agent --format markdown
```

Every JSON report includes `schema_version: "sounder.report.v1"`. Agent packets use `schema_version: "sounder.agent.v1"`.

Detail levels:

```bash
sounder check ./out --details none
sounder check ./out --details summary
sounder check ./out --details full
```

`none` keeps only high-level artifact, scan, summary, finding, limit, warning, and error fields. `summary` is the default and bounds dataset file examples. `full` emits every collected detail within the configured scan limits.

## Why Agents Use It

Sounder is useful in agent workflows because it turns a Parquet file or dataset into bounded, stable evidence:

- [`AGENTS.md`](AGENTS.md) gives agents a short operating guide for choosing commands, flags, and exit-code handling.
- `--agent` emits compact JSON with `schema_version: "sounder.agent.v1"`, top findings, limits, and suggested next actions.
- `--json` emits a fuller report with stable field names for scripts, CI, and tool calls.
- Exit codes separate invalid input, missing data, S3 permission failures, scan limits, unreadable files, and policy failures.
- Metadata-only defaults keep agent runs cheap and predictable; data pages are read only when `--head` is requested.
- Guardrails such as `--max-files`, `--max-findings`, `--max-columns`, `--timeout`, `--max-requests`, and `--max-bytes` prevent runaway local or S3 scans.
- Sounder does not call an LLM or external AI service. It is a deterministic inspection tool that agents can call and reason over.

## Peek Rows

Row preview is explicit and separate from dataset checks:

```bash
sounder inspect ./events.parquet --head 20
```

For local files and S3 objects, preview mode marks `data_pages_read: true` in JSON and agent output. S3 preview downloads object bytes and is bounded by `--max-bytes`.

## CI Policy

Sounder returns stable exit codes:

| Code | Meaning |
|---:|---|
| 0 | Scan succeeded, no findings above threshold |
| 1 | Scan succeeded, findings violated policy |
| 2 | Invalid arguments |
| 3 | Input not found or no matching Parquet files |
| 4 | Unreadable Parquet or corrupted metadata prevented inspection |
| 5 | S3 auth / permission error |
| 6 | Scan limit exceeded |
| 7 | Internal error |

Policy flags:

```bash
sounder check ./out \
  --json \
  --fail-on schema-drift,corrupt-file \
  --severity-threshold warning
```

Finding names may use either underscores or dashes in `--fail-on`; common aliases such as `missing-stats` and `corrupt-file` are normalized to the stable finding types.

Finding threshold flags:

```bash
sounder check ./out \
  --null-spike-ratio 0.90 \
  --row-count-skew-factor 6 \
  --minmax-outlier-factor 50
```

## Implemented Findings

- `schema_drift`
- `missing_column`
- `extra_column`
- `type_change`
- `row_count_skew`
- `null_spike`
- `all_null_row_group`
- `missing_statistics`
- `minmax_outlier`
- `corrupt_metadata`
- `unreadable_file`
- `scan_truncated`
- `s3_permission_error`

## Guardrails

```bash
sounder check ./large-dataset --max-files 500 --max-findings 20 --max-columns 80 --timeout 30s
```

Machine-oriented modes are non-interactive. If a local or S3 scan exceeds `--max-files` or `--timeout`, Sounder emits a structured `scan_truncated` finding and exits `6`.

S3 scans also enforce `--max-requests` and `--max-bytes` to prevent runaway object-store work. Footer reads are bounded by `--s3-concurrency` and the default timeout is `60s`.

## S3

Sounder supports read-only metadata inspection for S3 objects and prefixes:

```bash
sounder inspect s3://company-lake/events/part-00001.parquet
sounder check s3://company-lake/events/dt=2026-06-11/ --max-files 200
sounder check s3://company-lake/events/dt=2026-06-11/ --s3-concurrency 8
```

S3 scans use object listing, object metadata, and range reads for Parquet footers. They do not write to S3.

`sounder inspect s3://... --head N` is explicit preview mode. It downloads the object for preview, marks `data_pages_read: true`, and is bounded by `--max-bytes`.

Credential and endpoint flags:

```bash
sounder check s3://bucket/prefix/ --region us-east-1
sounder check s3://bucket/prefix/ --endpoint-url http://localhost:4566
sounder check s3://bucket/prefix/ --requester-pays
```

Sounder uses AWS environment variables by default, plus web identity, container, and instance metadata credentials supported by `object_store`.

`--profile` first reads static credentials from AWS shared credentials/config files, including optional session tokens and profile regions. If the profile does not contain static keys, Sounder falls back to `aws configure export-credentials --profile <name> --format env-no-export`, which supports AWS CLI SSO and `credential_process` profiles after you have logged in. Credential values are passed directly into the S3 client and are not printed.

### S3 integration test

The integration test uses your local AWS authentication and never asks you to paste secrets. It creates small Parquet fixtures, uploads them to S3, runs `sounder inspect` and `sounder check`, then removes the test objects.

Create or choose an AWS profile first:

```bash
aws configure --profile your-profile
```

Use an IAM user or role scoped to the scratch bucket or prefix. Avoid root-account access keys.

Use an existing scratch bucket:

```bash
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
export SOUNDER_S3_BUCKET=your-scratch-bucket
export SOUNDER_AWS_ACCOUNT_ID=123456789012
scripts/s3-integration-test.sh
```

Or let the script create and delete a temporary bucket:

```bash
export AWS_PROFILE=your-profile
export AWS_REGION=us-east-1
scripts/s3-integration-test.sh
```

Required AWS permissions for an existing bucket are `s3:PutObject`, `s3:GetObject`, `s3:ListBucket`, and `s3:DeleteObject` on the scratch prefix. Temporary bucket mode also needs `s3:CreateBucket` and `s3:DeleteBucket`.

Example least-privilege policy for an existing bucket and the default integration-test prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::your-scratch-bucket",
      "Condition": {
        "StringLike": {
          "s3:prefix": ["sounder-integration/*"]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::your-scratch-bucket/sounder-integration/*"
    }
  ]
}
```

If `AWS_PROFILE` points at an SSO profile, run `aws sso login --profile your-profile` first. The script and Sounder's `--profile` fallback use `aws configure export-credentials` when available so Sounder receives temporary credentials without printing secrets.

If your shell has stale local proxy variables, run with `SOUNDER_AWS_DIRECT=1` to unset proxy variables only for the integration test process.

## Install

During local development:

```bash
cargo install --path .
```

Planned release channels:

```bash
brew install sounder
cargo install sounder
```

Note: the PyPI package named `sounder` is unrelated. Do not use `pip install sounder` for this tool.

## Current Limitations

- SSO and `credential_process` profiles require AWS CLI v2 and a prior `aws sso login` when applicable.
- No SQL, jq expressions, conversion, editing, or TUI browser.
- Min/max anomaly detection is conservative and currently numeric-only.
- Sounder is metadata-first and does not scan full data pages by default.
