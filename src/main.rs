use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use futures::{StreamExt, TryStreamExt};
use object_store::ObjectStore;
use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey};
use object_store::path::Path as ObjectPath;
use parquet::basic::{Compression, Encoding, Type as PhysicalType};
use parquet::errors::ParquetError;
use parquet::file::metadata::ParquetMetaDataReader;
use parquet::file::metadata::{ColumnChunkMetaData, ParquetMetaData};
use parquet::file::reader::{FileReader, SerializedFileReader};
use parquet::file::statistics::Statistics;
use serde::Serialize;
use walkdir::WalkDir;

mod errors;
mod redaction;

use errors::{
    ExitError, error_type_for_failure, recoverable_for_error_type, suggested_action_for_error_type,
};
use redaction::{format_error, redact_sensitive};

const TOOL_NAME: &str = "sounder";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const REPORT_SCHEMA_VERSION: &str = "sounder.report.v1";
const AGENT_SCHEMA_VERSION: &str = "sounder.agent.v1";

#[derive(Parser, Clone, Debug)]
#[command(
    name = "sounder",
    version,
    about = "Metadata-first Parquet inspector and dataset doctor"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, help = "Emit a full stable JSON report")]
    json: bool,

    #[arg(
        long,
        global = true,
        help = "Emit a compact evidence packet for agents"
    )]
    agent: bool,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text, global = true, help = "Choose text, JSON, or Markdown output")]
    format: OutputFormat,

    #[arg(long, value_enum, default_value_t = Details::Summary, global = true, help = "Control emitted detail volume")]
    details: Details,

    #[arg(
        long,
        default_value_t = 1000,
        global = true,
        help = "Maximum Parquet files or S3 objects to scan"
    )]
    max_files: usize,

    #[arg(
        long,
        default_value_t = 20,
        global = true,
        help = "Maximum findings to emit"
    )]
    max_findings: usize,

    #[arg(
        long,
        default_value_t = 5,
        global = true,
        help = "Maximum example files per finding"
    )]
    max_example_files: usize,

    #[arg(
        long,
        default_value_t = 80,
        global = true,
        help = "Maximum schema/column details to emit"
    )]
    max_columns: usize,

    #[arg(
        long,
        default_value = "60s",
        global = true,
        help = "Maximum scan duration, e.g. 500ms, 30s, 2m"
    )]
    timeout: Option<String>,

    #[arg(
        long,
        global = true,
        help = "Fail CI on finding types, e.g. schema-drift,corrupt-file"
    )]
    fail_on: Option<String>,

    #[arg(long, value_enum, default_value_t = Severity::Warning, global = true, help = "Fail on findings at or above this severity")]
    severity_threshold: Severity,

    #[arg(
        long,
        default_value_t = 0.95,
        global = true,
        help = "Null ratio threshold for null_spike findings"
    )]
    null_spike_ratio: f64,

    #[arg(
        long,
        default_value_t = 8.0,
        global = true,
        help = "Median row-count skew factor"
    )]
    row_count_skew_factor: f64,

    #[arg(
        long,
        default_value_t = 100.0,
        global = true,
        help = "Numeric min/max outlier factor"
    )]
    minmax_outlier_factor: f64,

    #[arg(long, global = true, help = "Disable ANSI color in human text output")]
    no_color: bool,

    #[arg(long, global = true, help = "Suppress human text output")]
    quiet: bool,

    #[arg(
        long,
        global = true,
        help = "Include more diagnostic context in errors when available"
    )]
    verbose: bool,

    #[arg(long, global = true, help = "AWS region for S3 reads")]
    region: Option<String>,

    #[arg(long, global = true, help = "AWS profile for S3 credentials")]
    profile: Option<String>,

    #[arg(long, global = true, help = "S3-compatible endpoint URL")]
    endpoint_url: Option<String>,

    #[arg(long, global = true, help = "Send requester-pays headers for S3 reads")]
    requester_pays: bool,

    #[arg(
        long,
        default_value_t = 2000,
        global = true,
        help = "Maximum S3 metadata/list/range requests"
    )]
    max_requests: usize,

    #[arg(long, default_value_t = 64 * 1024 * 1024, global = true, help = "Maximum S3 bytes to download")]
    max_bytes: usize,

    #[arg(
        long,
        default_value_t = 16,
        global = true,
        help = "Maximum concurrent S3 footer reads"
    )]
    s3_concurrency: usize,
}

#[derive(Subcommand, Clone, Debug)]
enum Commands {
    #[command(about = "Inspect one local or S3 Parquet file")]
    Inspect {
        #[arg(help = "Local Parquet file or s3://bucket/key.parquet")]
        target: String,
        #[arg(long, help = "Preview N rows by explicitly reading data pages")]
        head: Option<usize>,
    },
    #[command(about = "Alias for inspect")]
    File {
        #[arg(help = "Local Parquet file or s3://bucket/key.parquet")]
        target: String,
        #[arg(long, help = "Preview N rows by explicitly reading data pages")]
        head: Option<usize>,
    },
    #[command(about = "Check a local directory or S3 prefix as one dataset")]
    Check {
        #[arg(help = "Local directory or s3://bucket/prefix/")]
        target: String,
    },
    #[command(about = "Alias for check")]
    Dataset {
        #[arg(help = "Local directory or s3://bucket/prefix/")]
        target: String,
    },
    #[command(about = "Alias for check")]
    Doctor {
        #[arg(help = "Local directory or s3://bucket/prefix/")]
        target: String,
    },
    #[command(about = "Print the Sounder version")]
    Version,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Markdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmitMode {
    TextReport,
    JsonReport,
    JsonAgent,
    MarkdownReport,
    MarkdownAgent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Details {
    None,
    Summary,
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Info,
    Warning,
    Error,
}

impl Status {
    fn from_findings(findings: &[Finding]) -> Self {
        if findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
        {
            Status::Error
        } else if findings
            .iter()
            .any(|finding| finding.severity == Severity::Warning)
        {
            Status::Warning
        } else if findings
            .iter()
            .any(|finding| finding.severity == Severity::Info)
        {
            Status::Info
        } else {
            Status::Ok
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Info => "info",
            Status::Warning => "warning",
            Status::Error => "error",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct Report {
    schema_version: &'static str,
    tool: Tool,
    command: &'static str,
    status: Status,
    artifact: Artifact,
    scan: Scan,
    summary: Summary,
    schema: SchemaSummary,
    columns: Vec<ColumnSummary>,
    row_groups: RowGroupSummary,
    files: Vec<FileSummary>,
    findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview: Option<Preview>,
    limits: Limits,
    warnings: Vec<String>,
    errors: Vec<ErrorInfo>,
}

#[derive(Clone, Debug, Serialize)]
struct AgentPacket {
    schema_version: &'static str,
    command: &'static str,
    status: Status,
    artifact: Artifact,
    scan: Scan,
    summary: String,
    top_findings: Vec<Finding>,
    recommended_next_actions: Vec<String>,
    limits: Limits,
    tool: Tool,
}

#[derive(Clone, Debug, Serialize)]
struct Artifact {
    #[serde(rename = "type")]
    artifact_type: &'static str,
    uri: String,
    rows: i64,
    columns: usize,
    row_groups: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    files_matched: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    files_scanned: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
struct Scan {
    mode: &'static str,
    data_pages_read: bool,
    complete: bool,
    scan_truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
struct Summary {
    message: String,
    rows: i64,
    columns: usize,
    files: usize,
    findings: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SchemaSummary {
    column_count: usize,
    variants: usize,
    canonical: Vec<SchemaField>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct SchemaField {
    name: String,
    physical_type: String,
    logical_type: String,
    max_definition_level: i16,
}

#[derive(Clone, Debug, Serialize)]
struct ColumnSummary {
    name: String,
    physical_type: String,
    logical_type: String,
    files_present: usize,
    row_groups_present: usize,
    row_groups_with_statistics: usize,
    row_groups_missing_statistics: usize,
    null_count: Option<i64>,
    min_value: Option<String>,
    max_value: Option<String>,
    all_null_row_groups: usize,
    compression: Vec<String>,
    encodings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct RowGroupSummary {
    count: usize,
    min_rows: Option<i64>,
    median_rows: Option<i64>,
    max_rows: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct FileSummary {
    uri: String,
    rows: i64,
    columns: usize,
    row_groups: usize,
    size_bytes: Option<u64>,
    created_by: Option<String>,
    key_value_metadata: BTreeMap<String, String>,
    schema_fingerprint: String,
    #[serde(skip)]
    schema: Vec<SchemaField>,
    suspicious_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Preview {
    requested_rows: usize,
    returned_rows: usize,
    rows: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct S3Target {
    bucket: String,
    key: String,
}

#[derive(Clone, Debug)]
struct S3Object {
    uri: String,
    path: ObjectPath,
}

#[derive(Debug)]
struct S3Budget {
    max_requests: usize,
    used_requests: usize,
    max_bytes: usize,
    used_bytes: usize,
}

type SharedS3Budget = Arc<Mutex<S3Budget>>;

#[derive(Debug, Default, Eq, PartialEq)]
struct AwsProfileConfig {
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
    region: Option<String>,
}

impl S3Budget {
    fn new(cli: &Cli) -> Result<SharedS3Budget> {
        if cli.max_requests == 0 {
            return Err(
                ExitError::new(6, "--max-requests must be greater than 0 for S3 scans").into(),
            );
        }
        Ok(Arc::new(Mutex::new(Self {
            max_requests: cli.max_requests,
            used_requests: 0,
            max_bytes: cli.max_bytes,
            used_bytes: 0,
        })))
    }

    fn record_request(&mut self, operation: &str) -> Result<()> {
        self.used_requests += 1;
        if self.used_requests > self.max_requests {
            return Err(ExitError::new(
                6,
                format!(
                    "S3 request budget exceeded during {operation}: used {} requests, limit is {}",
                    self.used_requests, self.max_requests
                ),
            )
            .into());
        }
        Ok(())
    }

    fn record_bytes(&mut self, bytes: usize, operation: &str) -> Result<()> {
        self.used_bytes = self.used_bytes.saturating_add(bytes);
        if self.used_bytes > self.max_bytes {
            return Err(ExitError::new(
                6,
                format!(
                    "S3 byte budget exceeded during {operation}: fetched {} bytes, limit is {}",
                    self.used_bytes, self.max_bytes
                ),
            )
            .into());
        }
        Ok(())
    }
}

fn record_s3_request(budget: &SharedS3Budget, operation: &str) -> Result<()> {
    let mut budget = budget
        .lock()
        .map_err(|_| ExitError::new(7, "S3 budget state was poisoned"))?;
    budget.record_request(operation)
}

fn record_s3_bytes(budget: &SharedS3Budget, bytes: usize, operation: &str) -> Result<()> {
    let mut budget = budget
        .lock()
        .map_err(|_| ExitError::new(7, "S3 budget state was poisoned"))?;
    budget.record_bytes(bytes, operation)
}

#[derive(Clone, Debug)]
struct NumericRange {
    file: String,
    column: String,
    min: f64,
    max: f64,
}

#[derive(Clone, Debug, Serialize)]
struct Finding {
    id: String,
    #[serde(rename = "type")]
    finding_type: String,
    severity: Severity,
    confidence: &'static str,
    message: String,
    location: FindingLocation,
    evidence: BTreeMap<String, serde_json::Value>,
    suggested_action: String,
    example_files: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct FindingLocation {
    file: Option<String>,
    row_group: Option<usize>,
    column: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Limits {
    max_files: usize,
    max_findings: usize,
    max_example_files: usize,
    max_columns: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout: Option<String>,
    max_requests: usize,
    max_bytes: usize,
    s3_concurrency: usize,
    null_spike_ratio: f64,
    row_count_skew_factor: f64,
    minmax_outlier_factor: f64,
}

#[derive(Clone, Debug, Serialize)]
struct ErrorInfo {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
    recoverable: bool,
    suggested_action: String,
}

#[derive(Debug)]
struct InspectedFile {
    summary: FileSummary,
    schema: Vec<SchemaField>,
    columns: Vec<ColumnSummary>,
    row_group_rows: Vec<i64>,
    numeric_ranges: Vec<NumericRange>,
    findings: Vec<FindingSeed>,
}

#[derive(Clone, Debug)]
struct FindingSeed {
    finding_type: &'static str,
    severity: Severity,
    confidence: &'static str,
    message: String,
    location: FindingLocation,
    evidence: BTreeMap<String, serde_json::Value>,
    suggested_action: String,
    example_files: Vec<String>,
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match run(&cli) {
        Ok(code) => code,
        Err(err) => {
            let exit_code = err
                .downcast_ref::<ExitError>()
                .map(|error| error.code)
                .unwrap_or(7);
            if should_emit_structured_failure(&cli) {
                let report = command_failure_report(&cli, &err, exit_code);
                if let Err(emit_err) = emit_report(&report, &cli) {
                    eprintln!(
                        "sounder: failed to emit structured error: {}",
                        redact_sensitive(&format_error(&emit_err, cli.verbose))
                    );
                    eprintln!(
                        "sounder: {}",
                        redact_sensitive(&format_error(&err, cli.verbose))
                    );
                }
            } else {
                eprintln!(
                    "sounder: {}",
                    redact_sensitive(&format_error(&err, cli.verbose))
                );
            }
            exit_code
        }
    };
    std::process::exit(exit_code);
}

fn run(cli: &Cli) -> Result<i32> {
    validate_cli(&cli)?;
    match &cli.command {
        Commands::Version => {
            println!("{TOOL_NAME} {TOOL_VERSION}");
            Ok(0)
        }
        Commands::Inspect { target, head } | Commands::File { target, head } => {
            let report = inspect_command(target, *head, &cli)?;
            emit_report(&report, &cli)?;
            Ok(exit_code_for_report(&report, &cli))
        }
        Commands::Check { target } | Commands::Dataset { target } | Commands::Doctor { target } => {
            let report = check_command(target, &cli)?;
            emit_report(&report, &cli)?;
            Ok(exit_code_for_report(&report, &cli))
        }
    }
}

fn validate_cli(cli: &Cli) -> Result<()> {
    if !(0.0..=1.0).contains(&cli.null_spike_ratio) {
        return Err(ExitError::new(2, "--null-spike-ratio must be between 0.0 and 1.0").into());
    }
    if cli.row_count_skew_factor <= 1.0 {
        return Err(ExitError::new(2, "--row-count-skew-factor must be greater than 1.0").into());
    }
    if cli.minmax_outlier_factor <= 1.0 {
        return Err(ExitError::new(2, "--minmax-outlier-factor must be greater than 1.0").into());
    }
    if let Some(fail_on) = &cli.fail_on {
        validate_fail_on(fail_on)?;
    }
    timeout_duration(cli)?;
    Ok(())
}

fn should_emit_structured_failure(cli: &Cli) -> bool {
    cli.json || cli.agent || cli.format != OutputFormat::Text
}

fn command_failure_report(cli: &Cli, err: &anyhow::Error, exit_code: i32) -> Report {
    let (command, artifact_type, uri) = command_context(cli);
    let error_type = error_type_for_failure(err, exit_code);
    let message = redact_sensitive(&format_error(err, cli.verbose));
    let scan_truncated = exit_code == 6;
    let mut report = Report {
        schema_version: REPORT_SCHEMA_VERSION,
        tool: Tool {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        },
        command,
        status: Status::Error,
        artifact: Artifact {
            artifact_type,
            uri,
            rows: 0,
            columns: 0,
            row_groups: 0,
            size_bytes: None,
            files_matched: (command == "check").then_some(0),
            files_scanned: (command == "check").then_some(0),
        },
        scan: Scan {
            mode: "metadata_only",
            data_pages_read: false,
            complete: false,
            scan_truncated,
        },
        summary: Summary {
            message: "Command failed before metadata inspection completed.".to_string(),
            rows: 0,
            columns: 0,
            files: 0,
            findings: 1,
        },
        schema: SchemaSummary::default(),
        columns: Vec::new(),
        row_groups: RowGroupSummary {
            count: 0,
            min_rows: None,
            median_rows: None,
            max_rows: None,
        },
        files: Vec::new(),
        findings: vec![make_finding(
            error_type,
            Severity::Error,
            "high",
            message.clone(),
            FindingLocation::default(),
            BTreeMap::new(),
            suggested_action_for_error_type(error_type).to_string(),
            Vec::new(),
            1,
        )],
        preview: None,
        limits: limits(cli),
        warnings: Vec::new(),
        errors: vec![ErrorInfo {
            error_type: error_type.to_string(),
            message,
            recoverable: recoverable_for_error_type(error_type, exit_code),
            suggested_action: suggested_action_for_error_type(error_type).to_string(),
        }],
    };
    finalize_report(&mut report, cli);
    report
}

fn scan_truncated_failure_report(
    command: &'static str,
    uri: &str,
    artifact_type: &'static str,
    message: String,
    cli: &Cli,
) -> Report {
    let mut report = Report {
        schema_version: REPORT_SCHEMA_VERSION,
        tool: Tool {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        },
        command,
        status: Status::Error,
        artifact: Artifact {
            artifact_type,
            uri: uri.to_string(),
            rows: 0,
            columns: 0,
            row_groups: 0,
            size_bytes: None,
            files_matched: (command == "check").then_some(0),
            files_scanned: (command == "check").then_some(0),
        },
        scan: Scan {
            mode: "metadata_only",
            data_pages_read: false,
            complete: false,
            scan_truncated: true,
        },
        summary: Summary {
            message: "Command exceeded configured scan limits.".to_string(),
            rows: 0,
            columns: 0,
            files: 0,
            findings: 1,
        },
        schema: SchemaSummary::default(),
        columns: Vec::new(),
        row_groups: RowGroupSummary {
            count: 0,
            min_rows: None,
            median_rows: None,
            max_rows: None,
        },
        files: Vec::new(),
        findings: vec![make_finding(
            "scan_truncated",
            Severity::Warning,
            "high",
            redact_sensitive(&message),
            FindingLocation::default(),
            scan_truncated_evidence(&limits(cli)),
            "Increase configured limits only after confirming the scan scope is expected."
                .to_string(),
            Vec::new(),
            1,
        )],
        preview: None,
        limits: limits(cli),
        warnings: Vec::new(),
        errors: vec![ErrorInfo {
            error_type: "scan_truncated".to_string(),
            message: redact_sensitive(&message),
            recoverable: true,
            suggested_action:
                "Increase configured limits only after confirming the scan scope is expected."
                    .to_string(),
        }],
    };
    finalize_report(&mut report, cli);
    report
}

fn command_context(cli: &Cli) -> (&'static str, &'static str, String) {
    match &cli.command {
        Commands::Inspect { target, .. } | Commands::File { target, .. } => {
            ("inspect", "parquet_file", target.clone())
        }
        Commands::Check { target } | Commands::Dataset { target } | Commands::Doctor { target } => {
            ("check", "parquet_dataset", target.clone())
        }
        Commands::Version => ("version", "command", "version".to_string()),
    }
}

fn run_async<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Runtime::new()?.block_on(future)
}

fn run_s3_report_async(
    command: &'static str,
    target: &str,
    future: impl std::future::Future<Output = Result<Report>>,
    cli: &Cli,
) -> Result<Report> {
    let timeout_label = timeout_label(cli);
    let timeout_duration = timeout_duration(cli)?;
    let target = target.to_string();
    run_async(async move {
        match tokio::time::timeout(timeout_duration, future).await {
            Ok(result) => result,
            Err(_) => {
                let err: anyhow::Error =
                    ExitError::new(6, format!("S3 scan exceeded --timeout {timeout_label}")).into();
                Ok(s3_failure_report(command, &target, &err, cli))
            }
        }
    })
}

fn inspect_command(target: &str, head: Option<usize>, cli: &Cli) -> Result<Report> {
    if is_s3_uri(target) {
        return run_s3_report_async("inspect", target, inspect_s3_object(target, head, cli), cli);
    }
    validate_local_inspect_target(target)?;
    let target_owned = target.to_string();
    let cli_owned = cli.clone();
    run_local_report_with_timeout("inspect", target, "parquet_file", cli, move || {
        inspect_local_target(&target_owned, head, &cli_owned)
    })
}

fn inspect_local_target(target: &str, head: Option<usize>, cli: &Cli) -> Result<Report> {
    if let Some(requested_rows) = head {
        let mut report = inspect_local_file(target, cli)?;
        report.preview = Some(
            preview_rows(Path::new(target), requested_rows).map_err(|err| {
                ExitError::new(
                    4,
                    format!("failed to read row preview for {target}: {err:#}"),
                )
            })?,
        );
        report.scan.mode = "metadata_with_preview";
        report.scan.data_pages_read = true;
        finalize_report(&mut report, cli);
        return Ok(report);
    }
    inspect_local_file(target, cli)
}

fn validate_local_inspect_target(target: &str) -> Result<()> {
    let path = Path::new(target);
    if !path.exists() {
        return Err(ExitError::new(3, format!("input not found: {target}")).into());
    }
    if !path.is_file() {
        return Err(ExitError::new(2, format!("inspect expects a Parquet file: {target}")).into());
    }
    Ok(())
}

fn inspect_local_file(target: &str, cli: &Cli) -> Result<Report> {
    validate_local_inspect_target(target)?;
    let path = Path::new(target);
    let inspected = read_parquet_file(path, target, cli).map_err(|err| {
        ExitError::with_type(
            4,
            classify_parquet_read_error(&err),
            format!("failed to inspect Parquet metadata for {target}: {err:#}"),
        )
    })?;
    Ok(report_from_files(
        "inspect",
        target,
        "parquet_file",
        vec![inspected],
        true,
        false,
        cli,
        Vec::new(),
        Vec::new(),
    ))
}

fn run_local_report_with_timeout(
    command: &'static str,
    target: &str,
    artifact_type: &'static str,
    cli: &Cli,
    operation: impl FnOnce() -> Result<Report> + Send + 'static,
) -> Result<Report> {
    let timeout_label = timeout_label(cli);
    let timeout_duration = timeout_duration(cli)?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(operation());
    });

    match receiver.recv_timeout(timeout_duration) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Ok(scan_truncated_failure_report(
            command,
            target,
            artifact_type,
            format!("local {command} exceeded --timeout {timeout_label}"),
            cli,
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(ExitError::new(7, format!("local {command} worker stopped unexpectedly")).into())
        }
    }
}

fn check_command(target: &str, cli: &Cli) -> Result<Report> {
    if is_s3_uri(target) {
        return run_s3_report_async("check", target, check_s3_prefix(target, cli), cli);
    }
    let root = Path::new(target);
    if !root.exists() {
        return Err(ExitError::new(3, format!("input not found: {target}")).into());
    }
    let files = discover_parquet_files(root)?;
    let files_matched = files.len();
    if files.is_empty() {
        return Err(
            ExitError::new(3, format!("no matching Parquet files found under {target}")).into(),
        );
    }

    let mut warnings = Vec::new();
    let mut scan_truncated = false;
    let files_to_scan = if files.len() > cli.max_files {
        scan_truncated = true;
        warnings.push(format!(
            "scan truncated: matched {} files but --max-files is {}",
            files.len(),
            cli.max_files
        ));
        files.into_iter().take(cli.max_files).collect::<Vec<_>>()
    } else {
        files
    };

    let timeout_duration = timeout_duration(cli)?;
    let (inspected, errors, timed_out, files_scanned) =
        read_local_parquet_files(files_to_scan, cli, timeout_duration);
    if timed_out {
        scan_truncated = true;
        warnings.push(format!(
            "scan truncated: local check exceeded --timeout {}",
            timeout_label(cli)
        ));
    }
    if inspected.is_empty() && !errors.is_empty() {
        return Err(
            ExitError::new(4, format!("no readable Parquet files found under {target}")).into(),
        );
    }

    let mut report = report_from_files(
        "check",
        target,
        "parquet_dataset",
        inspected,
        !scan_truncated,
        scan_truncated,
        cli,
        warnings,
        errors,
    );
    report.artifact.files_matched = Some(files_matched);
    report.artifact.files_scanned = Some(files_scanned);
    add_dataset_findings(&mut report, cli);
    finalize_report(&mut report, cli);
    Ok(report)
}

fn read_local_parquet_files(
    files_to_scan: Vec<PathBuf>,
    cli: &Cli,
    timeout_duration: Duration,
) -> (Vec<InspectedFile>, Vec<ErrorInfo>, bool, usize) {
    let concurrency = cli.s3_concurrency.max(1);
    let mut inspected = Vec::new();
    let mut errors = Vec::new();
    let started = Instant::now();
    let mut timed_out = false;
    let mut files_scanned = 0usize;

    for batch in files_to_scan.chunks(concurrency) {
        if started.elapsed() >= timeout_duration {
            timed_out = true;
            break;
        }
        files_scanned += batch.len();
        let batch_results = thread::scope(|scope| {
            let handles = batch
                .iter()
                .map(|path| {
                    let path = path.clone();
                    let uri = path.display().to_string();
                    let uri_for_error = uri.clone();
                    let handle = scope.spawn(move || {
                        let result = read_parquet_file(&path, &uri, cli);
                        (uri, result)
                    });
                    (uri_for_error, handle)
                })
                .collect::<Vec<_>>();

            handles
                .into_iter()
                .map(|(uri, handle)| match handle.join() {
                    Ok(result) => result,
                    Err(_) => (
                        uri,
                        Err(anyhow::anyhow!(
                            "internal error while reading Parquet metadata"
                        )),
                    ),
                })
                .collect::<Vec<_>>()
        });

        for (uri, result) in batch_results {
            match result {
                Ok(file) => inspected.push(file),
                Err(err) => errors.push(local_read_error_info(&uri, &err)),
            }
        }
        if started.elapsed() >= timeout_duration {
            timed_out = true;
            break;
        }
    }

    (inspected, errors, timed_out, files_scanned)
}

fn local_read_error_info(uri: &str, err: &anyhow::Error) -> ErrorInfo {
    ErrorInfo {
        error_type: classify_parquet_read_error(err).to_string(),
        message: redact_sensitive(&format!("{uri}: {err:#}")),
        recoverable: true,
        suggested_action: "Remove or rewrite the unreadable Parquet file.".to_string(),
    }
}

fn read_parquet_file(path: &Path, uri: &str, cli: &Cli) -> Result<InspectedFile> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let size_bytes = file.metadata().ok().map(|metadata| metadata.len());
    let reader = SerializedFileReader::new(file)?;
    let metadata = reader.metadata();
    Ok(inspect_metadata(metadata, uri, size_bytes, cli))
}

fn preview_rows(path: &Path, requested_rows: usize) -> Result<Preview> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let reader = SerializedFileReader::new(file)?;
    preview_rows_from_reader(reader, requested_rows)
}

fn preview_rows_from_bytes(bytes: Bytes, requested_rows: usize) -> Result<Preview> {
    let reader = SerializedFileReader::new(bytes)?;
    preview_rows_from_reader(reader, requested_rows)
}

fn preview_rows_from_reader<R>(
    reader: SerializedFileReader<R>,
    requested_rows: usize,
) -> Result<Preview>
where
    R: parquet::file::reader::ChunkReader + 'static,
{
    let mut rows = Vec::new();
    for row in reader.get_row_iter(None)?.take(requested_rows) {
        rows.push(format!("{}", row?));
    }
    Ok(Preview {
        requested_rows,
        returned_rows: rows.len(),
        rows,
    })
}

fn inspect_metadata(
    metadata: &ParquetMetaData,
    uri: &str,
    size_bytes: Option<u64>,
    cli: &Cli,
) -> InspectedFile {
    let file_metadata = metadata.file_metadata();
    let schema = schema_fields(metadata);
    let columns = column_summaries(metadata);
    let numeric_ranges = numeric_ranges(metadata, uri);
    let row_group_rows = metadata
        .row_groups()
        .iter()
        .map(|row_group| row_group.num_rows())
        .collect::<Vec<_>>();
    let rows = file_metadata.num_rows();
    let fingerprint = schema_fingerprint(&schema);
    let mut findings = Vec::new();

    for column in &columns {
        if column.row_groups_present > 0
            && column.row_groups_missing_statistics == column.row_groups_present
        {
            findings.push(FindingSeed {
                finding_type: "missing_statistics",
                severity: Severity::Warning,
                confidence: "high",
                message: format!(
                    "{} has no row-group statistics in {} row groups",
                    column.name, column.row_groups_present
                ),
                location: FindingLocation {
                    file: Some(uri.to_string()),
                    row_group: None,
                    column: Some(column.name.clone()),
                },
                evidence: btree_json([
                    (
                        "row_groups_missing_statistics",
                        column.row_groups_missing_statistics,
                    ),
                    ("row_groups_present", column.row_groups_present),
                ]),
                suggested_action: "Check whether the writer disabled statistics for this column."
                    .to_string(),
                example_files: vec![uri.to_string()],
            });
        } else if column.row_groups_missing_statistics > 0 {
            findings.push(FindingSeed {
                finding_type: "missing_statistics",
                severity: Severity::Info,
                confidence: "high",
                message: format!(
                    "{} is missing statistics in {} row groups",
                    column.name, column.row_groups_missing_statistics
                ),
                location: FindingLocation {
                    file: Some(uri.to_string()),
                    row_group: None,
                    column: Some(column.name.clone()),
                },
                evidence: btree_json([
                    (
                        "row_groups_missing_statistics",
                        column.row_groups_missing_statistics,
                    ),
                    ("row_groups_present", column.row_groups_present),
                ]),
                suggested_action:
                    "Use files with complete statistics for stronger metadata-only diagnosis."
                        .to_string(),
                example_files: vec![uri.to_string()],
            });
        }

        if column.all_null_row_groups > 0 {
            findings.push(FindingSeed {
                finding_type: "all_null_row_group",
                severity: Severity::Warning,
                confidence: "high",
                message: format!(
                    "{} is all-null in {} row groups",
                    column.name, column.all_null_row_groups
                ),
                location: FindingLocation {
                    file: Some(uri.to_string()),
                    row_group: None,
                    column: Some(column.name.clone()),
                },
                evidence: btree_json([("all_null_row_groups", column.all_null_row_groups)]),
                suggested_action: "Inspect the producer job for null handling regressions."
                    .to_string(),
                example_files: vec![uri.to_string()],
            });
        }

        if let Some(null_count) = column.null_count {
            if rows > 0 {
                let ratio = null_count as f64 / rows as f64;
                if ratio >= cli.null_spike_ratio {
                    findings.push(FindingSeed {
                        finding_type: "null_spike",
                        severity: Severity::Warning,
                        confidence: "medium",
                        message: format!("{} is {:.1}% null", column.name, ratio * 100.0),
                        location: FindingLocation {
                            file: Some(uri.to_string()),
                            row_group: None,
                            column: Some(column.name.clone()),
                        },
                        evidence: btree_json([
                            ("null_count", serde_json::json!(null_count)),
                            ("rows", serde_json::json!(rows)),
                            (
                                "null_ratio_percent",
                                serde_json::json!((ratio * 1000.0).round() / 10.0),
                            ),
                            ("threshold_ratio", serde_json::json!(cli.null_spike_ratio)),
                        ]),
                        suggested_action:
                            "Compare this file against a known healthy output from the same writer."
                                .to_string(),
                        example_files: vec![uri.to_string()],
                    });
                }
            }
        }
    }

    InspectedFile {
        summary: FileSummary {
            uri: uri.to_string(),
            rows,
            columns: schema.len(),
            row_groups: metadata.num_row_groups(),
            size_bytes,
            created_by: file_metadata.created_by().map(ToOwned::to_owned),
            key_value_metadata: key_value_metadata(file_metadata),
            schema_fingerprint: fingerprint,
            schema: schema.clone(),
            suspicious_reasons: Vec::new(),
        },
        schema,
        columns,
        row_group_rows,
        numeric_ranges,
        findings,
    }
}

fn schema_fields(metadata: &ParquetMetaData) -> Vec<SchemaField> {
    metadata
        .file_metadata()
        .schema_descr()
        .columns()
        .iter()
        .map(|column| SchemaField {
            name: column.path().string(),
            physical_type: format_physical_type(column.physical_type()),
            logical_type: format!("{:?}", column.logical_type()),
            max_definition_level: column.max_def_level(),
        })
        .collect()
}

fn key_value_metadata(
    file_metadata: &parquet::file::metadata::FileMetaData,
) -> BTreeMap<String, String> {
    file_metadata
        .key_value_metadata()
        .map(|metadata| {
            metadata
                .iter()
                .map(|item| {
                    (
                        item.key.clone(),
                        item.value.clone().unwrap_or_else(|| "<none>".to_string()),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn column_summaries(metadata: &ParquetMetaData) -> Vec<ColumnSummary> {
    let mut columns: BTreeMap<String, MutableColumnSummary> = BTreeMap::new();
    for row_group in metadata.row_groups() {
        for column in row_group.columns() {
            let name = column.column_path().string();
            columns
                .entry(name.clone())
                .or_insert_with(|| MutableColumnSummary::new(name.clone(), column))
                .add_column(column, row_group.num_rows());
        }
    }
    columns
        .into_values()
        .map(MutableColumnSummary::finish)
        .collect()
}

fn numeric_ranges(metadata: &ParquetMetaData, file: &str) -> Vec<NumericRange> {
    let mut ranges: BTreeMap<String, (f64, f64)> = BTreeMap::new();
    for row_group in metadata.row_groups() {
        for column in row_group.columns() {
            let Some(statistics) = column.statistics() else {
                continue;
            };
            let Some((min, max)) = numeric_min_max(statistics) else {
                continue;
            };
            let name = column.column_path().string();
            ranges
                .entry(name)
                .and_modify(|range| {
                    range.0 = range.0.min(min);
                    range.1 = range.1.max(max);
                })
                .or_insert((min, max));
        }
    }
    ranges
        .into_iter()
        .map(|(column, (min, max))| NumericRange {
            file: file.to_string(),
            column,
            min,
            max,
        })
        .collect()
}

fn numeric_min_max(statistics: &Statistics) -> Option<(f64, f64)> {
    match statistics {
        Statistics::Int32(stats) => Some((*stats.min_opt()? as f64, *stats.max_opt()? as f64)),
        Statistics::Int64(stats) => Some((*stats.min_opt()? as f64, *stats.max_opt()? as f64)),
        Statistics::Float(stats) => Some((*stats.min_opt()? as f64, *stats.max_opt()? as f64)),
        Statistics::Double(stats) => Some((*stats.min_opt()?, *stats.max_opt()?)),
        _ => None,
    }
}

#[derive(Debug)]
struct MutableColumnSummary {
    name: String,
    physical_type: String,
    logical_type: String,
    files_present: usize,
    row_groups_present: usize,
    row_groups_with_statistics: usize,
    row_groups_missing_statistics: usize,
    null_count: i64,
    null_count_known: bool,
    min_value: Option<StatValue>,
    max_value: Option<StatValue>,
    all_null_row_groups: usize,
    compression: BTreeSet<String>,
    encodings: BTreeSet<String>,
}

#[derive(Clone, Debug)]
enum StatValue {
    Number(f64),
    Text(String),
}

impl StatValue {
    fn display(&self) -> String {
        match self {
            StatValue::Number(value) => {
                if value.fract() == 0.0 {
                    format!("{value:.0}")
                } else {
                    format!("{value}")
                }
            }
            StatValue::Text(value) => value.clone(),
        }
    }
}

impl MutableColumnSummary {
    fn new(name: String, column: &ColumnChunkMetaData) -> Self {
        Self {
            name,
            physical_type: format_physical_type(column.column_type()),
            logical_type: format!("{:?}", column.column_descr().logical_type()),
            files_present: 1,
            row_groups_present: 0,
            row_groups_with_statistics: 0,
            row_groups_missing_statistics: 0,
            null_count: 0,
            null_count_known: false,
            min_value: None,
            max_value: None,
            all_null_row_groups: 0,
            compression: BTreeSet::new(),
            encodings: BTreeSet::new(),
        }
    }

    fn add_column(&mut self, column: &ColumnChunkMetaData, row_group_rows: i64) {
        self.row_groups_present += 1;
        self.compression
            .insert(format_compression(column.compression()));
        for encoding in column.encodings() {
            self.encodings.insert(format_encoding(*encoding));
        }
        match column.statistics() {
            Some(statistics) => {
                self.row_groups_with_statistics += 1;
                if let Some(null_count) = statistics.null_count_opt() {
                    let null_count = null_count as i64;
                    self.null_count += null_count;
                    self.null_count_known = true;
                    if row_group_rows > 0 && null_count >= row_group_rows {
                        self.all_null_row_groups += 1;
                    }
                }
                if let Some((min_value, max_value)) = statistic_values(statistics) {
                    self.min_value = Some(match self.min_value.take() {
                        Some(existing) => min_stat_value(existing, min_value),
                        None => min_value,
                    });
                    self.max_value = Some(match self.max_value.take() {
                        Some(existing) => max_stat_value(existing, max_value),
                        None => max_value,
                    });
                }
            }
            None => self.row_groups_missing_statistics += 1,
        }
    }

    fn finish(self) -> ColumnSummary {
        ColumnSummary {
            name: self.name,
            physical_type: self.physical_type,
            logical_type: self.logical_type,
            files_present: self.files_present,
            row_groups_present: self.row_groups_present,
            row_groups_with_statistics: self.row_groups_with_statistics,
            row_groups_missing_statistics: self.row_groups_missing_statistics,
            null_count: self.null_count_known.then_some(self.null_count),
            min_value: self.min_value.map(|value| value.display()),
            max_value: self.max_value.map(|value| value.display()),
            all_null_row_groups: self.all_null_row_groups,
            compression: self.compression.into_iter().collect(),
            encodings: self.encodings.into_iter().collect(),
        }
    }
}

fn statistic_values(statistics: &Statistics) -> Option<(StatValue, StatValue)> {
    match statistics {
        Statistics::Boolean(stats) => Some((
            StatValue::Text(stats.min_opt()?.to_string()),
            StatValue::Text(stats.max_opt()?.to_string()),
        )),
        Statistics::Int32(stats) => Some((
            StatValue::Number(*stats.min_opt()? as f64),
            StatValue::Number(*stats.max_opt()? as f64),
        )),
        Statistics::Int64(stats) => Some((
            StatValue::Number(*stats.min_opt()? as f64),
            StatValue::Number(*stats.max_opt()? as f64),
        )),
        Statistics::Float(stats) => Some((
            StatValue::Number(*stats.min_opt()? as f64),
            StatValue::Number(*stats.max_opt()? as f64),
        )),
        Statistics::Double(stats) => Some((
            StatValue::Number(*stats.min_opt()?),
            StatValue::Number(*stats.max_opt()?),
        )),
        Statistics::ByteArray(stats) => Some((
            StatValue::Text(String::from_utf8_lossy(stats.min_opt()?.data()).to_string()),
            StatValue::Text(String::from_utf8_lossy(stats.max_opt()?.data()).to_string()),
        )),
        Statistics::FixedLenByteArray(stats) => Some((
            StatValue::Text(format!("{:?}", stats.min_opt()?)),
            StatValue::Text(format!("{:?}", stats.max_opt()?)),
        )),
        Statistics::Int96(_) => None,
    }
}

fn min_stat_value(left: StatValue, right: StatValue) -> StatValue {
    match (left, right) {
        (StatValue::Number(left), StatValue::Number(right)) => StatValue::Number(left.min(right)),
        (StatValue::Text(left), StatValue::Text(right)) => StatValue::Text(left.min(right)),
        (left, _) => left,
    }
}

fn max_stat_value(left: StatValue, right: StatValue) -> StatValue {
    match (left, right) {
        (StatValue::Number(left), StatValue::Number(right)) => StatValue::Number(left.max(right)),
        (StatValue::Text(left), StatValue::Text(right)) => StatValue::Text(left.max(right)),
        (left, _) => left,
    }
}

fn report_from_files(
    command: &'static str,
    target: &str,
    artifact_type: &'static str,
    files: Vec<InspectedFile>,
    complete: bool,
    scan_truncated: bool,
    cli: &Cli,
    warnings: Vec<String>,
    errors: Vec<ErrorInfo>,
) -> Report {
    let rows = files.iter().map(|file| file.summary.rows).sum();
    let row_groups = files.iter().map(|file| file.summary.row_groups).sum();
    let mut schema_variants = files
        .iter()
        .map(|file| file.summary.schema_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    if schema_variants.is_empty() {
        schema_variants.insert("empty".to_string());
    }
    let canonical_schema = files
        .first()
        .map(|file| file.schema.clone())
        .unwrap_or_default();
    let columns = aggregate_columns(&files, cli.max_columns);
    let row_group_summary = summarize_row_groups(&files);
    let numeric_ranges = files
        .iter()
        .flat_map(|file| file.numeric_ranges.clone())
        .collect::<Vec<_>>();
    let mut file_summaries = files
        .iter()
        .map(|file| file.summary.clone())
        .collect::<Vec<_>>();
    file_summaries.sort_by(|left, right| left.uri.cmp(&right.uri));
    let mut findings = if command == "check" {
        let mut seeds = files
            .iter()
            .flat_map(|file| {
                file.findings
                    .iter()
                    .filter(|finding| !is_column_stat_dataset_finding(finding.finding_type))
                    .cloned()
            })
            .collect::<Vec<_>>();
        seeds.extend(dataset_column_stat_findings(&files, cli));
        seeds
    } else {
        files
            .iter()
            .flat_map(|file| file.findings.clone())
            .collect::<Vec<_>>()
    };
    findings.sort_by(seed_sort);
    let findings = assign_finding_ids(findings);
    let mut report = Report {
        schema_version: REPORT_SCHEMA_VERSION,
        tool: Tool {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        },
        command,
        status: Status::Ok,
        artifact: Artifact {
            artifact_type,
            uri: target.to_string(),
            rows,
            columns: canonical_schema.len(),
            row_groups,
            size_bytes: (command == "inspect")
                .then(|| file_summaries.first().and_then(|file| file.size_bytes))
                .flatten(),
            files_matched: (command == "check").then_some(file_summaries.len()),
            files_scanned: (command == "check").then_some(file_summaries.len()),
        },
        scan: Scan {
            mode: "metadata_only",
            data_pages_read: false,
            complete,
            scan_truncated,
        },
        summary: Summary {
            message: String::new(),
            rows,
            columns: canonical_schema.len(),
            files: file_summaries.len(),
            findings: findings.len(),
        },
        schema: SchemaSummary {
            column_count: canonical_schema.len(),
            variants: schema_variants.len(),
            canonical: canonical_schema,
        },
        columns,
        row_groups: row_group_summary,
        files: file_summaries,
        findings,
        preview: None,
        limits: limits(cli),
        warnings,
        errors,
    };
    finalize_report(&mut report, cli);
    if command == "check" {
        detect_minmax_outliers(&mut report, &numeric_ranges, cli);
        finalize_report(&mut report, cli);
    }
    report
}

fn add_dataset_findings(report: &mut Report, cli: &Cli) {
    detect_unreadable_files(report, cli);
    detect_schema_drift(report, cli);
    detect_row_count_skew(report, cli);
    detect_scan_truncated(report);
    rank_suspicious_files(report);
}

#[derive(Default)]
struct DatasetColumnStatAggregate {
    row_groups_present: usize,
    row_groups_missing_statistics: usize,
    all_null_row_groups: usize,
    null_count: i64,
    rows_with_known_nulls: i64,
    missing_stat_files: BTreeSet<String>,
    all_null_files: BTreeSet<String>,
    null_spike_files: BTreeSet<String>,
}

fn dataset_column_stat_findings(files: &[InspectedFile], cli: &Cli) -> Vec<FindingSeed> {
    let mut by_column: BTreeMap<String, DatasetColumnStatAggregate> = BTreeMap::new();
    for file in files {
        for column in &file.columns {
            let aggregate = by_column.entry(column.name.clone()).or_default();
            aggregate.row_groups_present += column.row_groups_present;
            aggregate.row_groups_missing_statistics += column.row_groups_missing_statistics;
            aggregate.all_null_row_groups += column.all_null_row_groups;
            if column.row_groups_missing_statistics > 0 {
                aggregate
                    .missing_stat_files
                    .insert(file.summary.uri.clone());
            }
            if column.all_null_row_groups > 0 {
                aggregate.all_null_files.insert(file.summary.uri.clone());
            }
            if let Some(null_count) = column.null_count {
                aggregate.null_count += null_count;
                aggregate.rows_with_known_nulls += file.summary.rows;
                if file.summary.rows > 0 {
                    let ratio = null_count as f64 / file.summary.rows as f64;
                    if ratio >= cli.null_spike_ratio {
                        aggregate.null_spike_files.insert(file.summary.uri.clone());
                    }
                }
            }
        }
    }

    let mut findings = Vec::new();
    for (column, aggregate) in by_column {
        if aggregate.row_groups_missing_statistics > 0 {
            let affected_files = aggregate.missing_stat_files.len();
            findings.push(FindingSeed {
                finding_type: "missing_statistics",
                severity: if aggregate.row_groups_missing_statistics == aggregate.row_groups_present
                {
                    Severity::Warning
                } else {
                    Severity::Info
                },
                confidence: "high",
                message: format!(
                    "{column} is missing statistics in {} row groups across {affected_files} files",
                    aggregate.row_groups_missing_statistics
                ),
                location: FindingLocation {
                    file: aggregate.missing_stat_files.iter().next().cloned(),
                    row_group: None,
                    column: Some(column.clone()),
                },
                evidence: btree_json([
                    (
                        "row_groups_missing_statistics",
                        aggregate.row_groups_missing_statistics,
                    ),
                    ("row_groups_present", aggregate.row_groups_present),
                    ("affected_files", affected_files),
                ]),
                suggested_action:
                    "Use files with complete statistics for stronger metadata-only diagnosis."
                        .to_string(),
                example_files: aggregate
                    .missing_stat_files
                    .iter()
                    .take(cli.max_example_files)
                    .cloned()
                    .collect(),
            });
        }

        if aggregate.all_null_row_groups > 0 {
            let affected_files = aggregate.all_null_files.len();
            findings.push(FindingSeed {
                finding_type: "all_null_row_group",
                severity: Severity::Warning,
                confidence: "high",
                message: format!(
                    "{column} is all-null in {} row groups across {affected_files} files",
                    aggregate.all_null_row_groups
                ),
                location: FindingLocation {
                    file: aggregate.all_null_files.iter().next().cloned(),
                    row_group: None,
                    column: Some(column.clone()),
                },
                evidence: btree_json([
                    ("all_null_row_groups", aggregate.all_null_row_groups),
                    ("affected_files", affected_files),
                ]),
                suggested_action: "Inspect the producer job for null handling regressions."
                    .to_string(),
                example_files: aggregate
                    .all_null_files
                    .iter()
                    .take(cli.max_example_files)
                    .cloned()
                    .collect(),
            });
        }

        if aggregate.rows_with_known_nulls > 0 {
            let ratio = aggregate.null_count as f64 / aggregate.rows_with_known_nulls as f64;
            if ratio >= cli.null_spike_ratio {
                findings.push(FindingSeed {
                    finding_type: "null_spike",
                    severity: Severity::Warning,
                    confidence: "medium",
                    message: format!("{column} is {:.1}% null across the dataset", ratio * 100.0),
                    location: FindingLocation {
                        file: aggregate.null_spike_files.iter().next().cloned(),
                        row_group: None,
                        column: Some(column),
                    },
                    evidence: btree_json([
                        ("null_count", serde_json::json!(aggregate.null_count)),
                        ("rows", serde_json::json!(aggregate.rows_with_known_nulls)),
                        (
                            "null_ratio_percent",
                            serde_json::json!((ratio * 1000.0).round() / 10.0),
                        ),
                        ("threshold_ratio", serde_json::json!(cli.null_spike_ratio)),
                        (
                            "affected_files",
                            serde_json::json!(aggregate.null_spike_files.len()),
                        ),
                    ]),
                    suggested_action:
                        "Compare this dataset against a known healthy output from the same writer."
                            .to_string(),
                    example_files: aggregate
                        .null_spike_files
                        .iter()
                        .take(cli.max_example_files)
                        .cloned()
                        .collect(),
                });
            }
        }
    }
    findings
}

fn is_column_stat_dataset_finding(finding_type: &str) -> bool {
    matches!(
        finding_type,
        "missing_statistics" | "all_null_row_group" | "null_spike"
    )
}

fn detect_minmax_outliers(report: &mut Report, ranges: &[NumericRange], cli: &Cli) {
    let mut by_column: BTreeMap<String, Vec<&NumericRange>> = BTreeMap::new();
    for range in ranges {
        if range.min.is_finite() && range.max.is_finite() {
            by_column
                .entry(range.column.clone())
                .or_default()
                .push(range);
        }
    }

    for (column, mut column_ranges) in by_column {
        if column_ranges.len() < 3 {
            continue;
        }
        column_ranges.sort_by(|left, right| {
            left.max
                .partial_cmp(&right.max)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.file.cmp(&right.file))
        });
        let median_max = column_ranges[column_ranges.len() / 2].max;
        if median_max <= 0.0 {
            continue;
        }
        for range in column_ranges {
            if range.max > median_max * cli.minmax_outlier_factor {
                let ratio = range.max / median_max;
                report.findings.push(make_finding(
                    "minmax_outlier",
                    Severity::Warning,
                    "medium",
                    format!(
                        "{} max in {} is {:.1}x the median file max",
                        column, range.file, ratio
                    ),
                    FindingLocation {
                        file: Some(range.file.clone()),
                        row_group: None,
                        column: Some(column.clone()),
                    },
                    btree_json([
                        ("file_max", serde_json::json!(range.max)),
                        ("median_file_max", serde_json::json!(median_max)),
                        ("ratio", serde_json::json!((ratio * 10.0).round() / 10.0)),
                        ("threshold_factor", serde_json::json!(cli.minmax_outlier_factor)),
                    ]),
                    "Check whether this file contains records outside the expected partition or time range."
                        .to_string(),
                    vec![range.file.clone()],
                    report.findings.len() + 1,
                ));
            }
        }
    }
}

fn detect_unreadable_files(report: &mut Report, cli: &Cli) {
    let errors = report
        .errors
        .iter()
        .filter(|error| is_unreadable_dataset_error(error))
        .collect::<Vec<_>>();
    if errors.is_empty() {
        return;
    }
    let examples = error_example_files(errors.iter().copied(), cli.max_example_files);
    report.findings.push(make_finding(
        "unreadable_file",
        Severity::Error,
        "high",
        format!("{} Parquet files could not be read", errors.len()),
        FindingLocation::default(),
        btree_json([("unreadable_files", errors.len())]),
        "Remove or rewrite unreadable Parquet files before trusting this dataset.".to_string(),
        examples,
        report.findings.len() + 1,
    ));

    let corrupt_errors = errors
        .iter()
        .filter(|error| error.error_type == "corrupt_metadata")
        .copied()
        .collect::<Vec<_>>();
    if !corrupt_errors.is_empty() {
        let examples = error_example_files(corrupt_errors.iter().copied(), cli.max_example_files);
        report.findings.push(make_finding(
            "corrupt_metadata",
            Severity::Error,
            "high",
            format!(
                "{} Parquet files have corrupt or invalid metadata",
                corrupt_errors.len()
            ),
            FindingLocation::default(),
            btree_json([("corrupt_files", corrupt_errors.len())]),
            "Rewrite the affected files so their Parquet footer metadata is valid.".to_string(),
            examples,
            report.findings.len() + 1,
        ));
    }
}

fn error_example_files<'a>(
    errors: impl IntoIterator<Item = &'a ErrorInfo>,
    max_examples: usize,
) -> Vec<String> {
    errors
        .into_iter()
        .filter_map(|error| {
            error
                .message
                .split_once(": ")
                .map(|(uri, _)| uri.to_string())
        })
        .filter(|uri| !uri.is_empty())
        .take(max_examples)
        .collect()
}

fn detect_schema_drift(report: &mut Report, cli: &Cli) {
    if report.files.len() <= 1 || report.schema.variants <= 1 {
        return;
    }
    let mut by_fingerprint: BTreeMap<String, Vec<&FileSummary>> = BTreeMap::new();
    for file in &report.files {
        by_fingerprint
            .entry(file.schema_fingerprint.clone())
            .or_default()
            .push(file);
    }
    let mut variants = by_fingerprint
        .iter()
        .map(|(fingerprint, files)| (fingerprint.clone(), files.len(), files.clone()))
        .collect::<Vec<_>>();
    variants.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let baseline = variants.first().cloned();
    let Some((baseline_fingerprint, baseline_count, baseline_files)) = baseline else {
        return;
    };
    let Some(baseline_file) = baseline_files.first() else {
        return;
    };
    let baseline_schema = schema_map(&baseline_file.schema);

    for (fingerprint, count, files) in variants.into_iter().skip(1) {
        let examples = files
            .iter()
            .map(|file| file.uri.clone())
            .take(cli.max_example_files)
            .collect::<Vec<_>>();
        report.findings.push(make_finding(
            "schema_drift",
            Severity::Error,
            "high",
            format!(
                "schema variant {fingerprint} appears in {count} files; baseline {baseline_fingerprint} appears in {baseline_count} files"
            ),
            FindingLocation::default(),
            btree_json([
                ("variant_files", count),
                ("baseline_files", baseline_count),
                ("schema_variants", report.schema.variants),
            ]),
            "Compare writer schemas for the affected files or partition.".to_string(),
            examples,
            report.findings.len() + 1,
        ));
    }

    let mut missing_columns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut extra_columns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut type_changes: BTreeMap<String, (SchemaField, SchemaField, Vec<String>)> =
        BTreeMap::new();

    for file in &report.files {
        if file.schema_fingerprint == baseline_fingerprint {
            continue;
        }
        let file_schema = schema_map(&file.schema);
        for (name, expected) in &baseline_schema {
            match file_schema.get(name) {
                None => missing_columns
                    .entry(name.clone())
                    .or_default()
                    .push(file.uri.clone()),
                Some(actual) if field_signature(actual) != field_signature(expected) => {
                    let key = format!(
                        "{}:{}->{}",
                        name,
                        field_signature(expected),
                        field_signature(actual)
                    );
                    type_changes
                        .entry(key)
                        .or_insert_with(|| (expected.clone(), actual.clone(), Vec::new()))
                        .2
                        .push(file.uri.clone());
                }
                _ => {}
            }
        }
        for (name, actual) in &file_schema {
            if !baseline_schema.contains_key(name) {
                extra_columns
                    .entry(format!("{}:{}", name, field_signature(actual)))
                    .or_default()
                    .push(file.uri.clone());
            }
        }
    }

    for (column, files) in missing_columns {
        let expected = baseline_schema
            .get(&column)
            .map(field_signature)
            .unwrap_or_else(|| "unknown".to_string());
        let examples = files
            .iter()
            .take(cli.max_example_files)
            .cloned()
            .collect::<Vec<_>>();
        report.findings.push(make_finding(
            "missing_column",
            Severity::Error,
            "high",
            format!("column {column} is missing in {} files", files.len()),
            FindingLocation {
                file: examples.first().cloned(),
                row_group: None,
                column: Some(column.clone()),
            },
            btree_json([
                ("expected", serde_json::json!(expected)),
                ("affected_files", serde_json::json!(files.len())),
            ]),
            "Check whether the writer dropped a field or used an incompatible schema.".to_string(),
            examples,
            report.findings.len() + 1,
        ));
    }

    for (column_with_type, files) in extra_columns {
        let (column, actual) = column_with_type
            .split_once(':')
            .map(|(column, actual)| (column.to_string(), actual.to_string()))
            .unwrap_or_else(|| (column_with_type.clone(), "unknown".to_string()));
        let examples = files
            .iter()
            .take(cli.max_example_files)
            .cloned()
            .collect::<Vec<_>>();
        report.findings.push(make_finding(
            "extra_column",
            Severity::Warning,
            "high",
            format!(
                "column {column} appears only in {} drifted files",
                files.len()
            ),
            FindingLocation {
                file: examples.first().cloned(),
                row_group: None,
                column: Some(column),
            },
            btree_json([
                ("actual", serde_json::json!(actual)),
                ("affected_files", serde_json::json!(files.len())),
            ]),
            "Check whether a new writer version introduced an unintended field.".to_string(),
            examples,
            report.findings.len() + 1,
        ));
    }

    for (_, (expected, actual, files)) in type_changes {
        let examples = files
            .iter()
            .take(cli.max_example_files)
            .cloned()
            .collect::<Vec<_>>();
        report.findings.push(make_finding(
            "type_change",
            Severity::Error,
            "high",
            format!(
                "column {} changed from {} to {} in {} files",
                expected.name,
                field_signature(&expected),
                field_signature(&actual),
                files.len()
            ),
            FindingLocation {
                file: examples.first().cloned(),
                row_group: None,
                column: Some(expected.name.clone()),
            },
            btree_json([
                ("expected", serde_json::json!(field_signature(&expected))),
                ("actual", serde_json::json!(field_signature(&actual))),
                ("affected_files", serde_json::json!(files.len())),
            ]),
            "Compare writer schema serialization for this column across affected files."
                .to_string(),
            examples,
            report.findings.len() + 1,
        ));
    }
}

fn schema_map(schema: &[SchemaField]) -> BTreeMap<String, SchemaField> {
    schema
        .iter()
        .map(|field| (field.name.clone(), field.clone()))
        .collect()
}

fn field_signature(field: &SchemaField) -> String {
    format!(
        "{}:{}:def{}",
        field.physical_type, field.logical_type, field.max_definition_level
    )
}

fn detect_row_count_skew(report: &mut Report, cli: &Cli) {
    if report.files.len() < 3 {
        return;
    }
    let mut row_counts = report
        .files
        .iter()
        .map(|file| file.rows)
        .collect::<Vec<_>>();
    row_counts.sort_unstable();
    let median = median_i64(&row_counts).unwrap_or(0);
    if median <= 0 {
        return;
    }
    let mut skew_findings = Vec::new();
    for file in &report.files {
        let ratio = file.rows as f64 / median as f64;
        if ratio > cli.row_count_skew_factor {
            skew_findings.push(make_finding(
                "row_count_skew",
                Severity::Warning,
                "medium",
                format!("{} has {:.1}x the median row count", file.uri, ratio),
                FindingLocation {
                    file: Some(file.uri.clone()),
                    row_group: None,
                    column: None,
                },
                btree_json([
                    ("file_rows", serde_json::json!(file.rows)),
                    ("median_rows", serde_json::json!(median)),
                    ("ratio", serde_json::json!((ratio * 10.0).round() / 10.0)),
                    (
                        "threshold_factor",
                        serde_json::json!(cli.row_count_skew_factor),
                    ),
                ]),
                "Check whether this file combines multiple expected output shards.".to_string(),
                vec![file.uri.clone()],
                report.findings.len() + skew_findings.len() + 1,
            ));
        } else if file.rows > 0 && ratio < 1.0 / cli.row_count_skew_factor {
            skew_findings.push(make_finding(
                "row_count_skew",
                Severity::Warning,
                "medium",
                format!(
                    "{} has {:.1}% of the median row count",
                    file.uri,
                    ratio * 100.0
                ),
                FindingLocation {
                    file: Some(file.uri.clone()),
                    row_group: None,
                    column: None,
                },
                btree_json([
                    ("file_rows", serde_json::json!(file.rows)),
                    ("median_rows", serde_json::json!(median)),
                    (
                        "ratio",
                        serde_json::json!((ratio * 1000.0).round() / 1000.0),
                    ),
                    (
                        "threshold_factor",
                        serde_json::json!(cli.row_count_skew_factor),
                    ),
                ]),
                "Check whether this file is an incomplete shard.".to_string(),
                vec![file.uri.clone()],
                report.findings.len() + skew_findings.len() + 1,
            ));
        }
    }
    report.findings.extend(skew_findings);
}

fn detect_scan_truncated(report: &mut Report) {
    if !report.scan.scan_truncated {
        return;
    }
    report.findings.push(make_finding(
        "scan_truncated",
        Severity::Warning,
        "high",
        "scan was truncated by configured limits".to_string(),
        FindingLocation::default(),
        scan_truncated_evidence(&report.limits),
        "Increase configured limits only after confirming the scan scope is expected.".to_string(),
        Vec::new(),
        report.findings.len() + 1,
    ));
}

fn scan_truncated_evidence(limits: &Limits) -> BTreeMap<String, serde_json::Value> {
    btree_json([
        ("max_files", serde_json::json!(limits.max_files)),
        ("timeout", serde_json::json!(limits.timeout)),
        ("max_requests", serde_json::json!(limits.max_requests)),
        ("max_bytes", serde_json::json!(limits.max_bytes)),
    ])
}

fn rank_suspicious_files(report: &mut Report) {
    let mut reasons_by_file: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in &report.findings {
        for file in &finding.example_files {
            reasons_by_file
                .entry(file.clone())
                .or_default()
                .insert(finding.finding_type.clone());
        }
        if let Some(file) = &finding.location.file {
            reasons_by_file
                .entry(file.clone())
                .or_default()
                .insert(finding.finding_type.clone());
        }
    }
    for file in &mut report.files {
        if let Some(reasons) = reasons_by_file.remove(&file.uri) {
            file.suspicious_reasons = reasons.into_iter().collect();
        }
    }
    report.files.sort_by(|left, right| {
        right
            .suspicious_reasons
            .len()
            .cmp(&left.suspicious_reasons.len())
            .then_with(|| right.rows.cmp(&left.rows))
            .then_with(|| left.uri.cmp(&right.uri))
    });
}

fn finalize_report(report: &mut Report, _cli: &Cli) {
    report.findings.sort_by(finding_sort);
    for (index, finding) in report.findings.iter_mut().enumerate() {
        finding.id = format!("finding_{:03}", index + 1);
    }
    report.summary.findings = report.findings.len();
    report.status = if report
        .errors
        .iter()
        .any(|error| error.error_type == "s3_permission_error")
    {
        Status::Error
    } else {
        Status::from_findings(&report.findings)
    };
    report.summary.message = summary_message(report);
}

fn summary_message(report: &Report) -> String {
    if !report.scan.complete && !report.errors.is_empty() {
        return format!(
            "{} metadata inspection did not complete: {}",
            title_case(artifact_label(report)),
            report
                .errors
                .first()
                .map(|error| error.message.as_str())
                .unwrap_or("unknown error")
        );
    }
    match (report.command, report.status) {
        ("inspect", Status::Ok) => {
            "File is readable. No schema or metadata anomalies detected.".to_string()
        }
        ("inspect", _) => format!(
            "File is readable, with {} metadata findings.",
            report.findings.len()
        ),
        ("check", Status::Ok) => {
            "Dataset is readable. No schema or metadata anomalies detected.".to_string()
        }
        ("check", _) => format!(
            "Dataset is readable, with {} metadata findings across {} scanned files.",
            report.findings.len(),
            report.artifact.files_scanned.unwrap_or(report.files.len())
        ),
        _ => "Command completed.".to_string(),
    }
}

fn emit_report(report: &Report, cli: &Cli) -> Result<()> {
    let report = report_for_details(report, cli);
    match emit_mode(cli) {
        EmitMode::MarkdownAgent => {
            println!("{}", render_markdown_agent(&report));
        }
        EmitMode::JsonAgent => {
            println!("{}", serde_json::to_string_pretty(&agent_packet(&report))?);
        }
        EmitMode::JsonReport => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        EmitMode::MarkdownReport => {
            println!("{}", render_markdown_report(&report));
        }
        EmitMode::TextReport => {
            if !cli.quiet {
                println!("{}", render_text(&report, text_color_enabled(cli)));
            }
        }
    }
    Ok(())
}

fn emit_mode(cli: &Cli) -> EmitMode {
    if cli.agent {
        if cli.format == OutputFormat::Markdown && !cli.json {
            EmitMode::MarkdownAgent
        } else {
            EmitMode::JsonAgent
        }
    } else if cli.json || cli.format == OutputFormat::Json {
        EmitMode::JsonReport
    } else if cli.format == OutputFormat::Markdown {
        EmitMode::MarkdownReport
    } else {
        EmitMode::TextReport
    }
}

fn text_color_enabled(cli: &Cli) -> bool {
    !cli.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}

fn report_for_details(report: &Report, cli: &Cli) -> Report {
    let mut report = report.clone();
    match cli.details {
        Details::Full => {}
        Details::Summary => {
            if report.command == "check" {
                let mut files = report
                    .files
                    .iter()
                    .filter(|file| !file.suspicious_reasons.is_empty())
                    .cloned()
                    .collect::<Vec<_>>();
                if files.is_empty() {
                    files = report
                        .files
                        .iter()
                        .take(cli.max_example_files)
                        .cloned()
                        .collect();
                }
                report.files = files;
            }
        }
        Details::None => {
            report.schema.canonical.clear();
            report.columns.clear();
            report.files.clear();
            report.preview = None;
            report.row_groups.min_rows = None;
            report.row_groups.median_rows = None;
            report.row_groups.max_rows = None;
        }
    }
    bound_report_columns(&mut report, cli.max_columns);
    bound_report_findings(&mut report, cli.max_findings);
    report
}

fn bound_report_columns(report: &mut Report, max_columns: usize) {
    let canonical_len = report.schema.canonical.len();
    if canonical_len > max_columns {
        report.schema.canonical.truncate(max_columns);
        report.warnings.push(format!(
            "schema output truncated: showing {max_columns} of {canonical_len} columns due to --max-columns"
        ));
    }
    let columns_len = report.columns.len();
    if columns_len > max_columns {
        report.columns.truncate(max_columns);
        report.warnings.push(format!(
            "column summary output truncated: showing {max_columns} of {columns_len} columns due to --max-columns"
        ));
    }
}

fn bound_report_findings(report: &mut Report, max_findings: usize) {
    let findings_len = report.findings.len();
    if findings_len > max_findings {
        report.findings.truncate(max_findings);
        report.warnings.push(format!(
            "findings output truncated: showing {max_findings} of {findings_len} findings due to --max-findings"
        ));
    }
}

fn agent_packet(report: &Report) -> AgentPacket {
    AgentPacket {
        schema_version: AGENT_SCHEMA_VERSION,
        command: report.command,
        status: report.status,
        artifact: report.artifact.clone(),
        scan: report.scan.clone(),
        summary: report.summary.message.clone(),
        top_findings: report.findings.iter().take(10).cloned().collect(),
        recommended_next_actions: recommended_next_actions(report),
        limits: report.limits.clone(),
        tool: Tool {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        },
    }
}

fn recommended_next_actions(report: &Report) -> Vec<String> {
    let mut actions = BTreeSet::new();
    for finding in report.findings.iter().take(5) {
        actions.insert(finding.suggested_action.clone());
    }
    if report.command == "check" && report.status != Status::Ok {
        actions.insert("Compare against a previous healthy partition or dataset.".to_string());
    }
    if report.command == "inspect" {
        actions.insert(
            "If this file is generated, compare it against the expected schema or previous output."
                .to_string(),
        );
    }
    if actions.is_empty() {
        actions.insert("No immediate action required from metadata-only inspection.".to_string());
    }
    actions.into_iter().collect()
}

fn render_text(report: &Report, color: bool) -> String {
    let mut out = String::new();
    if report.command == "inspect" {
        out.push_str(&format!("File: {}\n", report.artifact.uri));
    } else {
        out.push_str(&format!("Dataset: {}\n", report.artifact.uri));
        out.push_str(&format!(
            "Files: {} matched, {} scanned\n",
            report.artifact.files_matched.unwrap_or(report.files.len()),
            report.artifact.files_scanned.unwrap_or(report.files.len())
        ));
    }
    out.push_str(&format!("Rows: {}\n", report.artifact.rows));
    out.push_str(&format!("Columns: {}\n", report.artifact.columns));
    out.push_str(&format!("Row groups: {}\n", report.artifact.row_groups));
    if let Some(compression) =
        distinct_column_metadata_values(&report.columns, |column| &column.compression)
    {
        out.push_str(&format!("Compression: {compression}\n"));
    }
    if let Some(encodings) =
        distinct_column_metadata_values(&report.columns, |column| &column.encodings)
    {
        out.push_str(&format!("Encodings: {encodings}\n"));
    }
    if let Some(size) = report.artifact.size_bytes {
        out.push_str(&format!("Size: {} bytes\n", size));
    }
    if report.command == "inspect" {
        if let Some(created_by) = report
            .files
            .first()
            .and_then(|file| file.created_by.as_ref())
        {
            out.push_str(&format!("Created by: {created_by}\n"));
        }
    }
    out.push_str(&format!("Mode: {}\n", report.scan.mode.replace('_', "-")));
    out.push_str(&format!(
        "Status: {}\n",
        format_status(report.status, color)
    ));

    if !report.warnings.is_empty() {
        out.push_str("\nWarnings\n");
        for warning in &report.warnings {
            out.push_str(&format!("  {warning}\n"));
        }
    }

    if !report.schema.canonical.is_empty() {
        out.push_str("\nSchema\n");
        let columns_by_name = report
            .columns
            .iter()
            .map(|column| (column.name.as_str(), column))
            .collect::<BTreeMap<_, _>>();
        for field in report.schema.canonical.iter().take(20) {
            let mut stats = Vec::new();
            if let Some(column) = columns_by_name.get(field.name.as_str()) {
                if let Some(min_value) = &column.min_value {
                    stats.push(format!("min={min_value}"));
                }
                if let Some(max_value) = &column.max_value {
                    stats.push(format!("max={max_value}"));
                }
                if let Some(null_count) = column.null_count {
                    stats.push(format!("nulls={null_count}"));
                }
            }
            out.push_str(&format!(
                "  {:24} {:12} {} {}\n",
                field.name,
                field.physical_type,
                field.logical_type,
                stats.join(" ")
            ));
        }
        if report.schema.canonical.len() > 20 {
            out.push_str(&format!(
                "  ... {} more columns\n",
                report.schema.canonical.len() - 20
            ));
        }
    }

    if report.command == "inspect" {
        if let Some(file) = report.files.first() {
            if !file.key_value_metadata.is_empty() {
                out.push_str("\nKey-value metadata\n");
                for (key, value) in &file.key_value_metadata {
                    out.push_str(&format!(
                        "  {key}: {}\n",
                        format_human_metadata_value(value)
                    ));
                }
            }
        }
    }

    if let Some(preview) = &report.preview {
        out.push_str("\nPreview\n");
        for row in &preview.rows {
            out.push_str(&format!("  {row}\n"));
        }
        if preview.returned_rows < preview.requested_rows {
            out.push_str(&format!(
                "  ... returned {} of {} requested rows\n",
                preview.returned_rows, preview.requested_rows
            ));
        }
    }

    if !report.findings.is_empty() {
        out.push_str("\nFindings\n");
        for finding in &report.findings {
            out.push_str(&format!(
                "  {:7} {:20} {}\n",
                format_severity(finding.severity, color),
                finding.finding_type,
                finding.message
            ));
        }
    }

    let suspicious = suspicious_file_rows(report, 5);
    if !suspicious.is_empty() {
        out.push_str("\nTop suspicious files\n");
        for (uri, reasons) in suspicious {
            out.push_str(&format!("  {}  {}\n", uri, reasons.join(", ")));
        }
    }

    if !report.errors.is_empty() {
        out.push_str("\nErrors\n");
        for error in &report.errors {
            out.push_str(&format!("  {}  {}\n", error.error_type, error.message));
        }
    }

    let actions = recommended_next_actions(report);
    if !actions.is_empty() {
        out.push_str("\nNext actions\n");
        for action in actions {
            out.push_str(&format!("  - {action}\n"));
        }
    }
    out
}

fn format_status(status: Status, color: bool) -> String {
    colorize(status.as_str(), status_color_code(status), color)
}

fn format_severity(severity: Severity, color: bool) -> String {
    colorize(severity.as_str(), severity_color_code(severity), color)
}

fn colorize(value: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_string()
    }
}

fn status_color_code(status: Status) -> &'static str {
    match status {
        Status::Ok => "32",
        Status::Info => "34",
        Status::Warning => "33",
        Status::Error => "31",
    }
}

fn severity_color_code(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "34",
        Severity::Warning => "33",
        Severity::Error => "31",
    }
}

fn format_human_metadata_value(value: &str) -> String {
    const MAX_CHARS: usize = 120;
    let char_count = value.chars().count();
    if char_count <= MAX_CHARS {
        value.to_string()
    } else {
        let prefix = value.chars().take(MAX_CHARS).collect::<String>();
        format!("{prefix}... ({char_count} chars)")
    }
}

fn distinct_column_metadata_values<F>(
    columns: &[ColumnSummary],
    mut values_for: F,
) -> Option<String>
where
    F: FnMut(&ColumnSummary) -> &[String],
{
    let values = columns
        .iter()
        .flat_map(|column| values_for(column).iter().cloned())
        .collect::<BTreeSet<_>>();
    if values.is_empty() {
        None
    } else {
        Some(values.into_iter().collect::<Vec<_>>().join(", "))
    }
}

fn suspicious_file_rows(report: &Report, limit: usize) -> Vec<(String, Vec<String>)> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for file in report
        .files
        .iter()
        .filter(|file| !file.suspicious_reasons.is_empty())
    {
        if rows.len() >= limit {
            return rows;
        }
        seen.insert(file.uri.clone());
        rows.push((file.uri.clone(), file.suspicious_reasons.clone()));
    }

    let mut example_reasons: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in &report.findings {
        for file in &finding.example_files {
            if !seen.contains(file) {
                example_reasons
                    .entry(file.clone())
                    .or_default()
                    .insert(finding.finding_type.clone());
            }
        }
    }
    for (uri, reasons) in example_reasons {
        if rows.len() >= limit {
            break;
        }
        rows.push((uri, reasons.into_iter().collect()));
    }

    rows
}

fn render_markdown_report(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("## Sounder Report\n\n");
    out.push_str(&format!(
        "**Status:** {}\n",
        title_case(report.status.as_str())
    ));
    out.push_str(&format!(
        "**{}:** `{}`\n",
        artifact_label(report),
        report.artifact.uri
    ));
    if report.command == "check" {
        out.push_str(&format!(
            "**Files scanned:** {}\n",
            report.artifact.files_scanned.unwrap_or(report.files.len())
        ));
    }
    out.push_str(&format!("**Rows:** {}\n", report.artifact.rows));
    render_markdown_scan_scope(report, &mut out);
    render_markdown_findings_and_actions(report, &mut out);
    out
}

fn render_markdown_agent(report: &Report) -> String {
    let mut out = String::new();
    out.push_str("## Sounder Evidence Packet\n\n");
    out.push_str(&format!(
        "**Status:** {}\n",
        title_case(report.status.as_str())
    ));
    out.push_str(&format!(
        "**{}:** `{}`\n",
        artifact_label(report),
        report.artifact.uri
    ));
    if report.command == "check" {
        out.push_str(&format!(
            "**Files scanned:** {}\n",
            report.artifact.files_scanned.unwrap_or(report.files.len())
        ));
    }
    out.push_str(&format!("**Rows:** {}\n", report.artifact.rows));
    render_markdown_scan_scope(report, &mut out);
    render_markdown_findings_and_actions(report, &mut out);
    out
}

fn render_markdown_scan_scope(report: &Report, out: &mut String) {
    let completeness = if report.scan.complete {
        "complete"
    } else {
        "truncated"
    };
    let data_pages = if report.scan.data_pages_read {
        "yes"
    } else {
        "no"
    };
    out.push_str(&format!(
        "**Scan:** {} ({}, data pages read: {})\n",
        report.scan.mode, completeness, data_pages
    ));
    if !report.warnings.is_empty() {
        out.push_str("\n### Warnings\n\n");
        for warning in &report.warnings {
            out.push_str(&format!("- {warning}\n"));
        }
    }
}

fn render_markdown_findings_and_actions(report: &Report, out: &mut String) {
    if !report.findings.is_empty() {
        out.push_str("\n### Findings\n\n");
        for (index, finding) in report.findings.iter().enumerate() {
            out.push_str(&format!(
                "{}. **{} - {}**  \n   {}\n\n",
                index + 1,
                title_case(finding.severity.as_str()),
                finding.finding_type,
                finding.message
            ));
        }
    }
    let actions = recommended_next_actions(report);
    if !actions.is_empty() {
        out.push_str("\n### Suggested next actions\n\n");
        for action in actions {
            out.push_str(&format!("- {action}\n"));
        }
    }
}

fn exit_code_for_report(report: &Report, cli: &Cli) -> i32 {
    if report
        .errors
        .iter()
        .any(|error| error.error_type == "invalid_arguments")
    {
        return 2;
    }
    if report
        .errors
        .iter()
        .any(|error| error.error_type == "input_not_found")
    {
        return 3;
    }
    if report
        .errors
        .iter()
        .any(|error| error.error_type == "s3_permission_error")
    {
        return 5;
    }
    if report.scan.scan_truncated {
        return 6;
    }
    if report
        .errors
        .iter()
        .any(|error| error.error_type == "internal_error")
    {
        return 7;
    }
    if report.errors.iter().any(|error| !error.recoverable) {
        return 4;
    }
    let fail_on = cli
        .fail_on
        .as_deref()
        .map(parse_fail_on_set)
        .unwrap_or_default();
    let policy_failed = report.findings.iter().any(|finding| {
        finding.severity >= cli.severity_threshold || fail_on.contains(&finding.finding_type)
    });
    if policy_failed { 1 } else { 0 }
}

async fn inspect_s3_object(target: &str, head: Option<usize>, cli: &Cli) -> Result<Report> {
    let (store, s3_target, warnings) = match s3_store_for_target(target, cli) {
        Ok(result) => result,
        Err(err) => {
            return Ok(s3_failure_report("inspect", target, &err, cli));
        }
    };
    let budget = match S3Budget::new(cli) {
        Ok(budget) => budget,
        Err(err) => {
            return Ok(s3_failure_report("inspect", target, &err, cli));
        }
    };
    let object = S3Object {
        uri: target.to_string(),
        path: ObjectPath::from(s3_target.key.as_str()),
    };
    match read_s3_parquet_file(store.as_ref(), object.clone(), &budget, cli).await {
        Ok(file) => {
            let size_bytes = file.summary.size_bytes;
            let mut report = report_from_files(
                "inspect",
                target,
                "parquet_file",
                vec![file],
                true,
                false,
                cli,
                warnings,
                Vec::new(),
            );
            if let Some(requested_rows) = head {
                report.warnings.push(s3_preview_warning(&object.uri));
                match read_s3_preview_rows(
                    store.as_ref(),
                    &object,
                    size_bytes.unwrap_or_default(),
                    requested_rows,
                    &budget,
                )
                .await
                {
                    Ok(preview) => {
                        report.preview = Some(preview);
                        report.scan.mode = "metadata_with_preview";
                        report.scan.data_pages_read = true;
                    }
                    Err(err) => {
                        return Ok(s3_failure_report("inspect", target, &err, cli));
                    }
                }
                finalize_report(&mut report, cli);
            }
            Ok(report)
        }
        Err(err) => Ok(s3_failure_report("inspect", target, &err, cli)),
    }
}

async fn check_s3_prefix(target: &str, cli: &Cli) -> Result<Report> {
    let (store, s3_target, mut warnings) = match s3_store_for_target(target, cli) {
        Ok(result) => result,
        Err(err) => return Ok(s3_failure_report("check", target, &err, cli)),
    };
    let budget = match S3Budget::new(cli) {
        Ok(budget) => budget,
        Err(err) => return Ok(s3_failure_report("check", target, &err, cli)),
    };
    let (objects, matched_count, scan_truncated) =
        match list_s3_parquet_objects(store.as_ref(), &s3_target, cli, &budget).await {
            Ok(result) => result,
            Err(err) => return Ok(s3_failure_report("check", target, &err, cli)),
        };

    if scan_truncated {
        warnings.push(format!(
            "scan truncated: matched at least {matched_count} objects but --max-files is {}",
            cli.max_files
        ));
    }
    if objects.is_empty() {
        if scan_truncated && matched_count > 0 {
            let mut report = report_from_files(
                "check",
                target,
                "parquet_dataset",
                Vec::new(),
                false,
                true,
                cli,
                warnings,
                Vec::new(),
            );
            report.artifact.files_matched = Some(matched_count);
            report.artifact.files_scanned = Some(0);
            add_dataset_findings(&mut report, cli);
            finalize_report(&mut report, cli);
            return Ok(report);
        }
        return Err(ExitError::new(
            3,
            format!("no matching Parquet objects found under {target}"),
        )
        .into());
    }

    let scanned_count = objects.len();
    let mut inspected = Vec::new();
    let mut errors = Vec::new();
    let concurrency = cli.s3_concurrency.max(1);
    let mut stream = futures::stream::iter(objects.into_iter().map(|object| {
        let store = Arc::clone(&store);
        let budget = Arc::clone(&budget);
        async move {
            let uri = object.uri.clone();
            let result = read_s3_parquet_file(store.as_ref(), object, &budget, cli).await;
            (uri, result)
        }
    }))
    .buffer_unordered(concurrency);

    while let Some((uri, result)) = stream.next().await {
        match result {
            Ok(file) => inspected.push(file),
            Err(err) => {
                if is_exit_code(&err, 6) {
                    return Ok(s3_failure_report("check", target, &err, cli));
                }
                errors.push(ErrorInfo {
                    error_type: classify_parquet_read_error(&err).to_string(),
                    message: redact_sensitive(&format!("{uri}: {err:#}")),
                    recoverable: true,
                    suggested_action: "Check S3 permissions or rewrite the unreadable Parquet object."
                        .to_string(),
                });
            }
        }
    }

    if inspected.is_empty() && !errors.is_empty() {
        let err = anyhow::anyhow!("no readable Parquet objects found under S3 prefix");
        return Ok(s3_failure_report("check", target, &err, cli));
    }

    let mut report = report_from_files(
        "check",
        target,
        "parquet_dataset",
        inspected,
        !scan_truncated,
        scan_truncated,
        cli,
        warnings,
        errors,
    );
    report.artifact.files_matched = Some(matched_count);
    report.artifact.files_scanned = Some(scanned_count);
    add_dataset_findings(&mut report, cli);
    finalize_report(&mut report, cli);
    Ok(report)
}

fn s3_preview_warning(uri: &str) -> String {
    format!("S3 preview requested for {uri}; data pages may be read and object bytes downloaded")
}

fn s3_store_for_target(
    target: &str,
    cli: &Cli,
) -> Result<(Arc<dyn ObjectStore>, S3Target, Vec<String>)> {
    let s3_target = parse_s3_uri(target)?;
    let warnings = Vec::new();
    let mut builder = AmazonS3Builder::from_env().with_bucket_name(&s3_target.bucket);
    let profile_config = cli.profile.as_deref().map(load_aws_profile).transpose()?;
    if let Some(profile_config) = &profile_config {
        if let Some(access_key_id) = &profile_config.access_key_id {
            builder = builder.with_access_key_id(access_key_id);
        }
        if let Some(secret_access_key) = &profile_config.secret_access_key {
            builder = builder.with_secret_access_key(secret_access_key);
        }
        if let Some(session_token) = &profile_config.session_token {
            builder = builder.with_token(session_token);
        }
        if cli.region.is_none() {
            if let Some(region) = &profile_config.region {
                builder = builder.with_region(region);
            }
        }
    }
    if let Some(region) = &cli.region {
        builder = builder.with_region(region);
    }
    if let Some(endpoint_url) = &cli.endpoint_url {
        builder = builder.with_endpoint(endpoint_url);
        if endpoint_url.starts_with("http://") {
            builder = builder.with_allow_http(true);
        }
    }
    if cli.requester_pays {
        builder = builder.with_config(AmazonS3ConfigKey::RequestPayer, "true");
    }
    let store = builder.build()?;
    Ok((Arc::new(store), s3_target, warnings))
}

async fn list_s3_parquet_objects(
    store: &dyn ObjectStore,
    target: &S3Target,
    cli: &Cli,
    budget: &SharedS3Budget,
) -> Result<(Vec<S3Object>, usize, bool)> {
    record_s3_request(budget, "list_objects")?;
    let prefix = ObjectPath::from(target.key.as_str());
    let mut stream = store.list(Some(&prefix));
    let mut objects = Vec::new();
    let mut matched = 0usize;
    let mut truncated = false;

    while let Some(object) = stream.try_next().await? {
        let key = object.location.to_string();
        if !key.to_ascii_lowercase().ends_with(".parquet") {
            continue;
        }
        matched += 1;
        if objects.len() >= cli.max_files {
            truncated = true;
            break;
        }
        objects.push(S3Object {
            uri: format!("s3://{}/{}", target.bucket, key),
            path: object.location,
        });
    }
    objects.sort_by(|left, right| left.uri.cmp(&right.uri));
    Ok((objects, matched, truncated))
}

async fn read_s3_parquet_file(
    store: &dyn ObjectStore,
    object: S3Object,
    budget: &SharedS3Budget,
    cli: &Cli,
) -> Result<InspectedFile> {
    record_s3_request(budget, "head_object")?;
    let meta = store.head(&object.path).await?;
    let metadata = read_s3_footer_metadata(store, &object.path, meta.size, budget).await?;
    Ok(inspect_metadata(
        &metadata,
        &object.uri,
        Some(meta.size),
        cli,
    ))
}

async fn read_s3_preview_rows(
    store: &dyn ObjectStore,
    object: &S3Object,
    size_bytes: u64,
    requested_rows: usize,
    budget: &SharedS3Budget,
) -> Result<Preview> {
    let size_bytes = usize::try_from(size_bytes).map_err(|_| {
        ExitError::new(
            6,
            format!("{} is too large to preview on this platform", object.uri),
        )
    })?;
    record_s3_bytes(budget, size_bytes, "get_object_preview")?;
    record_s3_request(budget, "get_object_preview")?;
    let bytes = store.get(&object.path).await?.bytes().await?;
    preview_rows_from_bytes(bytes, requested_rows)
}

async fn read_s3_footer_metadata(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    size_bytes: u64,
    budget: &SharedS3Budget,
) -> Result<ParquetMetaData> {
    if size_bytes < 8 {
        return Err(ExitError::with_type(
            4,
            "corrupt_metadata",
            "object is too small to contain a Parquet footer",
        )
        .into());
    }
    let mut needed = 8usize;
    loop {
        let start = size_bytes.saturating_sub(needed as u64);
        let requested_bytes = s3_range_len(start, size_bytes)?;
        record_s3_bytes(budget, requested_bytes, "get_object_range")?;
        record_s3_request(budget, "get_object_range")?;
        let bytes = store.get_range(path, start..size_bytes).await?;
        let mut reader = ParquetMetaDataReader::new();
        match reader.try_parse_sized(&bytes, size_bytes) {
            Ok(()) => return Ok(reader.finish()?),
            Err(ParquetError::NeedMoreData(next_needed)) => {
                if next_needed <= needed || next_needed as u64 > size_bytes {
                    return Err(ExitError::with_type(
                        4,
                        "corrupt_metadata",
                        format!(
                            "Parquet footer requested {next_needed} bytes but object size is {size_bytes}"
                        ),
                    )
                    .into());
                }
                needed = next_needed;
            }
            Err(err) => {
                return Err(ExitError::with_type(
                    4,
                    "corrupt_metadata",
                    format!("failed to parse Parquet footer metadata: {err}"),
                )
                .into());
            }
        }
    }
}

fn s3_range_len(start: u64, end: u64) -> Result<usize> {
    let len = end.saturating_sub(start);
    usize::try_from(len).map_err(|_| {
        ExitError::new(
            6,
            format!("S3 range request is too large to account for locally: {len} bytes"),
        )
        .into()
    })
}

fn parse_s3_uri(target: &str) -> Result<S3Target> {
    let rest = target
        .strip_prefix("s3://")
        .ok_or_else(|| ExitError::new(2, format!("not an S3 URI: {target}")))?;
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket.is_empty() {
        return Err(ExitError::new(2, format!("S3 URI bucket is empty: {target}")).into());
    }
    Ok(S3Target {
        bucket: bucket.to_string(),
        key: key.trim_start_matches('/').to_string(),
    })
}

fn load_aws_profile(profile: &str) -> Result<AwsProfileConfig> {
    let credentials_path = aws_config_path("AWS_SHARED_CREDENTIALS_FILE", &[".aws", "credentials"]);
    let config_path = aws_config_path("AWS_CONFIG_FILE", &[".aws", "config"]);
    let mut values = BTreeMap::new();
    let mut config_values = BTreeMap::new();

    if let Some(path) = config_path {
        if let Some(contents) = read_optional_string(&path)? {
            config_values.extend(parse_aws_ini_section(
                &contents,
                &aws_profile_section_names(profile, true),
            ));
            values.extend(config_values.clone());
        }
    }
    if let Some(path) = credentials_path {
        if let Some(contents) = read_optional_string(&path)? {
            values.extend(parse_aws_ini_section(
                &contents,
                &aws_profile_section_names(profile, false),
            ));
        }
    }

    let profile_config = aws_profile_config_from_values(values);
    if profile_config.access_key_id.is_some() && profile_config.secret_access_key.is_some() {
        return Ok(profile_config);
    }

    let mut exported = export_aws_profile_credentials(profile)?;
    if exported.region.is_none() {
        exported.region = config_values.get("region").cloned();
    }
    Ok(exported)
}

fn export_aws_profile_credentials(profile: &str) -> Result<AwsProfileConfig> {
    let output = Command::new("aws")
        .args([
            "configure",
            "export-credentials",
            "--profile",
            profile,
            "--format",
            "env-no-export",
        ])
        .env("AWS_PAGER", "")
        .output()
        .map_err(|err| {
            ExitError::new(
                5,
                format!(
                    "AWS profile {profile} does not contain static credentials and aws configure export-credentials could not be started: {err}"
                ),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ExitError::new(
            5,
            format!(
                "AWS profile {profile} does not contain static credentials and aws configure export-credentials failed. Run aws sso login --profile {profile} if this is an SSO profile. {}",
                stderr.trim()
            ),
        )
        .into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let exported = aws_profile_config_from_export_env(&stdout);
    if exported.access_key_id.is_none() || exported.secret_access_key.is_none() {
        return Err(ExitError::new(
            5,
            format!(
                "aws configure export-credentials for profile {profile} did not return AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
            ),
        )
        .into());
    }
    Ok(exported)
}

fn aws_config_path(env_name: &str, default_parts: &[&str]) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_name) {
        return Some(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME")?;
    let mut path = PathBuf::from(home);
    for part in default_parts {
        path.push(part);
    }
    Some(path)
}

fn read_optional_string(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(ExitError::new(5, format!("failed to read {}: {err}", path.display())).into())
        }
    }
}

fn aws_profile_section_names(profile: &str, config_file: bool) -> Vec<String> {
    if config_file && profile != "default" {
        vec![format!("profile {profile}")]
    } else {
        vec![profile.to_string()]
    }
}

fn parse_aws_ini_section(contents: &str, section_names: &[String]) -> BTreeMap<String, String> {
    let mut active = false;
    let mut values = BTreeMap::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            active = section_names.iter().any(|name| name == section.trim());
            continue;
        }
        if !active {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(key.trim().to_string(), value.trim().to_string());
    }
    values
}

fn aws_profile_config_from_values(values: BTreeMap<String, String>) -> AwsProfileConfig {
    AwsProfileConfig {
        access_key_id: values.get("aws_access_key_id").cloned(),
        secret_access_key: values.get("aws_secret_access_key").cloned(),
        session_token: values
            .get("aws_session_token")
            .or_else(|| values.get("aws_security_token"))
            .cloned(),
        region: values.get("region").cloned(),
    }
}

fn aws_profile_config_from_export_env(contents: &str) -> AwsProfileConfig {
    let values = contents
        .lines()
        .filter_map(|line| {
            let (key, value) = line.trim().split_once('=')?;
            Some((key.trim().to_string(), unquote_env_value(value.trim())))
        })
        .collect::<BTreeMap<_, _>>();
    AwsProfileConfig {
        access_key_id: values.get("AWS_ACCESS_KEY_ID").cloned(),
        secret_access_key: values.get("AWS_SECRET_ACCESS_KEY").cloned(),
        session_token: values.get("AWS_SESSION_TOKEN").cloned(),
        region: values
            .get("AWS_REGION")
            .or_else(|| values.get("AWS_DEFAULT_REGION"))
            .cloned(),
    }
}

fn unquote_env_value(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|stripped| stripped.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|stripped| stripped.strip_suffix('\''))
        })
        .unwrap_or(value)
        .to_string()
}

fn s3_failure_report(
    command: &'static str,
    target: &str,
    err: &anyhow::Error,
    cli: &Cli,
) -> Report {
    let message = redact_sensitive(&format_error(err, cli.verbose));
    let exit_code = err.downcast_ref::<ExitError>().map(|error| error.code);
    let finding_type = exit_code
        .filter(|code| *code != 5)
        .map(|code| error_type_for_failure(err, code))
        .unwrap_or("s3_permission_error");
    let is_limit_failure = finding_type == "scan_truncated";
    let suggested_action = if is_limit_failure {
        "Increase the configured limit only if the expected S3 scan cost is acceptable."
    } else {
        suggested_action_for_error_type(finding_type)
    };
    let summary_message = match finding_type {
        "scan_truncated" => "S3 scan stopped by configured guardrails.",
        "s3_permission_error" => "S3 metadata inspection failed before the scan completed.",
        "invalid_arguments" => {
            "S3 metadata inspection did not start because arguments were invalid."
        }
        "input_not_found" => "S3 metadata inspection did not find matching Parquet objects.",
        "unreadable_file" => "S3 object metadata could not be read as Parquet.",
        _ => "S3 metadata inspection failed before the scan completed.",
    };
    let mut report = Report {
        schema_version: REPORT_SCHEMA_VERSION,
        tool: Tool {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        },
        command,
        status: Status::Error,
        artifact: Artifact {
            artifact_type: if command == "inspect" {
                "parquet_file"
            } else {
                "parquet_dataset"
            },
            uri: target.to_string(),
            rows: 0,
            columns: 0,
            row_groups: 0,
            size_bytes: None,
            files_matched: (command == "check").then_some(0),
            files_scanned: (command == "check").then_some(0),
        },
        scan: Scan {
            mode: "metadata_only",
            data_pages_read: false,
            complete: false,
            scan_truncated: is_limit_failure,
        },
        summary: Summary {
            message: summary_message.to_string(),
            rows: 0,
            columns: 0,
            files: 0,
            findings: 1,
        },
        schema: SchemaSummary::default(),
        columns: Vec::new(),
        row_groups: RowGroupSummary {
            count: 0,
            min_rows: None,
            median_rows: None,
            max_rows: None,
        },
        files: Vec::new(),
        findings: vec![make_finding(
            finding_type,
            Severity::Error,
            "high",
            message.clone(),
            FindingLocation::default(),
            BTreeMap::new(),
            suggested_action.to_string(),
            Vec::new(),
            1,
        )],
        preview: None,
        limits: limits(cli),
        warnings: Vec::new(),
        errors: vec![ErrorInfo {
            error_type: finding_type.to_string(),
            message,
            recoverable: !matches!(
                finding_type,
                "corrupt_metadata" | "unreadable_file" | "internal_error"
            ),
            suggested_action: suggested_action.to_string(),
        }],
    };
    finalize_report(&mut report, cli);
    report
}

fn discover_parquet_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if root.is_file() {
        if is_parquet_path(root) {
            files.push(root.to_path_buf());
        }
    } else {
        for entry in WalkDir::new(root).follow_links(false).sort_by_file_name() {
            let entry = entry?;
            if entry.file_type().is_file() && is_parquet_path(entry.path()) {
                files.push(entry.path().to_path_buf());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn aggregate_columns(files: &[InspectedFile], max_columns: usize) -> Vec<ColumnSummary> {
    let mut columns: BTreeMap<String, ColumnSummary> = BTreeMap::new();
    for file in files {
        for column in &file.columns {
            columns
                .entry(column.name.clone())
                .and_modify(|aggregate| {
                    aggregate.files_present += 1;
                    aggregate.row_groups_present += column.row_groups_present;
                    aggregate.row_groups_with_statistics += column.row_groups_with_statistics;
                    aggregate.row_groups_missing_statistics += column.row_groups_missing_statistics;
                    aggregate.all_null_row_groups += column.all_null_row_groups;
                    aggregate.null_count = match (aggregate.null_count, column.null_count) {
                        (Some(left), Some(right)) => Some(left + right),
                        (Some(left), None) => Some(left),
                        (None, Some(right)) => Some(right),
                        (None, None) => None,
                    };
                    aggregate.min_value = match (&aggregate.min_value, &column.min_value) {
                        (Some(left), Some(right)) => Some(left.min(right).clone()),
                        (Some(left), None) => Some(left.clone()),
                        (None, Some(right)) => Some(right.clone()),
                        (None, None) => None,
                    };
                    aggregate.max_value = match (&aggregate.max_value, &column.max_value) {
                        (Some(left), Some(right)) => Some(left.max(right).clone()),
                        (Some(left), None) => Some(left.clone()),
                        (None, Some(right)) => Some(right.clone()),
                        (None, None) => None,
                    };
                    merge_sorted_strings(&mut aggregate.compression, &column.compression);
                    merge_sorted_strings(&mut aggregate.encodings, &column.encodings);
                })
                .or_insert_with(|| column.clone());
        }
    }
    columns.into_values().take(max_columns).collect()
}

fn summarize_row_groups(files: &[InspectedFile]) -> RowGroupSummary {
    let mut rows = files
        .iter()
        .flat_map(|file| file.row_group_rows.clone())
        .collect::<Vec<_>>();
    rows.sort_unstable();
    RowGroupSummary {
        count: rows.len(),
        min_rows: rows.first().copied(),
        median_rows: median_i64(&rows),
        max_rows: rows.last().copied(),
    }
}

fn assign_finding_ids(seeds: Vec<FindingSeed>) -> Vec<Finding> {
    seeds
        .into_iter()
        .enumerate()
        .map(|(index, seed)| Finding {
            id: format!("finding_{:03}", index + 1),
            finding_type: seed.finding_type.to_string(),
            severity: seed.severity,
            confidence: seed.confidence,
            message: seed.message,
            location: seed.location,
            evidence: seed.evidence,
            suggested_action: seed.suggested_action,
            example_files: seed.example_files,
        })
        .collect()
}

fn make_finding(
    finding_type: &str,
    severity: Severity,
    confidence: &'static str,
    message: String,
    location: FindingLocation,
    evidence: BTreeMap<String, serde_json::Value>,
    suggested_action: String,
    example_files: Vec<String>,
    index: usize,
) -> Finding {
    Finding {
        id: format!("finding_{index:03}"),
        finding_type: finding_type.to_string(),
        severity,
        confidence,
        message,
        location,
        evidence,
        suggested_action,
        example_files,
    }
}

fn seed_sort(left: &FindingSeed, right: &FindingSeed) -> Ordering {
    right
        .severity
        .cmp(&left.severity)
        .then_with(|| left.finding_type.cmp(right.finding_type))
        .then_with(|| left.message.cmp(&right.message))
}

fn finding_sort(left: &Finding, right: &Finding) -> Ordering {
    right
        .severity
        .cmp(&left.severity)
        .then_with(|| left.finding_type.cmp(&right.finding_type))
        .then_with(|| left.message.cmp(&right.message))
}

fn schema_fingerprint(schema: &[SchemaField]) -> String {
    let joined = schema
        .iter()
        .map(|field| {
            format!(
                "{}:{}:{}:{}",
                field.name, field.physical_type, field.logical_type, field.max_definition_level
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    format!("{:016x}", stable_hash(joined.as_bytes()))
}

fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn format_physical_type(physical_type: PhysicalType) -> String {
    format!("{physical_type:?}").to_lowercase()
}

fn format_compression(compression: Compression) -> String {
    format!("{compression:?}").to_lowercase()
}

fn format_encoding(encoding: Encoding) -> String {
    format!("{encoding:?}").to_lowercase()
}

fn median_i64(values: &[i64]) -> Option<i64> {
    if values.is_empty() {
        None
    } else {
        Some(values[values.len() / 2])
    }
}

fn is_parquet_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("parquet"))
}

fn is_s3_uri(target: &str) -> bool {
    target.starts_with("s3://")
}

fn is_exit_code(err: &anyhow::Error, code: i32) -> bool {
    err.downcast_ref::<ExitError>()
        .is_some_and(|error| error.code == code)
}

fn parse_fail_on_set(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .flat_map(normalize_finding_type_alias)
        .collect()
}

fn normalize_finding_type_alias(value: &str) -> Vec<String> {
    let normalized = value.replace('-', "_");
    match normalized.as_str() {
        "corrupt_file" => vec![
            "unreadable_file".to_string(),
            "corrupt_metadata".to_string(),
        ],
        "missing_stats" => vec!["missing_statistics".to_string()],
        _ => vec![normalized],
    }
}

fn validate_fail_on(value: &str) -> Result<()> {
    for token in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let normalized = normalize_finding_type_alias(token);
        if normalized
            .iter()
            .any(|finding_type| !is_known_policy_finding_type(finding_type))
        {
            return Err(ExitError::new(
                2,
                format!(
                    "unknown --fail-on finding type {token}; expected one of: {}",
                    known_policy_finding_types().join(", ")
                ),
            )
            .into());
        }
    }
    Ok(())
}

fn is_known_policy_finding_type(finding_type: &str) -> bool {
    known_policy_finding_types().contains(&finding_type)
}

fn known_policy_finding_types() -> &'static [&'static str] {
    &[
        "all_null_row_group",
        "corrupt_metadata",
        "extra_column",
        "minmax_outlier",
        "missing_column",
        "missing_statistics",
        "null_spike",
        "row_count_skew",
        "s3_permission_error",
        "scan_truncated",
        "schema_drift",
        "type_change",
        "unreadable_file",
    ]
}

fn classify_parquet_read_error(err: &anyhow::Error) -> &'static str {
    if err.chain().any(|cause| cause.is::<ParquetError>()) {
        "corrupt_metadata"
    } else {
        "unreadable_file"
    }
}

fn is_unreadable_dataset_error(error: &ErrorInfo) -> bool {
    matches!(
        error.error_type.as_str(),
        "unreadable_file" | "corrupt_metadata"
    )
}

fn timeout_label(cli: &Cli) -> String {
    cli.timeout.clone().unwrap_or_else(|| "60s".to_string())
}

fn timeout_duration(cli: &Cli) -> Result<Duration> {
    parse_duration(&timeout_label(cli))
}

fn parse_duration(value: &str) -> Result<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ExitError::new(2, "--timeout must not be empty").into());
    }
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, Duration::from_millis(1))
    } else if let Some(number) = value.strip_suffix('s') {
        (number, Duration::from_secs(1))
    } else if let Some(number) = value.strip_suffix('m') {
        (number, Duration::from_secs(60))
    } else {
        (value, Duration::from_secs(1))
    };
    let amount = number.trim().parse::<u64>().map_err(|_| {
        ExitError::new(
            2,
            format!("invalid --timeout {value}; use a duration like 500ms, 30s, or 2m"),
        )
    })?;
    if amount == 0 {
        return Err(ExitError::new(2, "--timeout must be greater than zero").into());
    }
    let amount = u32::try_from(amount).map_err(|_| {
        ExitError::new(
            2,
            format!("invalid --timeout {value}; duration is too large"),
        )
    })?;
    multiplier.checked_mul(amount).ok_or_else(|| {
        ExitError::new(
            2,
            format!("invalid --timeout {value}; duration is too large"),
        )
        .into()
    })
}

fn limits(cli: &Cli) -> Limits {
    Limits {
        max_files: cli.max_files,
        max_findings: cli.max_findings,
        max_example_files: cli.max_example_files,
        max_columns: cli.max_columns,
        timeout: cli.timeout.clone(),
        max_requests: cli.max_requests,
        max_bytes: cli.max_bytes,
        s3_concurrency: cli.s3_concurrency,
        null_spike_ratio: cli.null_spike_ratio,
        row_count_skew_factor: cli.row_count_skew_factor,
        minmax_outlier_factor: cli.minmax_outlier_factor,
    }
}

fn btree_json<const N: usize, K, V>(items: [(K, V); N]) -> BTreeMap<String, serde_json::Value>
where
    K: Into<String>,
    V: Serialize,
{
    items
        .into_iter()
        .map(|(key, value)| {
            (
                key.into(),
                serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

fn merge_sorted_strings(target: &mut Vec<String>, source: &[String]) {
    let mut set = target.iter().cloned().collect::<BTreeSet<_>>();
    set.extend(source.iter().cloned());
    *target = set.into_iter().collect();
}

fn title_case(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn artifact_label(report: &Report) -> &'static str {
    if report.command == "inspect" {
        "File"
    } else {
        "Dataset"
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_array::{Int64Array, RecordBatch, StringArray};
    use arrow_schema::{DataType, Field, Schema};
    use clap::CommandFactory;
    use object_store::memory::InMemory;
    use parquet::arrow::ArrowWriter;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn inspect_local_file_emits_stable_json_contract() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("healthy.parquet");
        write_parquet(
            &path,
            Arc::new(Schema::new(vec![
                Field::new("user_id", DataType::Int64, false),
                Field::new("country", DataType::Utf8, true),
            ])),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![Some("US"), Some("CA"), Some("US")])),
            ],
        );

        let cli = test_cli();
        let report = inspect_local_file(path.to_str().unwrap(), &cli).unwrap();

        assert_eq!(report.schema_version, "sounder.report.v1");
        assert_eq!(report.command, "inspect");
        assert_eq!(report.artifact.rows, 3);
        assert_eq!(report.artifact.columns, 2);
        assert!(!report.scan.data_pages_read);
        assert!(report.scan.complete);
        let text = render_text(&report, false);
        assert!(text.contains("Compression: uncompressed"));
        assert!(text.contains("Encodings: plain, rle, rle_dictionary"));
        let user_id = report
            .columns
            .iter()
            .find(|column| column.name == "user_id")
            .unwrap();
        assert_eq!(user_id.logical_type, "None");
        assert_eq!(user_id.min_value.as_deref(), Some("1"));
        assert_eq!(user_id.max_value.as_deref(), Some("3"));
        let country = report
            .columns
            .iter()
            .find(|column| column.name == "country")
            .unwrap();
        assert_eq!(country.logical_type, "Some(String)");
    }

    #[test]
    fn inspect_head_reads_bounded_preview_rows() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("preview.parquet");
        write_parquet(
            &path,
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
        );

        let cli = test_cli();
        let report = inspect_command(path.to_str().unwrap(), Some(2), &cli).unwrap();
        let preview = report.preview.as_ref().unwrap();

        assert_eq!(report.scan.mode, "metadata_with_preview");
        assert!(report.scan.data_pages_read);
        assert_eq!(preview.requested_rows, 2);
        assert_eq!(preview.returned_rows, 2);
        assert_eq!(preview.rows.len(), 2);
    }

    #[test]
    fn s3_preview_warning_is_visible_in_human_and_markdown_output() {
        let cli = test_cli();
        let mut report = command_failure_report(&cli, &anyhow::anyhow!("preview smoke"), 7);
        report.command = "inspect";
        report.artifact.artifact_type = "parquet_file";
        report.artifact.uri = "s3://bucket/path/file.parquet".to_string();
        report.scan.mode = "metadata_with_preview";
        report.scan.data_pages_read = true;
        report.warnings = vec![s3_preview_warning(&report.artifact.uri)];
        report.errors.clear();
        report.findings.clear();
        finalize_report(&mut report, &cli);

        let text = render_text(&report, false);
        assert!(text.contains("Warnings"));
        assert!(text.contains("data pages may be read"));

        let markdown = render_markdown_report(&report);
        assert!(markdown.contains("### Warnings"));
        assert!(markdown.contains("data pages may be read"));
    }

    #[test]
    fn human_metadata_values_are_truncated_for_terminal_width() {
        let short = "created by test";
        assert_eq!(format_human_metadata_value(short), short);

        let long = "x".repeat(140);
        let rendered = format_human_metadata_value(&long);
        assert!(rendered.starts_with(&"x".repeat(120)));
        assert!(rendered.ends_with("... (140 chars)"));
        assert!(rendered.len() < long.len());
    }

    #[test]
    fn human_text_color_is_optional_and_limited_to_text_output() {
        let cli = test_cli();
        let mut report = command_failure_report(&cli, &anyhow::anyhow!("metadata issue"), 4);
        report.command = "inspect";
        report.artifact.artifact_type = "parquet_file";
        report.artifact.uri = "./bad.parquet".to_string();
        report.errors.clear();
        report.findings = vec![make_finding(
            "corrupt_metadata",
            Severity::Error,
            "high",
            "File footer metadata is corrupt.".to_string(),
            FindingLocation {
                file: Some("./bad.parquet".to_string()),
                row_group: None,
                column: None,
            },
            BTreeMap::new(),
            "Rewrite the affected file.".to_string(),
            vec!["./bad.parquet".to_string()],
            1,
        )];
        finalize_report(&mut report, &cli);

        let plain = render_text(&report, false);
        assert!(!plain.contains("\x1b["));
        assert!(plain.contains("Status: error"));

        let colored = render_text(&report, true);
        assert!(colored.contains("Status: \x1b[31merror\x1b[0m"));
        assert!(colored.contains("\x1b[31merror\x1b[0m"));
    }

    #[test]
    fn preview_rows_from_in_memory_parquet_bytes() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("preview.parquet");
        write_parquet(
            &path,
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
        );

        let bytes = Bytes::from(std::fs::read(path).unwrap());
        let preview = preview_rows_from_bytes(bytes, 2).unwrap();

        assert_eq!(preview.requested_rows, 2);
        assert_eq!(preview.returned_rows, 2);
        assert_eq!(preview.rows.len(), 2);
    }

    #[test]
    fn check_detects_schema_drift() {
        let temp = TempDir::new().unwrap();
        write_parquet(
            &temp.path().join("part-000.parquet"),
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
        );
        write_parquet(
            &temp.path().join("part-001.parquet"),
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Utf8,
                false,
            )])),
            vec![Arc::new(StringArray::from(vec![Some("1"), Some("2")]))],
        );

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert_eq!(report.status, Status::Error);
        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "schema_drift" && finding.severity == Severity::Error
        }));
    }

    #[test]
    fn max_findings_bounds_output_not_policy() {
        let temp = TempDir::new().unwrap();
        write_schema_drift_dataset(&temp);

        let mut cli = test_cli();
        cli.max_findings = 0;
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert_eq!(report.status, Status::Error);
        assert_eq!(exit_code_for_report(&report, &cli), 1);
        assert!(report.summary.findings > 0);

        let shaped = report_for_details(&report, &cli);
        assert!(shaped.findings.is_empty());
        assert_eq!(shaped.status, Status::Error);
        assert!(shaped.summary.findings > 0);
        assert!(shaped.warnings.iter().any(|warning| {
            warning.contains("findings output truncated")
                && warning.contains(&format!("showing 0 of {}", report.summary.findings))
        }));
    }

    #[test]
    fn max_columns_bounds_schema_output_not_counts() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("wide.parquet");
        write_parquet(
            &path,
            Arc::new(Schema::new(vec![
                Field::new("col_0", DataType::Int64, false),
                Field::new("col_1", DataType::Int64, false),
                Field::new("col_2", DataType::Int64, false),
            ])),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])),
                Arc::new(Int64Array::from(vec![4, 5, 6])),
                Arc::new(Int64Array::from(vec![7, 8, 9])),
            ],
        );

        let mut cli = test_cli();
        cli.max_columns = 2;
        let report = inspect_command(path.to_str().unwrap(), None, &cli).unwrap();
        assert_eq!(report.artifact.columns, 3);
        assert_eq!(report.summary.columns, 3);
        assert_eq!(report.schema.column_count, 3);
        assert_eq!(report.schema.canonical.len(), 3);
        assert_eq!(report.columns.len(), 2);

        let shaped = report_for_details(&report, &cli);
        assert_eq!(shaped.artifact.columns, 3);
        assert_eq!(shaped.summary.columns, 3);
        assert_eq!(shaped.schema.column_count, 3);
        assert_eq!(shaped.schema.canonical.len(), 2);
        assert_eq!(shaped.columns.len(), 2);
        assert!(shaped.warnings.iter().any(|warning| {
            warning.contains("schema output truncated")
                && warning.contains("showing 2 of 3 columns")
        }));
    }

    #[test]
    fn check_classifies_missing_extra_and_type_change() {
        let temp = TempDir::new().unwrap();
        for name in ["part-000.parquet", "part-001.parquet"] {
            write_parquet(
                &temp.path().join(name),
                Arc::new(Schema::new(vec![
                    Field::new("user_id", DataType::Int64, false),
                    Field::new("country", DataType::Utf8, true),
                ])),
                vec![
                    Arc::new(Int64Array::from(vec![1, 2, 3])),
                    Arc::new(StringArray::from(vec![Some("US"), Some("CA"), Some("US")])),
                ],
            );
        }
        write_parquet(
            &temp.path().join("part-002.parquet"),
            Arc::new(Schema::new(vec![
                Field::new("user_id", DataType::Utf8, false),
                Field::new("device", DataType::Utf8, true),
            ])),
            vec![
                Arc::new(StringArray::from(vec![Some("1"), Some("2")])),
                Arc::new(StringArray::from(vec![Some("ios"), Some("web")])),
            ],
        );

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();
        let finding_types = report
            .findings
            .iter()
            .map(|finding| finding.finding_type.as_str())
            .collect::<BTreeSet<_>>();

        assert!(finding_types.contains("schema_drift"));
        assert!(finding_types.contains("missing_column"));
        assert!(finding_types.contains("extra_column"));
        assert!(finding_types.contains("type_change"));
    }

    #[test]
    fn details_none_suppresses_heavy_report_sections() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("healthy.parquet");
        write_parquet(
            &path,
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
        );

        let mut cli = test_cli();
        cli.details = Details::None;
        let report = inspect_command(path.to_str().unwrap(), Some(2), &cli).unwrap();
        let shaped = report_for_details(&report, &cli);

        assert_eq!(shaped.artifact.rows, 3);
        assert!(shaped.schema.canonical.is_empty());
        assert!(shaped.columns.is_empty());
        assert!(shaped.files.is_empty());
        assert!(shaped.preview.is_none());
        assert_eq!(shaped.row_groups.count, 1);
    }

    #[test]
    fn details_summary_bounds_dataset_file_list() {
        let temp = TempDir::new().unwrap();
        for index in 0..4 {
            write_parquet(
                &temp.path().join(format!("part-{index:03}.parquet")),
                Arc::new(Schema::new(vec![Field::new(
                    "user_id",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
            );
        }

        let mut cli = test_cli();
        cli.details = Details::Summary;
        cli.max_example_files = 2;
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();
        let shaped = report_for_details(&report, &cli);

        assert_eq!(report.files.len(), 4);
        assert_eq!(shaped.files.len(), 2);
        assert_eq!(shaped.artifact.files_scanned, Some(4));
    }

    #[test]
    fn golden_inspect_healthy_agent_json() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("healthy.parquet");
        write_healthy_parquet(&path);

        let cli = test_cli();
        let report = inspect_command(path.to_str().unwrap(), None, &cli).unwrap();
        let actual = scrub_temp_path(
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&agent_packet(&report)).unwrap()
            ),
            &temp,
        );

        assert_golden("inspect_healthy.agent.json", &actual);
    }

    #[test]
    fn golden_inspect_healthy_report_json() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("healthy.parquet");
        write_healthy_parquet(&path);

        let cli = test_cli();
        let report = inspect_command(path.to_str().unwrap(), None, &cli).unwrap();
        let actual = scrub_temp_path(
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&report_for_details(&report, &cli)).unwrap()
            ),
            &temp,
        );

        assert_golden("inspect_healthy.report.json", &actual);
    }

    #[test]
    fn golden_inspect_healthy_markdown() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("healthy.parquet");
        write_healthy_parquet(&path);

        let cli = test_cli();
        let report = inspect_command(path.to_str().unwrap(), None, &cli).unwrap();
        let actual = scrub_temp_path(&(render_markdown_report(&report) + "\n"), &temp);

        assert_golden("inspect_healthy.markdown", &actual);
    }

    #[test]
    fn golden_check_schema_drift_agent_json() {
        let temp = TempDir::new().unwrap();
        write_schema_drift_dataset(&temp);

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();
        let actual = scrub_temp_path(
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&agent_packet(&report)).unwrap()
            ),
            &temp,
        );

        assert_golden("check_schema_drift.agent.json", &actual);
    }

    #[test]
    fn golden_check_schema_drift_report_json() {
        let temp = TempDir::new().unwrap();
        write_schema_drift_dataset(&temp);

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();
        let actual = scrub_temp_path(
            &format!(
                "{}\n",
                serde_json::to_string_pretty(&report_for_details(&report, &cli)).unwrap()
            ),
            &temp,
        );

        assert_golden("check_schema_drift.report.json", &actual);
    }

    #[test]
    fn golden_check_schema_drift_markdown() {
        let temp = TempDir::new().unwrap();
        write_schema_drift_dataset(&temp);

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();
        let actual = scrub_temp_path(&(render_markdown_agent(&report) + "\n"), &temp);

        assert_golden("check_schema_drift.markdown", &actual);
    }

    #[test]
    fn check_detects_all_null_row_group() {
        let temp = TempDir::new().unwrap();
        write_parquet(
            &temp.path().join("nulls.parquet"),
            Arc::new(Schema::new(vec![Field::new(
                "country",
                DataType::Utf8,
                true,
            )])),
            vec![Arc::new(StringArray::from(vec![
                None::<&str>,
                None::<&str>,
                None::<&str>,
            ]))],
        );

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "all_null_row_group" || finding.finding_type == "null_spike"
        }));
    }

    #[test]
    fn check_coalesces_column_stat_findings_by_dataset() {
        let temp = TempDir::new().unwrap();
        for index in 0..3 {
            write_parquet(
                &temp.path().join(format!("part-{index:03}.parquet")),
                Arc::new(Schema::new(vec![Field::new(
                    "country",
                    DataType::Utf8,
                    true,
                )])),
                vec![Arc::new(StringArray::from(vec![
                    None::<&str>,
                    None::<&str>,
                    None::<&str>,
                ]))],
            );
        }

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        let null_spikes = report
            .findings
            .iter()
            .filter(|finding| finding.finding_type == "null_spike")
            .collect::<Vec<_>>();
        assert_eq!(null_spikes.len(), 1);
        assert_eq!(
            null_spikes[0].evidence.get("affected_files"),
            Some(&serde_json::json!(3))
        );
        assert_eq!(null_spikes[0].example_files.len(), 3);

        let all_null = report
            .findings
            .iter()
            .find(|finding| finding.finding_type == "all_null_row_group")
            .unwrap();
        assert_eq!(
            all_null.evidence.get("all_null_row_groups"),
            Some(&serde_json::json!(3))
        );
    }

    #[test]
    fn custom_null_spike_threshold_controls_findings() {
        let temp = TempDir::new().unwrap();
        write_parquet(
            &temp.path().join("mostly_nulls.parquet"),
            Arc::new(Schema::new(vec![Field::new(
                "country",
                DataType::Utf8,
                true,
            )])),
            vec![Arc::new(StringArray::from(vec![
                None::<&str>,
                None::<&str>,
                Some("US"),
                Some("CA"),
            ]))],
        );

        let mut cli = test_cli();
        cli.null_spike_ratio = 0.5;
        let report = inspect_command(
            temp.path().join("mostly_nulls.parquet").to_str().unwrap(),
            None,
            &cli,
        )
        .unwrap();

        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "null_spike"
                && finding.evidence.get("threshold_ratio") == Some(&serde_json::json!(0.5))
        }));
    }

    #[test]
    fn custom_row_count_skew_threshold_controls_findings() {
        let temp = TempDir::new().unwrap();
        for (name, values) in [
            ("part-000.parquet", vec![1, 2, 3]),
            ("part-001.parquet", vec![1, 2, 3]),
            ("part-002.parquet", vec![1, 2, 3, 4, 5, 6, 7]),
        ] {
            write_parquet(
                &temp.path().join(name),
                Arc::new(Schema::new(vec![Field::new(
                    "user_id",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(values))],
            );
        }

        let mut cli = test_cli();
        cli.row_count_skew_factor = 2.0;
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "row_count_skew"
                && finding.evidence.get("threshold_factor") == Some(&serde_json::json!(2.0))
        }));
    }

    #[test]
    fn row_count_skew_detects_incomplete_small_shards() {
        let temp = TempDir::new().unwrap();
        for (name, values) in [
            ("part-000.parquet", (1..=10).collect::<Vec<_>>()),
            ("part-001.parquet", (1..=10).collect::<Vec<_>>()),
            ("part-002.parquet", (1..=10).collect::<Vec<_>>()),
            ("part-003.parquet", vec![1]),
        ] {
            write_parquet(
                &temp.path().join(name),
                Arc::new(Schema::new(vec![Field::new(
                    "user_id",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(values))],
            );
        }

        let mut cli = test_cli();
        cli.row_count_skew_factor = 5.0;
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        let finding = report
            .findings
            .iter()
            .find(|finding| {
                finding.finding_type == "row_count_skew"
                    && finding.message.contains("10.0% of the median row count")
            })
            .unwrap();
        assert_eq!(
            finding.suggested_action,
            "Check whether this file is an incomplete shard."
        );
        assert_eq!(
            finding.evidence.get("file_rows"),
            Some(&serde_json::json!(1))
        );
        assert_eq!(
            finding.evidence.get("median_rows"),
            Some(&serde_json::json!(10))
        );
    }

    #[test]
    fn invalid_thresholds_are_rejected() {
        let mut cli = test_cli();
        cli.null_spike_ratio = 1.1;
        assert!(validate_cli(&cli).is_err());

        let mut cli = test_cli();
        cli.row_count_skew_factor = 1.0;
        assert!(validate_cli(&cli).is_err());

        let mut cli = test_cli();
        cli.minmax_outlier_factor = 1.0;
        assert!(validate_cli(&cli).is_err());
    }

    #[test]
    fn machine_mode_failures_emit_schema_versioned_reports() {
        let mut cli = test_cli();
        cli.command = Commands::Check {
            target: "missing".to_string(),
        };
        cli.json = true;
        let err: anyhow::Error = ExitError::new(3, "input not found: missing").into();
        let report = command_failure_report(&cli, &err, 3);

        assert_eq!(report.schema_version, "sounder.report.v1");
        assert_eq!(report.command, "check");
        assert_eq!(report.status, Status::Error);
        assert!(report.summary.message.contains("did not complete"));
        assert!(!report.summary.message.contains("readable"));
        assert_eq!(report.errors[0].error_type, "input_not_found");
        assert_eq!(report.findings[0].finding_type, "input_not_found");
        assert_eq!(report.artifact.files_matched, Some(0));
    }

    #[test]
    fn verbose_controls_structured_failure_error_detail() {
        let mut cli = test_cli();
        cli.command = Commands::Check {
            target: "missing".to_string(),
        };
        cli.json = true;
        let err = anyhow::anyhow!("root cause").context("outer context");

        let concise = command_failure_report(&cli, &err, 7);
        assert_eq!(concise.errors[0].message, "outer context");
        assert!(!concise.errors[0].message.contains("root cause"));

        cli.verbose = true;
        let verbose = command_failure_report(&cli, &err, 7);
        assert!(verbose.errors[0].message.contains("outer context"));
        assert!(verbose.errors[0].message.contains("root cause"));
    }

    #[test]
    fn machine_mode_corrupt_inspect_preserves_corrupt_metadata_type() {
        let mut cli = test_cli();
        cli.command = Commands::Inspect {
            target: "bad.parquet".to_string(),
            head: None,
        };
        cli.json = true;
        let err: anyhow::Error = ExitError::with_type(
            4,
            "corrupt_metadata",
            "failed to inspect Parquet metadata for bad.parquet: invalid footer",
        )
        .into();
        let report = command_failure_report(&cli, &err, 4);

        assert_eq!(report.errors[0].error_type, "corrupt_metadata");
        assert_eq!(report.findings[0].finding_type, "corrupt_metadata");
        assert_eq!(exit_code_for_report(&report, &cli), 4);
    }

    #[test]
    fn check_reports_truncated_scan() {
        let temp = TempDir::new().unwrap();
        for index in 0..3 {
            write_parquet(
                &temp.path().join(format!("part-{index:03}.parquet")),
                Arc::new(Schema::new(vec![Field::new(
                    "user_id",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
            );
        }

        let mut cli = test_cli();
        cli.max_files = 2;
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert!(report.scan.scan_truncated);
        assert_eq!(report.artifact.files_matched, Some(3));
        assert_eq!(report.artifact.files_scanned, Some(2));
        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "scan_truncated" && finding.severity == Severity::Warning
        }));
        assert_eq!(exit_code_for_report(&report, &cli), 6);
    }

    #[test]
    fn local_reader_stops_when_timeout_is_exceeded() {
        let temp = TempDir::new().unwrap();
        for index in 0..2 {
            write_parquet(
                &temp.path().join(format!("part-{index:03}.parquet")),
                Arc::new(Schema::new(vec![Field::new(
                    "user_id",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
            );
        }
        let files = discover_parquet_files(temp.path()).unwrap();
        let cli = test_cli();

        let (inspected, errors, timed_out, files_scanned) =
            read_local_parquet_files(files, &cli, Duration::ZERO);

        assert!(timed_out);
        assert!(inspected.is_empty());
        assert!(errors.is_empty());
        assert_eq!(files_scanned, 0);
    }

    #[test]
    fn local_report_timeout_returns_structured_scan_truncated_report() {
        let mut cli = test_cli();
        cli.timeout = Some("1ms".to_string());

        let report =
            run_local_report_with_timeout("inspect", "slow.parquet", "parquet_file", &cli, || {
                std::thread::sleep(Duration::from_millis(50));
                Err(ExitError::new(7, "slow worker should time out first").into())
            })
            .unwrap();

        assert_eq!(report.schema_version, "sounder.report.v1");
        assert_eq!(report.command, "inspect");
        assert_eq!(report.artifact.uri, "slow.parquet");
        assert!(!report.scan.complete);
        assert!(report.scan.scan_truncated);
        assert_eq!(report.errors[0].error_type, "scan_truncated");
        assert_eq!(exit_code_for_report(&report, &cli), 6);
        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "scan_truncated"
                && finding.evidence.contains_key("timeout")
                && finding.evidence.contains_key("max_files")
        }));
    }

    #[test]
    fn check_reports_unreadable_files_as_findings() {
        let temp = TempDir::new().unwrap();
        write_parquet(
            &temp.path().join("healthy.parquet"),
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Int64,
                false,
            )])),
            vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
        );
        std::fs::write(temp.path().join("corrupt.parquet"), b"not parquet").unwrap();

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert_eq!(report.status, Status::Error);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.artifact.files_matched, Some(2));
        assert_eq!(report.artifact.files_scanned, Some(2));
        assert!(report.summary.message.contains("2 scanned files"));
        assert!(report.errors.iter().any(|error| {
            error.error_type == "corrupt_metadata" && error.message.contains("corrupt.parquet")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "unreadable_file"
                && finding.severity == Severity::Error
                && finding
                    .example_files
                    .iter()
                    .any(|file| file.ends_with("corrupt.parquet"))
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "corrupt_metadata"
                && finding.severity == Severity::Error
                && finding
                    .example_files
                    .iter()
                    .any(|file| file.ends_with("corrupt.parquet"))
        }));
        assert!(
            suspicious_file_rows(&report, 5)
                .iter()
                .any(|(file, reasons)| file.ends_with("corrupt.parquet")
                    && reasons.contains(&"corrupt_metadata".to_string()))
        );
        assert_eq!(exit_code_for_report(&report, &cli), 1);
    }

    #[test]
    fn check_detects_numeric_minmax_outlier() {
        let temp = TempDir::new().unwrap();
        for (name, values) in [
            ("part-000.parquet", vec![1, 2, 10]),
            ("part-001.parquet", vec![2, 3, 11]),
            ("part-002.parquet", vec![1, 4, 2000]),
        ] {
            write_parquet(
                &temp.path().join(name),
                Arc::new(Schema::new(vec![Field::new(
                    "event_time",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(values))],
            );
        }

        let cli = test_cli();
        let report = check_command(temp.path().to_str().unwrap(), &cli).unwrap();

        assert!(report.findings.iter().any(|finding| {
            finding.finding_type == "minmax_outlier"
                && finding.location.column.as_deref() == Some("event_time")
        }));
    }

    #[test]
    fn parses_s3_uri_targets() {
        let target = parse_s3_uri("s3://bucket/path/to/file.parquet").unwrap();
        assert_eq!(
            target,
            S3Target {
                bucket: "bucket".to_string(),
                key: "path/to/file.parquet".to_string()
            }
        );

        let prefix = parse_s3_uri("s3://bucket/path/to/prefix/").unwrap();
        assert_eq!(prefix.bucket, "bucket");
        assert_eq!(prefix.key, "path/to/prefix/");
    }

    #[test]
    fn s3_list_reports_truncation_when_file_budget_allows_no_matches() {
        let store = InMemory::new();
        run_async(async {
            store
                .put(
                    &ObjectPath::from("dataset/part-000.parquet"),
                    "not read by this test".into(),
                )
                .await?;

            let mut cli = test_cli();
            cli.max_files = 0;
            let budget = S3Budget::new(&cli).unwrap();
            let target = S3Target {
                bucket: "bucket".to_string(),
                key: "dataset/".to_string(),
            };

            let (objects, matched, truncated) =
                list_s3_parquet_objects(&store, &target, &cli, &budget).await?;

            assert!(objects.is_empty());
            assert_eq!(matched, 1);
            assert!(truncated);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn cli_default_timeout_is_finite() {
        let cli = Cli::parse_from(["sounder", "version"]);
        assert_eq!(cli.timeout.as_deref(), Some("60s"));
        assert_eq!(cli.s3_concurrency, 16);
    }

    #[test]
    fn help_text_describes_core_commands_and_flags() {
        let mut command = Cli::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("Inspect one local or S3 Parquet file"));
        assert!(help.contains("Check a local directory or S3 prefix as one dataset"));
        assert!(help.contains("dataset"));
        assert!(help.contains("doctor"));
        assert!(help.contains("Emit a compact evidence packet for agents"));
        assert!(help.contains("Maximum S3 metadata/list/range requests"));
        assert!(help.contains("Fail CI on finding types"));

        let mut inspect = Cli::command()
            .find_subcommand_mut("inspect")
            .unwrap()
            .clone();
        let mut inspect_help = Vec::new();
        inspect.write_long_help(&mut inspect_help).unwrap();
        let inspect_help = String::from_utf8(inspect_help).unwrap();

        assert!(inspect_help.contains("Local Parquet file or s3://bucket/key.parquet"));
        assert!(inspect_help.contains("Preview N rows by explicitly reading data pages"));
    }

    #[test]
    fn documented_check_aliases_parse_as_check_commands() {
        let dataset = Cli::parse_from(["sounder", "dataset", "fixtures"]);
        assert!(matches!(dataset.command, Commands::Dataset { .. }));

        let doctor = Cli::parse_from(["sounder", "doctor", "fixtures"]);
        assert!(matches!(doctor.command, Commands::Doctor { .. }));
    }

    #[test]
    fn output_mode_contract_matches_documented_flags() {
        let mut cli = test_cli();
        assert_eq!(emit_mode(&cli), EmitMode::TextReport);

        cli.json = true;
        assert_eq!(emit_mode(&cli), EmitMode::JsonReport);

        cli = test_cli();
        cli.format = OutputFormat::Json;
        assert_eq!(emit_mode(&cli), EmitMode::JsonReport);

        cli = test_cli();
        cli.agent = true;
        assert_eq!(emit_mode(&cli), EmitMode::JsonAgent);

        cli.format = OutputFormat::Markdown;
        assert_eq!(emit_mode(&cli), EmitMode::MarkdownAgent);

        cli.json = true;
        assert_eq!(emit_mode(&cli), EmitMode::JsonAgent);

        cli = test_cli();
        cli.format = OutputFormat::Markdown;
        assert_eq!(emit_mode(&cli), EmitMode::MarkdownReport);
    }

    #[test]
    fn parses_timeout_durations() {
        assert_eq!(
            parse_duration("500ms").unwrap(),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration("30s").unwrap(),
            std::time::Duration::from_secs(30)
        );
        assert_eq!(
            parse_duration("2m").unwrap(),
            std::time::Duration::from_secs(120)
        );
        assert_eq!(
            parse_duration("45").unwrap(),
            std::time::Duration::from_secs(45)
        );
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("soon").is_err());
    }

    #[test]
    fn s3_budget_enforces_requests_and_bytes() {
        let mut cli = test_cli();
        cli.max_requests = 1;
        cli.max_bytes = 8;

        let budget = S3Budget::new(&cli).unwrap();
        record_s3_request(&budget, "list_objects").unwrap();
        let err = record_s3_request(&budget, "head_object").unwrap_err();
        assert!(is_exit_code(&err, 6));

        let budget = S3Budget::new(&cli).unwrap();
        record_s3_bytes(&budget, 8, "get_object_range").unwrap();
        let err = record_s3_bytes(&budget, 1, "get_object_range").unwrap_err();
        assert!(is_exit_code(&err, 6));
    }

    #[test]
    fn s3_footer_range_budget_is_checked_before_request() {
        let mut cli = test_cli();
        cli.max_bytes = 7;
        let budget = S3Budget::new(&cli).unwrap();
        let requested_bytes = s3_range_len(92, 100).unwrap();

        let err = record_s3_bytes(&budget, requested_bytes, "get_object_range").unwrap_err();

        assert!(is_exit_code(&err, 6));
    }

    #[test]
    fn s3_footer_too_small_is_typed_as_corrupt_metadata() {
        let store = InMemory::new();
        run_async(async {
            let path = ObjectPath::from("tiny.parquet");
            store.put(&path, vec![1, 2, 3].into()).await?;

            let cli = test_cli();
            let budget = S3Budget::new(&cli).unwrap();
            let err = read_s3_footer_metadata(&store, &path, 3, &budget)
                .await
                .unwrap_err();
            let report = s3_failure_report("inspect", "s3://bucket/tiny.parquet", &err, &cli);

            assert_eq!(report.errors[0].error_type, "corrupt_metadata");
            assert_eq!(report.findings[0].finding_type, "corrupt_metadata");
            assert_eq!(exit_code_for_report(&report, &cli), 4);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn s3_range_len_handles_large_ranges() {
        assert_eq!(s3_range_len(92, 100).unwrap(), 8);
        assert_eq!(s3_range_len(100, 92).unwrap(), 0);
    }

    #[test]
    fn s3_guardrail_failure_reports_scan_truncated() {
        let cli = test_cli();
        let err: anyhow::Error =
            ExitError::new(6, "S3 request budget exceeded during head_object").into();
        let report = s3_failure_report("check", "s3://bucket/prefix/", &err, &cli);

        assert!(report.scan.scan_truncated);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.finding_type == "scan_truncated")
        );
        assert_eq!(exit_code_for_report(&report, &cli), 6);
    }

    #[test]
    fn s3_argument_failures_preserve_invalid_argument_exit_code() {
        let cli = test_cli();
        let err: anyhow::Error = ExitError::new(2, "S3 URI bucket is empty: s3://").into();
        let report = s3_failure_report("inspect", "s3://", &err, &cli);

        assert!(!report.scan.scan_truncated);
        assert_eq!(report.errors[0].error_type, "invalid_arguments");
        assert_eq!(report.findings[0].finding_type, "invalid_arguments");
        assert_eq!(exit_code_for_report(&report, &cli), 2);
        assert!(report.summary.message.contains("did not complete"));
    }

    #[test]
    fn s3_typed_corrupt_metadata_failure_exits_as_unreadable_parquet() {
        let cli = test_cli();
        let err: anyhow::Error = ExitError::with_type(
            4,
            "corrupt_metadata",
            "object is too small to contain a Parquet footer",
        )
        .into();
        let report = s3_failure_report("inspect", "s3://bucket/bad.parquet", &err, &cli);

        assert_eq!(report.errors[0].error_type, "corrupt_metadata");
        assert_eq!(report.findings[0].finding_type, "corrupt_metadata");
        assert_eq!(exit_code_for_report(&report, &cli), 4);
    }

    #[test]
    fn fail_on_accepts_documented_dashed_aliases() {
        let aliases = parse_fail_on_set("schema-drift,corrupt-file,missing-stats");

        assert!(aliases.contains("schema_drift"));
        assert!(aliases.contains("unreadable_file"));
        assert!(aliases.contains("corrupt_metadata"));
        assert!(aliases.contains("missing_statistics"));

        let mut cli = test_cli();
        cli.fail_on = Some("schema-drift,corrupt-file,missing-stats".to_string());
        validate_cli(&cli).unwrap();
    }

    #[test]
    fn fail_on_rejects_unknown_policy_names() {
        let mut cli = test_cli();
        cli.fail_on = Some("schema-drift,not-a-finding".to_string());

        let err = validate_cli(&cli).unwrap_err();
        assert!(is_exit_code(&err, 2));
        let message = format!("{err:#}");
        assert!(message.contains("unknown --fail-on finding type not-a-finding"));
        assert!(message.contains("schema_drift"));
    }

    #[test]
    fn parses_aws_profile_credentials_and_config_sections() {
        let credentials = r#"
            [default]
            aws_access_key_id = DEFAULT_KEY
            aws_secret_access_key = DEFAULT_SECRET

            [prod]
            aws_access_key_id = PROD_KEY
            aws_secret_access_key = PROD_SECRET
            aws_session_token = PROD_TOKEN
        "#;
        let config = r#"
            [profile prod]
            region = us-west-2
        "#;

        let mut values = parse_aws_ini_section(config, &aws_profile_section_names("prod", true));
        values.extend(parse_aws_ini_section(
            credentials,
            &aws_profile_section_names("prod", false),
        ));
        let profile = aws_profile_config_from_values(values);

        assert_eq!(
            profile,
            AwsProfileConfig {
                access_key_id: Some("PROD_KEY".to_string()),
                secret_access_key: Some("PROD_SECRET".to_string()),
                session_token: Some("PROD_TOKEN".to_string()),
                region: Some("us-west-2".to_string()),
            }
        );
    }

    #[test]
    fn parses_aws_cli_export_credentials_env_output() {
        let exported = r#"
            AWS_ACCESS_KEY_ID=EXPORTED_KEY
            AWS_SECRET_ACCESS_KEY="EXPORTED_SECRET"
            AWS_SESSION_TOKEN='EXPORTED_TOKEN'
        "#;

        let profile = aws_profile_config_from_export_env(exported);

        assert_eq!(
            profile,
            AwsProfileConfig {
                access_key_id: Some("EXPORTED_KEY".to_string()),
                secret_access_key: Some("EXPORTED_SECRET".to_string()),
                session_token: Some("EXPORTED_TOKEN".to_string()),
                region: None,
            }
        );
    }

    #[test]
    fn redacts_aws_credentials_and_signed_url_parts() {
        let message = concat!(
            "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF ",
            "AWS_SECRET_ACCESS_KEY=secret-value ",
            "AWS_SESSION_TOKEN='session-value' ",
            "https://bucket.s3.amazonaws.com/key?",
            "X-Amz-Credential=AKIA1234567890ABCDEF/20260613/us-west-2/s3/aws4_request&",
            "X-Amz-Signature=abcdef&",
            "X-Amz-Security-Token=token"
        );

        let redacted = redact_sensitive(message);

        assert!(redacted.contains("AWS_ACCESS_KEY_ID=[REDACTED]"));
        assert!(redacted.contains("AWS_SECRET_ACCESS_KEY=[REDACTED]"));
        assert!(redacted.contains("AWS_SESSION_TOKEN=[REDACTED]"));
        assert!(redacted.contains("X-Amz-Credential=[REDACTED]"));
        assert!(redacted.contains("X-Amz-Signature=[REDACTED]"));
        assert!(redacted.contains("X-Amz-Security-Token=[REDACTED]"));
        assert!(!redacted.contains("secret-value"));
        assert!(!redacted.contains("session-value"));
        assert!(!redacted.contains("abcdef&"));
        assert!(redacted.contains("bucket.s3.amazonaws.com/key"));
    }

    #[test]
    fn parses_default_aws_config_section_without_profile_prefix() {
        let config = r#"
            [default]
            region = us-east-1
        "#;

        let values = parse_aws_ini_section(config, &aws_profile_section_names("default", true));
        let profile = aws_profile_config_from_values(values);

        assert_eq!(profile.region.as_deref(), Some("us-east-1"));
    }

    fn write_parquet(path: &Path, schema: Arc<Schema>, columns: Vec<Arc<dyn arrow_array::Array>>) {
        let file = File::create(path).unwrap();
        let mut writer = ArrowWriter::try_new(file, schema.clone(), None).unwrap();
        let batch = RecordBatch::try_new(schema, columns).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    fn write_healthy_parquet(path: &Path) {
        write_parquet(
            path,
            Arc::new(Schema::new(vec![
                Field::new("user_id", DataType::Int64, false),
                Field::new("country", DataType::Utf8, true),
            ])),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3])),
                Arc::new(StringArray::from(vec![Some("US"), Some("CA"), Some("US")])),
            ],
        );
    }

    fn write_schema_drift_dataset(temp: &TempDir) {
        for name in ["part-000.parquet", "part-001.parquet"] {
            write_parquet(
                &temp.path().join(name),
                Arc::new(Schema::new(vec![Field::new(
                    "user_id",
                    DataType::Int64,
                    false,
                )])),
                vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
            );
        }
        write_parquet(
            &temp.path().join("part-002.parquet"),
            Arc::new(Schema::new(vec![Field::new(
                "user_id",
                DataType::Utf8,
                false,
            )])),
            vec![Arc::new(StringArray::from(vec![Some("1"), Some("2")]))],
        );
    }

    fn test_cli() -> Cli {
        Cli {
            command: Commands::Version,
            json: false,
            agent: false,
            format: OutputFormat::Text,
            details: Details::Summary,
            max_files: 1000,
            max_findings: 20,
            max_example_files: 5,
            max_columns: 80,
            timeout: Some("60s".to_string()),
            fail_on: None,
            severity_threshold: Severity::Warning,
            null_spike_ratio: 0.95,
            row_count_skew_factor: 8.0,
            minmax_outlier_factor: 100.0,
            no_color: false,
            quiet: false,
            verbose: false,
            region: None,
            profile: None,
            endpoint_url: None,
            requester_pays: false,
            max_requests: 2000,
            max_bytes: 64 * 1024 * 1024,
            s3_concurrency: 16,
        }
    }

    fn scrub_temp_path(output: &str, temp: &TempDir) -> String {
        output.replace(temp.path().to_str().unwrap(), "$TMP")
    }

    fn assert_golden(name: &str, actual: &str) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("golden")
            .join(name);
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        assert_eq!(actual, expected, "golden mismatch for {}", path.display());
    }
}
