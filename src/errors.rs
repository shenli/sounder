use std::fmt;

#[derive(Debug)]
pub(crate) struct ExitError {
    pub(crate) code: i32,
    message: String,
    error_type: Option<&'static str>,
}

impl ExitError {
    pub(crate) fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            error_type: None,
        }
    }

    pub(crate) fn with_type(
        code: i32,
        error_type: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            error_type: Some(error_type),
        }
    }

    pub(crate) fn error_type(&self) -> Option<&'static str> {
        self.error_type
    }
}

impl fmt::Display for ExitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for ExitError {}

pub(crate) fn error_type_for_exit_code(exit_code: i32) -> &'static str {
    match exit_code {
        2 => "invalid_arguments",
        3 => "input_not_found",
        4 => "unreadable_file",
        5 => "s3_permission_error",
        6 => "scan_truncated",
        _ => "internal_error",
    }
}

pub(crate) fn error_type_for_failure(err: &anyhow::Error, exit_code: i32) -> &'static str {
    err.downcast_ref::<ExitError>()
        .and_then(ExitError::error_type)
        .unwrap_or_else(|| error_type_for_exit_code(exit_code))
}

pub(crate) fn suggested_action_for_error_type(error_type: &str) -> &'static str {
    match error_type {
        "invalid_arguments" => "Check the command syntax and flag values.",
        "input_not_found" => {
            "Check that the input path or S3 URI exists and contains Parquet files."
        }
        "unreadable_file" => "Check that the input is a valid readable Parquet file.",
        "s3_permission_error" => {
            "Check AWS credentials, bucket policy, region, profile, or endpoint URL."
        }
        "scan_truncated" => {
            "Increase configured limits only after confirming the scan scope is expected."
        }
        _ => "Rerun with --verbose and report the error if it persists.",
    }
}

pub(crate) fn recoverable_for_error_type(error_type: &str, exit_code: i32) -> bool {
    !matches!(
        (error_type, exit_code),
        ("corrupt_metadata", _) | ("unreadable_file", _) | ("internal_error", _) | (_, 7)
    )
}
