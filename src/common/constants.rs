// -- EXECUTOR CONSTANTS --
pub const EXECUTOR_BASH: &str = "bash";
pub const EXECUTOR_CMD: &str = "cmd";
pub const EXECUTOR_POWERSHELL: &str = "powershell";
#[cfg(unix)]
pub const EXECUTOR_PSH: &str = "psh";
#[cfg(windows)]
pub const EXECUTOR_PWSH: &str = "pwsh";
pub const EXECUTOR_SH: &str = "sh";

// -- EXECUTION STATUS CONSTANTS --
// Info
pub const STATUS_INFO: &str = "INFO";
// Success
pub const STATUS_SUCCESS: &str = "SUCCESS";
pub const STATUS_WARNING: &str = "WARNING";
pub const STATUS_ACCESS_DENIED: &str = "ACCESS_DENIED";
// Error
pub const STATUS_ERROR: &str = "ERROR";
pub const STATUS_COMMAND_NOT_FOUND: &str = "COMMAND_NOT_FOUND";
pub const STATUS_COMMAND_CANNOT_BE_EXECUTED: &str = "COMMAND_CANNOT_BE_EXECUTED";
pub const STATUS_INVALID_USAGE: &str = "INVALID_USAGE";
pub const STATUS_TIMEOUT: &str = "TIMEOUT";
pub const STATUS_INTERRUPTED: &str = "INTERRUPTED";
