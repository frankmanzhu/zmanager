//! Offline-build stub for the `auth` command surface.
//!
//! A binary compiled with `--no-default-features` has no online identity
//! code at all, but `zm auth` must still be discoverable (it is listed in
//! the usage) and fail with a clear pointer to the full build instead of an
//! "unknown command" error.

use crate::cli::options::GlobalOptions;
use crate::cli::usage::print_error_line;
use std::process::ExitCode;

pub(crate) fn auth_command(_args: &[String], _global: GlobalOptions) -> ExitCode {
    hosted_command(&[], GlobalOptions::default())
}

pub(crate) fn hosted_command(_args: &[String], _global: GlobalOptions) -> ExitCode {
    #[cfg(unix)]
    let install_hint = "  curl -fsSL https://raw.githubusercontent.com/tzap-org/zmanager/main/install.sh | sh";
    #[cfg(windows)]
    let install_hint = "  https://github.com/tzap-org/zmanager/releases/latest";
    #[cfg(not(any(unix, windows)))]
    let install_hint = "  https://github.com/tzap-org/zmanager/releases/latest";

    print_error_line(
        &GlobalOptions::default(),
        format_args!("auth: this build does not include online identity features.\nInstall the full build:\n{install_hint}"),
    );
    ExitCode::FAILURE
}
