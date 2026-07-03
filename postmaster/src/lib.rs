//! postmaster library.
//!
//! The bulk of the logic lives in the submodules so that unit tests can
//! exercise key loading, resolution, argument parsing, and serving logic
//! without going through main().
//!
//! Security and fail-closed semantics are preserved exactly.

#![allow(missing_docs, missing_debug_implementations)]

pub mod config;
pub mod keys;
pub mod server;

pub use config::{Invocation, USAGE, parse_args};
pub use server::{fetch, harden_process, run};

/// Re-exported for binary use. The real main is here so tests can call into it.
pub fn main() -> std::process::ExitCode {
    harden_process();
    let result = match parse_args() {
        Ok(Invocation::Serve(args)) => run(&args),
        Ok(Invocation::Fetch(path)) => fetch(&path),
        Err(e) => Err(e),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            server::log(&e);
            std::process::ExitCode::FAILURE
        }
    }
}
