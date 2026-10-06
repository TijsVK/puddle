// SPDX-License-Identifier: GPL-3.0-or-later
//! `puddle doctor [--json] [--no-boot]`: checks this machine's prerequisites and what can get in
//! the way, with the exact fix for each problem ([`puddle_doctor`]). Exit code 0 when nothing
//! failed, 1 when something must be fixed first, so scripts can gate on it.

use std::process::ExitCode;

use puddle_doctor::{Options, Probe, Report, SystemProbe, diagnose};

use crate::cli::{Command, UsageError};

/// How `puddle doctor` should report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DoctorArgs {
    /// Print JSON (with `schema_version`) instead of text.
    pub json: bool,
    /// Skip the test boot.
    pub no_boot: bool,
}

/// Parses the arguments after `doctor`: `--json` and `--no-boot`, each at most once.
///
/// # Errors
///
/// [`UsageError::UnknownArgument`] for anything else or a repeated flag.
pub fn parse<I, S>(args: I) -> Result<Command, UsageError>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    let mut parsed = DoctorArgs::default();
    for arg in args {
        let flag = match arg.as_ref() {
            "--json" => &mut parsed.json,
            "--no-boot" => &mut parsed.no_boot,
            other => return Err(UsageError::UnknownArgument(other.to_owned())),
        };
        if *flag {
            return Err(UsageError::UnknownArgument(arg.as_ref().to_owned()));
        }
        *flag = true;
    }
    Ok(Command::Doctor(parsed))
}

/// Runs the checks on this machine against the runtime next to this program and prints the
/// report.
#[must_use]
#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the report is the command's output"
)]
pub fn run(args: DoctorArgs) -> ExitCode {
    let probe = match std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|exe| SystemProbe::installed(&exe).map_err(|e| e.to_string()))
    {
        Ok(probe) => probe,
        Err(e) => {
            eprintln!("puddle: can't find puddle's own folder: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (output, code) = report(&probe, args);
    print!("{output}");
    code
}

/// The report on `probe` as the text to print and the exit code.
pub(crate) fn report(probe: &dyn Probe, args: DoctorArgs) -> (String, ExitCode) {
    let options = Options {
        boot: !args.no_boot,
        ..Options::default()
    };
    let report = diagnose(probe, &options, puddle_types::VERSION);
    (render(&report, args.json), exit_code(&report))
}

fn render(report: &Report, json: bool) -> String {
    if json {
        format!("{}\n", report.to_json())
    } else {
        report.to_text()
    }
}

fn exit_code(report: &Report) -> ExitCode {
    if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use puddle_doctor::{
        BootFacts, CodeIntegrity, GsaFacts, HypervisorApi, HypervisorFacts, JobFacts, Os,
        ProcessOutcome, RuntimeFacts, RuntimeState,
    };

    use super::*;
    use crate::cli;

    struct Fake {
        runtime_ready: bool,
    }

    impl Probe for Fake {
        fn os(&self) -> Os {
            Os::Linux
        }
        fn arch(&self) -> String {
            "x86_64".into()
        }
        fn hypervisor(&self) -> HypervisorFacts {
            HypervisorFacts {
                api: HypervisorApi::Ready,
                firmware_virtualization: Some(true),
                hypervisor_vendor: None,
            }
        }
        fn code_integrity(&self) -> Option<CodeIntegrity> {
            None
        }
        fn runtime(&self) -> RuntimeFacts {
            RuntimeFacts {
                dir: PathBuf::from("/opt/puddle/runtime"),
                msb: PathBuf::from("/opt/puddle/runtime/msb"),
                expected: "0.7.7-puddle.2".into(),
                state: if self.runtime_ready {
                    RuntimeState::Ready {
                        version: "0.7.7-puddle.2".into(),
                        overridden: false,
                    }
                } else {
                    RuntimeState::Unusable(puddle_runtime_missing())
                },
            }
        }
        fn launch(&self, _limit: Duration) -> ProcessOutcome {
            ProcessOutcome::Exited {
                code: Some(0),
                stdout_first_line: "msb 0.7.7-puddle.2".into(),
                stderr_tail: String::new(),
                elapsed: Duration::from_millis(50),
            }
        }
        fn boot(&self, _limit: Duration) -> BootFacts {
            BootFacts::Ran {
                outcome: ProcessOutcome::Exited {
                    code: Some(puddle_doctor::PROBE_EXIT_CODE),
                    stdout_first_line: String::new(),
                    stderr_tail: String::new(),
                    elapsed: Duration::from_millis(900),
                },
                retried: false,
            }
        }
        fn job(&self) -> Option<JobFacts> {
            None
        }
        fn global_secure_access(&self) -> Option<GsaFacts> {
            None
        }
    }

    fn puddle_runtime_missing() -> puddle_doctor::RuntimeError {
        puddle_doctor::RuntimeError::Missing {
            path: PathBuf::from("/opt/puddle/runtime/msb"),
        }
    }

    #[test]
    fn flags() {
        assert_eq!(
            cli::parse(["doctor"]),
            Ok(Command::Doctor(DoctorArgs::default()))
        );
        assert_eq!(
            cli::parse(["doctor", "--no-boot", "--json"]),
            Ok(Command::Doctor(DoctorArgs {
                json: true,
                no_boot: true
            }))
        );
        assert_eq!(
            cli::parse(["doctor", "--json", "--json"]),
            Err(UsageError::UnknownArgument("--json".into()))
        );
        assert_eq!(
            cli::parse(["doctor", "--fix"]),
            Err(UsageError::UnknownArgument("--fix".into()))
        );
    }

    #[test]
    fn healthy_text_report_exits_zero() {
        let (text, code) = report(
            &Fake {
                runtime_ready: true,
            },
            DoctorArgs::default(),
        );
        assert!(text.starts_with("puddle doctor (puddle "), "{text}");
        assert!(text.contains("No problems found."), "{text}");
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn json_report_with_a_failure_exits_one() {
        let args = DoctorArgs {
            json: true,
            no_boot: true,
        };
        let (json, code) = report(
            &Fake {
                runtime_ready: false,
            },
            args,
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["schema_version"], puddle_doctor::SCHEMA_VERSION);
        assert_eq!(v["ok"], false);
        let runtime = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "runtime")
            .unwrap();
        assert_eq!(runtime["finding"], "runtime_missing");
        assert!(json.ends_with("}\n"));
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[test]
    fn no_boot_skips_the_test_boot() {
        let args = DoctorArgs {
            json: false,
            no_boot: true,
        };
        let (text, _) = report(
            &Fake {
                runtime_ready: true,
            },
            args,
        );
        assert!(text.contains("not checked: --no-boot"), "{text}");
    }
}
