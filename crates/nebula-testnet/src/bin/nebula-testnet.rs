use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }

    let wants_json = args.iter().any(|arg| arg == "--json");
    let wants_readiness = args.iter().any(|arg| arg == "--mainnet-readiness");
    let wants_sample_attestation = args
        .iter()
        .any(|arg| arg == "--sample-deployment-attestation");

    if wants_sample_attestation {
        println!(
            "{}",
            nebula_testnet::sample_deployment_attestation_json_pretty()
        );
    } else if let Some(path) = arg_value(&args, "--verify-deployment-attestation") {
        verify_attestation(path, wants_json);
    } else if wants_json || wants_readiness {
        println!("{}", nebula_testnet::readiness_json_pretty());
    } else {
        println!("{}", nebula_testnet::readiness_summary());
    }
}

fn arg_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == name)
        .map(|window| window[1].as_str())
}

fn verify_attestation(path: &str, wants_json: bool) {
    let input = match fs::read_to_string(path) {
        Ok(input) => input,
        Err(error) => {
            print_verification_error(wants_json, &[format!("failed to read {path}: {error}")]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_deployment_attestation_json(&input) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("verification report serializes")
                );
            } else {
                println!(
                    "Deployment attestation verified. Public launch gate can advance to {}.",
                    report.level
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_verification_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_verification_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn print_verification_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "public_launch_ready": false,
                "level": "public-launch-attestation-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Deployment attestation rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_help() {
    println!(
        "nebula-testnet\n\nUSAGE:\n    nebula-testnet [--mainnet-readiness] [--json]\n    nebula-testnet --sample-deployment-attestation\n    nebula-testnet --verify-deployment-attestation <path> [--json]\n\nOPTIONS:\n    --mainnet-readiness              Emit the public launch readiness contract\n    --sample-deployment-attestation  Emit a fillable deployment attestation sample\n    --verify-deployment-attestation  Verify a deployment attestation file\n    --json                           Emit JSON output\n    -h, --help                       Show this help"
    );
}
