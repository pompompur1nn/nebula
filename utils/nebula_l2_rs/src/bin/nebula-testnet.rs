use std::env;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }

    let wants_json = args.iter().any(|arg| arg == "--json");
    let wants_readiness = args.iter().any(|arg| arg == "--mainnet-readiness");

    if wants_json || wants_readiness {
        println!("{}", nebula_l2_rs::readiness_json_pretty());
    } else {
        println!("{}", nebula_l2_rs::readiness_summary());
    }
}

fn print_help() {
    println!(
        "nebula-testnet\n\nUSAGE:\n    nebula-testnet [--mainnet-readiness] [--json]\n\nOPTIONS:\n    --mainnet-readiness  Emit the public launch readiness contract\n    --json               Emit JSON output\n    -h, --help           Show this help"
    );
}
