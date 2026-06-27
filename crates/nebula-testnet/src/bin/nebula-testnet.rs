use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256};
use x509_parser::prelude::parse_x509_certificate;

const DEFAULT_PUBLIC_CAPTURE_TIMEOUT_MS: u64 = 5_000;
const MAX_PUBLIC_CAPTURE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return;
    }

    let wants_json = args.iter().any(|arg| arg == "--json");
    let wants_readiness = args.iter().any(|arg| arg == "--mainnet-readiness");
    let wants_prove_local_public_testnet =
        args.iter().any(|arg| arg == "--prove-local-public-testnet");
    let wants_prove_live_rpc_devnet = args.iter().any(|arg| arg == "--prove-live-rpc-devnet");
    let wants_sample_attestation = args
        .iter()
        .any(|arg| arg == "--sample-deployment-attestation");
    let wants_sample_validator_set = args.iter().any(|arg| arg == "--sample-validator-set");
    let wants_sample_operator_handoff = args.iter().any(|arg| arg == "--sample-operator-handoff");
    let wants_build_operator_handoff = args.iter().any(|arg| arg == "--build-operator-handoff");
    let wants_sample_operator_acceptance =
        args.iter().any(|arg| arg == "--sample-operator-acceptance");
    let wants_build_operator_acceptance =
        args.iter().any(|arg| arg == "--build-operator-acceptance");
    let wants_sample_genesis_manifest = args.iter().any(|arg| arg == "--sample-genesis-manifest");
    let wants_build_genesis_manifest = args.iter().any(|arg| arg == "--build-genesis-manifest");
    let wants_verify_launch_package = args.iter().any(|arg| arg == "--verify-launch-package");
    let wants_build_launch_package_bundle = args
        .iter()
        .any(|arg| arg == "--build-launch-package-bundle");
    let wants_build_public_testnet_peer_manifest = args
        .iter()
        .any(|arg| arg == "--build-public-testnet-peer-manifest");
    let wants_build_validator_activation =
        args.iter().any(|arg| arg == "--build-validator-activation");
    let wants_build_validator_join = args.iter().any(|arg| arg == "--build-validator-join");
    let wants_build_operator_join_confirmation = args
        .iter()
        .any(|arg| arg == "--build-operator-join-confirmation");
    let wants_build_public_observer_confirmation = args
        .iter()
        .any(|arg| arg == "--build-public-observer-confirmation");
    let wants_build_public_testnet_launch_certificate = args
        .iter()
        .any(|arg| arg == "--build-public-testnet-launch-certificate");
    let wants_build_public_status = args.iter().any(|arg| arg == "--build-public-status");
    let wants_build_public_probe = args.iter().any(|arg| arg == "--build-public-probe");
    let wants_build_runtime_surface_evidence = args
        .iter()
        .any(|arg| arg == "--build-runtime-surface-evidence");
    let wants_capture_public_runtime_surface = args
        .iter()
        .any(|arg| arg == "--capture-public-runtime-surface");
    let wants_build_live_rpc_devnet_runtime_surface = args
        .iter()
        .any(|arg| arg == "--build-live-rpc-devnet-runtime-surface");
    let wants_sign_bridge_observer_evidence = args
        .iter()
        .any(|arg| arg == "--sign-bridge-observer-evidence");
    let wants_assemble_bridge_deposit = args.iter().any(|arg| arg == "--assemble-bridge-deposit");
    let wants_sign_withdrawal_operator_approval = args
        .iter()
        .any(|arg| arg == "--sign-withdrawal-operator-approval");
    let wants_assemble_finalize_withdrawal = args
        .iter()
        .any(|arg| arg == "--assemble-finalize-withdrawal");
    let wants_sign_sequencer_rotation_approval = args
        .iter()
        .any(|arg| arg == "--sign-sequencer-rotation-approval");
    let wants_assemble_sequencer_rotation = args
        .iter()
        .any(|arg| arg == "--assemble-sequencer-rotation");
    let wants_build_deployment_attestation = args
        .iter()
        .any(|arg| arg == "--build-deployment-attestation");
    let wants_sample_public_status = args.iter().any(|arg| arg == "--sample-public-status");
    let wants_sample_public_probe = args.iter().any(|arg| arg == "--sample-public-probe");
    let wants_sample_preflight_receipt = args.iter().any(|arg| arg == "--sample-preflight-receipt");
    let wants_sample_runbook_receipt = args.iter().any(|arg| arg == "--sample-runbook-receipt");
    let wants_run_rpc = args.iter().any(|arg| arg == "--run-rpc");

    if wants_run_rpc {
        run_rpc_node(&args, wants_json);
    } else if wants_prove_local_public_testnet {
        prove_local_public_testnet(wants_json);
    } else if wants_prove_live_rpc_devnet {
        prove_live_rpc_devnet(&args, wants_json);
    } else if wants_build_public_status {
        build_public_status(&args, wants_json);
    } else if wants_build_public_probe {
        build_public_probe(&args, wants_json);
    } else if wants_build_runtime_surface_evidence {
        build_runtime_surface_evidence(&args, wants_json);
    } else if wants_capture_public_runtime_surface {
        capture_public_runtime_surface(&args, wants_json);
    } else if wants_build_live_rpc_devnet_runtime_surface {
        build_live_rpc_devnet_runtime_surface(&args, wants_json);
    } else if wants_sign_bridge_observer_evidence {
        sign_bridge_observer_evidence(&args, wants_json);
    } else if wants_assemble_bridge_deposit {
        assemble_bridge_deposit(&args, wants_json);
    } else if wants_sign_withdrawal_operator_approval {
        sign_withdrawal_operator_approval(&args, wants_json);
    } else if wants_assemble_finalize_withdrawal {
        assemble_finalize_withdrawal(&args, wants_json);
    } else if wants_sign_sequencer_rotation_approval {
        sign_sequencer_rotation_approval(&args, wants_json);
    } else if wants_assemble_sequencer_rotation {
        assemble_sequencer_rotation(&args, wants_json);
    } else if wants_build_deployment_attestation {
        build_deployment_attestation(&args, wants_json);
    } else if wants_sample_attestation {
        println!(
            "{}",
            nebula_testnet::sample_deployment_attestation_json_pretty()
        );
    } else if wants_sample_validator_set {
        println!("{}", nebula_testnet::sample_validator_set_json_pretty());
    } else if wants_sample_operator_handoff {
        println!("{}", nebula_testnet::sample_operator_handoff_json_pretty());
    } else if wants_sample_operator_acceptance {
        println!(
            "{}",
            nebula_testnet::sample_operator_acceptance_json_pretty()
        );
    } else if wants_sample_genesis_manifest {
        println!("{}", nebula_testnet::sample_genesis_manifest_json_pretty());
    } else if wants_sample_public_status {
        println!(
            "{}",
            nebula_testnet::sample_public_status_manifest_json_pretty()
        );
    } else if wants_sample_public_probe {
        println!("{}", nebula_testnet::sample_public_probe_json_pretty());
    } else if wants_sample_preflight_receipt {
        println!("{}", nebula_testnet::sample_preflight_receipt_json_pretty());
    } else if wants_sample_runbook_receipt {
        println!("{}", nebula_testnet::sample_runbook_receipt_json_pretty());
    } else if let Some(path) = arg_value(&args, "--verify-deployment-attestation") {
        verify_attestation(path, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-public-status") {
        verify_public_status(path, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-public-probe") {
        verify_public_probe(path, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-runtime-surface-evidence") {
        verify_runtime_surface_evidence(path, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-preflight-receipt") {
        verify_preflight_receipt(path, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-runbook-receipt") {
        verify_runbook_receipt(path, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-validator-set") {
        verify_validator_set(path, wants_json);
    } else if wants_build_operator_handoff {
        build_operator_handoff(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-operator-handoff") {
        verify_operator_handoff(path, &args, wants_json);
    } else if wants_build_operator_acceptance {
        build_operator_acceptance(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-operator-acceptance") {
        verify_operator_acceptance(path, &args, wants_json);
    } else if wants_build_genesis_manifest {
        build_genesis_manifest(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-genesis-manifest") {
        verify_genesis_manifest(path, wants_json);
    } else if wants_verify_launch_package {
        verify_launch_package(&args, wants_json);
    } else if wants_build_launch_package_bundle {
        build_launch_package_bundle(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-launch-package-bundle") {
        verify_launch_package_bundle(path, &args, wants_json);
    } else if wants_build_public_testnet_peer_manifest {
        build_public_testnet_peer_manifest(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-public-testnet-peer-manifest") {
        verify_public_testnet_peer_manifest(path, &args, wants_json);
    } else if wants_build_validator_activation {
        build_validator_activation(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-validator-activation") {
        verify_validator_activation(path, &args, wants_json);
    } else if wants_build_validator_join {
        build_validator_join(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-validator-join") {
        verify_validator_join(path, &args, wants_json);
    } else if wants_build_operator_join_confirmation {
        build_operator_join_confirmation(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-operator-join-confirmation") {
        verify_operator_join_confirmation(path, &args, wants_json);
    } else if wants_build_public_observer_confirmation {
        build_public_observer_confirmation(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-public-observer-confirmation") {
        verify_public_observer_confirmation(path, &args, wants_json);
    } else if wants_build_public_testnet_launch_certificate {
        build_public_testnet_launch_certificate(&args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-public-testnet-launch-certificate") {
        verify_public_testnet_launch_certificate(path, &args, wants_json);
    } else if let Some(path) = arg_value(&args, "--verify-public-testnet-launch-readiness") {
        verify_public_testnet_launch_readiness(path, &args, wants_json);
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

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|window| window[0] == name)
        .map(|window| window[1].clone())
        .collect()
}

fn current_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before UNIX_EPOCH")
        .as_millis()
}

fn parse_u128_arg(args: &[String], name: &str, default: u128) -> u128 {
    match arg_value(args, name) {
        Some(value) => value.parse::<u128>().unwrap_or_else(|error| {
            eprintln!("{name} must be an unsigned integer: {error}");
            process::exit(1);
        }),
        None => default,
    }
}

fn parse_u64_arg(args: &[String], name: &str, default: u64) -> u64 {
    match arg_value(args, name) {
        Some(value) => value.parse::<u64>().unwrap_or_else(|error| {
            eprintln!("{name} must be an unsigned integer: {error}");
            process::exit(1);
        }),
        None => default,
    }
}

fn parse_usize_arg(args: &[String], name: &str, default: usize) -> usize {
    match arg_value(args, name) {
        Some(value) => value.parse::<usize>().unwrap_or_else(|error| {
            eprintln!("{name} must be an unsigned integer: {error}");
            process::exit(1);
        }),
        None => default,
    }
}

fn parse_u32_arg(args: &[String], name: &str, default: u32) -> u32 {
    match arg_value(args, name) {
        Some(value) => value.parse::<u32>().unwrap_or_else(|error| {
            eprintln!("{name} must be an unsigned integer: {error}");
            process::exit(1);
        }),
        None => default,
    }
}

fn run_rpc_node(args: &[String], wants_json: bool) {
    let bind_addr =
        arg_value(args, "--rpc-bind").unwrap_or(nebula_testnet::runtime::DEFAULT_RPC_BIND_ADDR);
    let mut config = nebula_testnet::runtime::RuntimeConfig::public_testnet_default();
    config.block_target_ms = parse_u64_arg(
        args,
        "--block-ms",
        nebula_testnet::runtime::DEFAULT_SUBSECOND_BLOCK_MS,
    );
    if let Some(validator_id) = arg_value(args, "--validator-id") {
        config.validator_id = validator_id.to_string();
    }
    if let Some(sequencer_public_key) = arg_value(args, "--sequencer-public-key") {
        config.sequencer_public_key_hex = sequencer_public_key.to_string();
    }
    config.launch_binding = read_runtime_launch_binding(args, wants_json, &config.validator_id);
    if args.iter().any(|arg| arg == "--disable-nbla-faucet") {
        config.faucet_nbla_nebulai = 0;
    }
    config.max_mempool_transactions = parse_usize_arg(
        args,
        "--max-mempool-transactions",
        nebula_testnet::runtime::DEFAULT_MAX_MEMPOOL_TRANSACTIONS,
    );
    let wants_sequencer = args.iter().any(|arg| arg == "--sequencer");
    let wants_follower = args.iter().any(|arg| arg == "--follower");
    if wants_sequencer && wants_follower {
        eprintln!("--sequencer and --follower are mutually exclusive");
        process::exit(1);
    }
    config.produce_blocks = !wants_follower;
    let peer_manifest_binding = read_runtime_public_testnet_peer_manifest_binding(
        args,
        wants_json,
        &config.validator_id,
        wants_follower,
        config.launch_binding.as_ref(),
    );
    let max_request_bytes = parse_usize_arg(
        args,
        "--max-request-bytes",
        nebula_testnet::runtime::DEFAULT_MAX_REQUEST_BYTES,
    );
    let max_requests_per_minute = parse_u32_arg(
        args,
        "--max-requests-per-minute",
        nebula_testnet::runtime::DEFAULT_MAX_REQUESTS_PER_MINUTE,
    );
    let max_active_connections = parse_usize_arg(
        args,
        "--max-active-connections",
        nebula_testnet::runtime::DEFAULT_MAX_ACTIVE_CONNECTIONS,
    );
    let admin_max_active_connections = parse_usize_arg(
        args,
        "--admin-max-active-connections",
        nebula_testnet::runtime::DEFAULT_ADMIN_MAX_ACTIVE_CONNECTIONS,
    );
    let max_snapshot_response_bytes = parse_usize_arg(
        args,
        "--max-snapshot-response-bytes",
        nebula_testnet::runtime::DEFAULT_MAX_SNAPSHOT_RESPONSE_BYTES,
    );
    let trust_private_proxy_headers = args
        .iter()
        .any(|arg| arg == "--trust-private-proxy-headers");
    let trusted_proxy_ips = arg_values(args, "--trusted-proxy-ip");
    let explicit_sync_peer_quorum = arg_value(args, "--sync-peer-quorum").is_some();
    let mut sync_peer_quorum = parse_usize_arg(
        args,
        "--sync-peer-quorum",
        nebula_testnet::runtime::DEFAULT_SYNC_PEER_QUORUM,
    );
    let mut bootstrap_rpc_url = arg_value(args, "--bootstrap-rpc").map(str::to_string);
    let mut sync_rpc_urls = arg_values(args, "--sync-rpc");
    if let Some(binding) = &peer_manifest_binding {
        if explicit_sync_peer_quorum && sync_peer_quorum != binding.sync_peer_quorum {
            print_public_testnet_peer_manifest_error(
                wants_json,
                &[format!(
                    "--sync-peer-quorum {sync_peer_quorum} must match public testnet peer manifest quorum {}",
                    binding.sync_peer_quorum
                )],
            );
            process::exit(1);
        }
        sync_peer_quorum = binding.sync_peer_quorum;
        if wants_follower && sync_rpc_urls.is_empty() {
            sync_rpc_urls = binding.snapshot_peer_urls.clone();
        }
        if wants_follower && bootstrap_rpc_url.is_none() {
            bootstrap_rpc_url = sync_rpc_urls.first().cloned();
        }
    }
    let options = nebula_testnet::runtime::RuntimeNodeOptions {
        data_dir: arg_value(args, "--data-dir").map(str::to_string),
        bootstrap_rpc_url,
        sync_rpc_url: None,
        sync_rpc_urls,
        sync_peer_quorum,
        public_testnet_peer_manifest: peer_manifest_binding,
        auto_produce_blocks: true,
        sequencer_secret_key_hex: arg_value(args, "--sequencer-secret-key").map(str::to_string),
        admin_rpc_bind_addr: arg_value(args, "--admin-rpc-bind").map(str::to_string),
        admin_token: arg_value(args, "--admin-token").map(str::to_string),
        max_request_bytes,
        max_requests_per_minute,
        max_active_connections,
        admin_max_active_connections,
        max_snapshot_response_bytes,
        trust_private_proxy_headers,
        trusted_proxy_ips,
    };

    if let Err(error) = config.validate() {
        eprintln!("Nebula RPC config rejected: {error}");
        process::exit(1);
    }

    eprintln!(
        "Nebula public RPC listening on {bind_addr}; block target {} ms; validator {}; role {}; sequencer key {}; admin rpc {}; NBLA faucet {}; sync quorum {}; max mempool {} txs; max request {} bytes; max snapshot response {} bytes; client identity {}; trusted proxy IPs {}; rate limit {} requests/min per listener; public active connection cap {}; admin active connection cap {}",
        config.block_target_ms,
        config.validator_id,
        if config.produce_blocks {
            "sequencer"
        } else {
            "follower"
        },
        config.sequencer_public_key_hex,
        if options.admin_rpc_bind_addr.is_some() && options.admin_token.is_some() {
            "enabled"
        } else {
            "disabled"
        },
        if config.faucet_nbla_nebulai == 0 {
            "disabled".to_string()
        } else {
            format!("{} nebulai/call", config.faucet_nbla_nebulai)
        },
        options.sync_peer_quorum,
        config.max_mempool_transactions,
        options.max_request_bytes,
        options.max_snapshot_response_bytes,
        if !options.trusted_proxy_ips.is_empty() {
            "trusted-proxy"
        } else if options.trust_private_proxy_headers {
            "private-proxy-dev"
        } else {
            "tcp-peer"
        },
        options.trusted_proxy_ips.len(),
        options.max_requests_per_minute,
        options.max_active_connections,
        options.admin_max_active_connections
    );
    if let Some(admin_bind_addr) = &options.admin_rpc_bind_addr {
        eprintln!("Nebula private admin RPC listening on {admin_bind_addr}");
    }
    if let Some(peer_manifest) = &options.public_testnet_peer_manifest {
        eprintln!(
            "Nebula public testnet peer manifest binding enabled; root {}; usable snapshot peers {}; sync quorum {}",
            peer_manifest.public_testnet_peer_manifest_root,
            peer_manifest.snapshot_peer_urls.len(),
            peer_manifest.sync_peer_quorum
        );
    }
    if let Some(binding) = &config.launch_binding {
        eprintln!(
            "Nebula RPC launch binding enabled; endpoint {}; bundle root {}",
            binding.endpoint_url, binding.launch_package_bundle_root
        );
    } else {
        eprintln!(
            "Nebula RPC launch binding disabled; public ops readiness will report missing-launch-package-binding"
        );
    }
    if let Err(error) =
        nebula_testnet::runtime::serve_runtime_rpc_with_options(bind_addr, config, options)
    {
        eprintln!("Nebula RPC failed: {error}");
        process::exit(1);
    }
}

fn read_runtime_launch_binding(
    args: &[String],
    wants_json: bool,
    validator_id: &str,
) -> Option<nebula_testnet::runtime::RuntimeLaunchBinding> {
    const RUNTIME_LAUNCH_BINDING_FLAGS: &[&str] = &[
        "--deployment-attestation",
        "--public-status",
        "--public-probe",
        "--validator-set",
        "--operator-handoff",
        "--operator-acceptance",
        "--genesis-manifest",
        "--launch-package-bundle",
    ];
    if !args
        .iter()
        .any(|arg| RUNTIME_LAUNCH_BINDING_FLAGS.contains(&arg.as_str()))
    {
        return None;
    }

    let inputs = read_launch_package_inputs(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    match nebula_testnet::build_runtime_launch_binding_from_jsons(
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
        &bundle_input,
        validator_id,
    ) {
        Ok(binding) => Some(binding),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_runtime_launch_binding_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_runtime_launch_binding_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn read_runtime_public_testnet_peer_manifest_binding(
    args: &[String],
    wants_json: bool,
    validator_id: &str,
    require_validator_peer: bool,
    launch_binding: Option<&nebula_testnet::runtime::RuntimeLaunchBinding>,
) -> Option<nebula_testnet::runtime::RuntimePublicTestnetPeerManifestBinding> {
    let path = arg_value(args, "--public-testnet-peer-manifest")?;
    let peer_manifest_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_testnet_peer_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);
    let report = match nebula_testnet::verify_public_testnet_peer_manifest_jsons(
        &peer_manifest_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => report,
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_testnet_peer_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_testnet_peer_manifest_error(wants_json, &errors);
            process::exit(1);
        }
    };
    if let Some(launch_binding) = launch_binding {
        if !report
            .launch_package_bundle_root
            .eq_ignore_ascii_case(&launch_binding.launch_package_bundle_root)
        {
            print_public_testnet_peer_manifest_error(
                wants_json,
                &[format!(
                    "public testnet peer manifest bundle root {} does not match runtime launch binding bundle root {}",
                    report.launch_package_bundle_root,
                    launch_binding.launch_package_bundle_root
                )],
            );
            process::exit(1);
        }
    }
    let manifest = serde_json::from_str::<nebula_testnet::PublicTestnetPeerManifest>(
        peer_manifest_input.trim_start_matches('\u{feff}'),
    )
    .unwrap_or_else(|error| {
        print_public_testnet_peer_manifest_error(
            wants_json,
            &[format!(
                "invalid --public-testnet-peer-manifest JSON: {error}"
            )],
        );
        process::exit(1);
    });
    let validator_peer_present = manifest
        .peers
        .iter()
        .any(|peer| peer.validator_id.eq_ignore_ascii_case(validator_id));
    if require_validator_peer && !validator_peer_present {
        print_public_testnet_peer_manifest_error(
            wants_json,
            &[format!(
                "--validator-id {validator_id} must appear in --public-testnet-peer-manifest peers for follower sync"
            )],
        );
        process::exit(1);
    }
    let snapshot_peer_urls = manifest
        .peers
        .iter()
        .filter(|peer| !peer.validator_id.eq_ignore_ascii_case(validator_id))
        .map(|peer| peer.snapshot_url.clone())
        .collect::<Vec<_>>();
    if snapshot_peer_urls.is_empty() {
        print_public_testnet_peer_manifest_error(
            wants_json,
            &[format!(
                "--public-testnet-peer-manifest must include at least one snapshot peer besides validator_id {validator_id}"
            )],
        );
        process::exit(1);
    }
    if report.sync_peer_quorum > snapshot_peer_urls.len() {
        print_public_testnet_peer_manifest_error(
            wants_json,
            &[format!(
                "public testnet peer manifest quorum {} exceeds usable snapshot peer count {} after excluding validator_id {validator_id}",
                report.sync_peer_quorum,
                snapshot_peer_urls.len()
            )],
        );
        process::exit(1);
    }
    Some(
        nebula_testnet::runtime::RuntimePublicTestnetPeerManifestBinding {
            public_testnet_peer_manifest_root: report.public_testnet_peer_manifest_root,
            launch_package_bundle_root: report.launch_package_bundle_root,
            snapshot_peer_urls,
            sync_peer_quorum: report.sync_peer_quorum,
        },
    )
}

fn read_text_file(path: &str) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?;

    if bytes.starts_with(&[0xff, 0xfe]) {
        return decode_utf16_file(path, &bytes[2..], Endian::Little);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        return decode_utf16_file(path, &bytes[2..], Endian::Big);
    }

    String::from_utf8(bytes).map_err(|error| format!("failed to read {path}: {error}"))
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

struct LaunchPackageInputs {
    deployment_input: String,
    public_status_input: String,
    public_probe_input: String,
    validator_set_input: String,
    operator_handoff_input: String,
    operator_acceptance_input: String,
    genesis_input: String,
}

fn read_required_launch_package_input(args: &[String], name: &str, wants_json: bool) -> String {
    let Some(path) = arg_value(args, name) else {
        print_launch_package_error(wants_json, &[format!("missing {name} <path>")]);
        process::exit(1);
    };

    match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    }
}

fn read_required_deployment_builder_input(args: &[String], name: &str, wants_json: bool) -> String {
    let Some(path) = arg_value(args, name) else {
        print_deployment_attestation_builder_error(wants_json, &[format!("missing {name} <path>")]);
        process::exit(1);
    };

    match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_deployment_attestation_builder_error(wants_json, &[error]);
            process::exit(1);
        }
    }
}

fn read_required_runtime_surface_input(args: &[String], name: &str, wants_json: bool) -> String {
    let Some(path) = arg_value(args, name) else {
        print_runtime_surface_evidence_error(wants_json, &[format!("missing {name} <path>")]);
        process::exit(1);
    };

    match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
    }
}

fn read_required_bridge_json<T>(args: &[String], name: &str, wants_json: bool) -> T
where
    T: DeserializeOwned,
{
    let Some(path) = arg_value(args, name) else {
        print_bridge_evidence_error(wants_json, &[format!("missing {name} <path>")]);
        process::exit(1);
    };
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_bridge_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    serde_json::from_str::<T>(input.trim_start_matches('\u{feff}')).unwrap_or_else(|error| {
        print_bridge_evidence_error(wants_json, &[format!("invalid {name} JSON: {error}")]);
        process::exit(1);
    })
}

fn read_bridge_json_file<T>(path: &str, wants_json: bool) -> T
where
    T: DeserializeOwned,
{
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_bridge_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    serde_json::from_str::<T>(input.trim_start_matches('\u{feff}')).unwrap_or_else(|error| {
        print_bridge_evidence_error(
            wants_json,
            &[format!("invalid bridge evidence JSON: {error}")],
        );
        process::exit(1);
    })
}

fn required_bridge_arg(args: &[String], name: &str, wants_json: bool) -> String {
    let Some(value) = arg_value(args, name) else {
        print_bridge_evidence_error(wants_json, &[format!("missing {name} <value>")]);
        process::exit(1);
    };
    value.to_string()
}

fn required_bridge_u64_arg(args: &[String], name: &str, wants_json: bool) -> u64 {
    let value = required_bridge_arg(args, name, wants_json);
    value.parse::<u64>().unwrap_or_else(|error| {
        print_bridge_evidence_error(
            wants_json,
            &[format!("{name} must be an unsigned integer: {error}")],
        );
        process::exit(1);
    })
}

fn read_launch_package_inputs(args: &[String], wants_json: bool) -> LaunchPackageInputs {
    LaunchPackageInputs {
        deployment_input: read_required_launch_package_input(
            args,
            "--deployment-attestation",
            wants_json,
        ),
        public_status_input: read_required_launch_package_input(
            args,
            "--public-status",
            wants_json,
        ),
        public_probe_input: read_required_launch_package_input(args, "--public-probe", wants_json),
        validator_set_input: read_required_launch_package_input(
            args,
            "--validator-set",
            wants_json,
        ),
        operator_handoff_input: read_required_launch_package_input(
            args,
            "--operator-handoff",
            wants_json,
        ),
        operator_acceptance_input: read_required_launch_package_input(
            args,
            "--operator-acceptance",
            wants_json,
        ),
        genesis_input: read_required_launch_package_input(args, "--genesis-manifest", wants_json),
    }
}

fn read_launch_package_bundle_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--launch-package-bundle", wants_json)
}

fn read_validator_activation_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--validator-activation", wants_json)
}

fn read_validator_join_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--validator-join", wants_json)
}

fn read_operator_join_confirmation_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--operator-join-confirmation", wants_json)
}

fn read_public_observer_confirmation_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--public-observer-confirmation", wants_json)
}

fn read_runtime_surface_evidence_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--runtime-surface-evidence", wants_json)
}

fn read_live_rpc_devnet_rehearsal_input(args: &[String], wants_json: bool) -> String {
    read_required_launch_package_input(args, "--live-rpc-devnet-rehearsal", wants_json)
}

fn read_live_rpc_devnet_runtime_surface_evidence_input(
    args: &[String],
    wants_json: bool,
) -> String {
    read_required_launch_package_input(
        args,
        "--live-rpc-devnet-runtime-surface-evidence",
        wants_json,
    )
}

fn decode_utf16_file(path: &str, bytes: &[u8], endian: Endian) -> Result<String, String> {
    let chunks = bytes.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return Err(format!("failed to read {path}: odd-length UTF-16 input"));
    }

    let units = chunks
        .map(|chunk| match endian {
            Endian::Little => u16::from_le_bytes([chunk[0], chunk[1]]),
            Endian::Big => u16::from_be_bytes([chunk[0], chunk[1]]),
        })
        .collect::<Vec<_>>();

    String::from_utf16(&units).map_err(|error| format!("failed to read {path}: {error}"))
}

fn prove_local_public_testnet(wants_json: bool) {
    match nebula_testnet::prove_local_public_testnet_rehearsal() {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("rehearsal report serializes")
                );
            } else {
                println!(
                    "{} local_public_testnet_rehearsed={} public_launch_ready={} public_launch_blocker={} verified_artifacts={} rehearsal_root={} public_testnet_launch_certificate_root={}",
                    report.level,
                    report.local_public_testnet_rehearsed,
                    report.public_launch_ready,
                    report.public_launch_blocker,
                    report.verified_artifact_count,
                    report.rehearsal_root,
                    report.public_testnet_launch_certificate_root
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

fn prove_live_rpc_devnet(args: &[String], wants_json: bool) {
    const ARTIFACT_BOUND_REHEARSAL_FLAGS: &[&str] = &[
        "--deployment-attestation",
        "--public-status",
        "--public-probe",
        "--validator-set",
        "--operator-handoff",
        "--operator-acceptance",
        "--genesis-manifest",
        "--launch-package-bundle",
    ];
    let result = if args
        .iter()
        .any(|arg| ARTIFACT_BOUND_REHEARSAL_FLAGS.contains(&arg.as_str()))
    {
        let inputs = read_launch_package_inputs(args, wants_json);
        let bundle_input = read_launch_package_bundle_input(args, wants_json);
        nebula_testnet::prove_live_rpc_devnet_rehearsal_with_jsons_and_evidence(
            &bundle_input,
            &inputs.deployment_input,
            &inputs.public_status_input,
            &inputs.public_probe_input,
            &inputs.validator_set_input,
            &inputs.operator_handoff_input,
            &inputs.operator_acceptance_input,
            &inputs.genesis_input,
        )
    } else {
        nebula_testnet::prove_live_rpc_devnet_rehearsal_with_evidence()
    };

    match result {
        Ok((report, evidence)) => {
            if let Some(path) = arg_value(args, "--live-rpc-devnet-runtime-surface-out") {
                let evidence_json = serde_json::to_string_pretty(&evidence)
                    .expect("live RPC runtime surface evidence serializes");
                if let Err(error) = fs::write(path, evidence_json) {
                    print_verification_error(
                        wants_json,
                        &[format!(
                            "failed to write --live-rpc-devnet-runtime-surface-out {path}: {error}"
                        )],
                    );
                    process::exit(1);
                }
            }
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("live RPC rehearsal report serializes")
                );
            } else {
                println!(
                    "{} live_rpc_devnet_rehearsed={} public_launch_ready={} public_launch_blocker={} block_millis={} produced_block_count={} runtime_surface_root={} rehearsal_root={}",
                    report.level,
                    report.live_rpc_devnet_rehearsed,
                    report.public_launch_ready,
                    report.public_launch_blocker,
                    report.block_millis,
                    report.produced_block_count,
                    report.runtime_surface_root,
                    report.rehearsal_root
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

fn build_public_status(args: &[String], wants_json: bool) {
    let Some(endpoint_url) = arg_value(args, "--endpoint-url") else {
        print_public_status_error(wants_json, &["missing --endpoint-url <url>".to_string()]);
        process::exit(1);
    };
    let input = public_surface_build_input(args, endpoint_url);
    match nebula_testnet::build_public_status_manifest_json_pretty(input) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_status_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_status_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_public_probe(args: &[String], wants_json: bool) {
    let Some(endpoint_url) = arg_value(args, "--endpoint-url") else {
        print_public_probe_error(wants_json, &["missing --endpoint-url <url>".to_string()]);
        process::exit(1);
    };
    let input = public_surface_build_input(args, endpoint_url);
    match nebula_testnet::build_public_probe_json_pretty(input) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_probe_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_probe_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_runtime_surface_evidence(args: &[String], wants_json: bool) {
    let Some(endpoint_url) = arg_value(args, "--endpoint-url") else {
        print_runtime_surface_evidence_error(
            wants_json,
            &["missing --endpoint-url <url>".to_string()],
        );
        process::exit(1);
    };
    let input = nebula_testnet::RuntimeSurfaceEvidenceBuildInput {
        endpoint_url: endpoint_url.to_string(),
        capture_mode: nebula_testnet::RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT
            .to_string(),
        tls_observation: parse_runtime_surface_tls_observation(args, wants_json),
        captured_at_unix_ms: parse_u128_arg(args, "--captured-at-unix-ms", current_unix_ms()),
        health_json: read_required_runtime_surface_input(args, "--health", wants_json),
        status_json: read_required_runtime_surface_input(args, "--status", wants_json),
        snapshot_json: read_required_runtime_surface_input(args, "--snapshot", wants_json),
        ops_json: read_required_runtime_surface_input(args, "--ops", wants_json),
        backup_json: read_required_runtime_surface_input(args, "--backup", wants_json),
        rpc_status_json: read_required_runtime_surface_input(args, "--rpc-status", wants_json),
        rpc_ops_status_json: read_required_runtime_surface_input(
            args,
            "--rpc-ops-status",
            wants_json,
        ),
        rpc_backup_manifest_json: read_required_runtime_surface_input(
            args,
            "--rpc-backup-manifest",
            wants_json,
        ),
        metrics_text: read_required_runtime_surface_input(args, "--metrics", wants_json),
    };
    match nebula_testnet::build_runtime_surface_evidence_json_pretty(input) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_runtime_surface_evidence_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn capture_public_runtime_surface(args: &[String], wants_json: bool) {
    let deployment_attestation_json =
        read_required_public_capture_input(args, "--deployment-attestation", wants_json);
    match nebula_testnet::verify_deployment_attestation_json(&deployment_attestation_json) {
        Ok(_) => {}
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_runtime_surface_evidence_error(
                wants_json,
                &[format!("deployment attestation is malformed: {error}")],
            );
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_runtime_surface_evidence_error(wants_json, &errors);
            process::exit(1);
        }
    }
    let attestation = serde_json::from_str::<nebula_testnet::DeploymentAttestation>(
        deployment_attestation_json.trim_start_matches('\u{feff}'),
    )
    .unwrap_or_else(|error| {
        print_runtime_surface_evidence_error(
            wants_json,
            &[format!("deployment attestation is malformed: {error}")],
        );
        process::exit(1);
    });
    if let Some(endpoint_url) = arg_value(args, "--endpoint-url") {
        if endpoint_url != attestation.public_endpoint.url {
            print_runtime_surface_evidence_error(
                wants_json,
                &[format!(
                    "--endpoint-url expected {} but got {endpoint_url}",
                    attestation.public_endpoint.url
                )],
            );
            process::exit(1);
        }
    }

    let timeout = Duration::from_millis(parse_public_capture_timeout_ms(args, wants_json));
    let origin =
        parse_public_runtime_status_url(&attestation.public_endpoint.url).unwrap_or_else(|error| {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        });
    let capture =
        fetch_public_runtime_surface(&origin, &attestation.public_endpoint.tls_pins, timeout)
            .unwrap_or_else(|error| {
                print_runtime_surface_evidence_error(wants_json, &[error]);
                process::exit(1);
            });
    let input = nebula_testnet::RuntimeSurfaceEvidenceBuildInput {
        endpoint_url: attestation.public_endpoint.url,
        capture_mode: nebula_testnet::RUNTIME_SURFACE_CAPTURE_MODE_EXTERNAL_PUBLIC_ENDPOINT
            .to_string(),
        tls_observation: Some(capture.tls_observation),
        captured_at_unix_ms: current_unix_ms(),
        health_json: capture.health_json,
        status_json: capture.status_json,
        snapshot_json: capture.snapshot_json,
        ops_json: capture.ops_json,
        backup_json: capture.backup_json,
        rpc_status_json: capture.rpc_status_json,
        rpc_ops_status_json: capture.rpc_ops_status_json,
        rpc_backup_manifest_json: capture.rpc_backup_manifest_json,
        metrics_text: capture.metrics_text,
    };
    match nebula_testnet::build_runtime_surface_evidence_json_pretty(input) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_runtime_surface_evidence_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn read_required_public_capture_input(args: &[String], name: &str, wants_json: bool) -> String {
    let Some(path) = arg_value(args, name) else {
        print_runtime_surface_evidence_error(wants_json, &[format!("missing {name} <path>")]);
        process::exit(1);
    };

    match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
    }
}

fn parse_public_capture_timeout_ms(args: &[String], wants_json: bool) -> u64 {
    let Some(value) = arg_value(args, "--timeout-ms") else {
        return DEFAULT_PUBLIC_CAPTURE_TIMEOUT_MS;
    };
    value.parse::<u64>().unwrap_or_else(|error| {
        print_runtime_surface_evidence_error(
            wants_json,
            &[format!("--timeout-ms must be an unsigned integer: {error}")],
        );
        process::exit(1);
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicRuntimeOrigin {
    host: String,
    port: u16,
    host_header: String,
    status_path: String,
    base_path: String,
}

#[derive(Debug, Clone)]
struct CapturedRuntimeSurface {
    tls_observation: nebula_testnet::TlsEndpointPin,
    health_json: String,
    status_json: String,
    snapshot_json: String,
    ops_json: String,
    backup_json: String,
    rpc_status_json: String,
    rpc_ops_status_json: String,
    rpc_backup_manifest_json: String,
    metrics_text: String,
}

#[derive(Debug, Clone)]
struct CapturedHttpsText {
    body: String,
    tls_certificate: LiveTlsCertificateInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveTlsCertificateInfo {
    cert_sha256: String,
    public_key_sha256: String,
    not_after_unix_ms: u128,
}

fn parse_public_runtime_status_url(url: &str) -> Result<PublicRuntimeOrigin, String> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("--capture-public-runtime-surface endpoint must use https://".to_string());
    };
    if rest.contains(['?', '#']) {
        return Err(
            "--capture-public-runtime-surface endpoint must not include query or fragment"
                .to_string(),
        );
    }
    let (authority, path) = rest
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .ok_or_else(|| {
            "--capture-public-runtime-surface endpoint must include a /status path".to_string()
        })?;
    if authority.trim().is_empty() || authority.contains('@') {
        return Err(
            "--capture-public-runtime-surface endpoint must include a bare host".to_string(),
        );
    }
    if authority.contains(char::is_whitespace) || path.contains(char::is_whitespace) {
        return Err(
            "--capture-public-runtime-surface endpoint must not contain whitespace".to_string(),
        );
    }
    if !path.ends_with("/status") {
        return Err(
            "--capture-public-runtime-surface endpoint path must end with /status".to_string(),
        );
    }
    let (host, port) = split_public_runtime_authority(authority)?;
    let host_header = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let base_path = path
        .strip_suffix("/status")
        .expect("path ending was checked")
        .to_string();
    Ok(PublicRuntimeOrigin {
        host,
        port,
        host_header,
        status_path: path,
        base_path,
    })
}

fn split_public_runtime_authority(authority: &str) -> Result<(String, u16), String> {
    if authority.starts_with('[') || authority.contains(']') {
        return Err(
            "--capture-public-runtime-surface endpoint must use a DNS host, not an IPv6 literal"
                .to_string(),
        );
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port_text)) => {
            if host.contains(':') || port_text.is_empty() {
                return Err("--capture-public-runtime-surface endpoint port is invalid".to_string());
            }
            let port = port_text.parse::<u16>().map_err(|error| {
                format!("--capture-public-runtime-surface endpoint port is invalid: {error}")
            })?;
            (host, port)
        }
        None => (authority, 443),
    };
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err("--capture-public-runtime-surface endpoint host is invalid".to_string());
    }
    Ok((host.to_string(), port))
}

fn runtime_capture_path(origin: &PublicRuntimeOrigin, name: &str) -> String {
    if origin.base_path.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{}", origin.base_path.trim_end_matches('/'), name)
    }
}

fn fetch_public_runtime_surface(
    origin: &PublicRuntimeOrigin,
    tls_pins: &[nebula_testnet::TlsEndpointPin],
    timeout: Duration,
) -> Result<CapturedRuntimeSurface, String> {
    let config = Arc::new(public_runtime_tls_config()?);
    let health_path = runtime_capture_path(origin, "health");
    let status_path = origin.status_path.clone();
    let snapshot_path = runtime_capture_path(origin, "snapshot");
    let ops_path = runtime_capture_path(origin, "ops");
    let backup_path = runtime_capture_path(origin, "backup");
    let metrics_path = runtime_capture_path(origin, "metrics");

    let health = https_get_text(
        &config,
        origin,
        &health_path,
        "application/json",
        tls_pins,
        timeout,
    )?;
    let tls_certificate = health.tls_certificate.clone();
    let status = https_get_text(
        &config,
        origin,
        &status_path,
        "application/json",
        tls_pins,
        timeout,
    )?;
    require_same_live_tls(&status_path, &tls_certificate, &status.tls_certificate)?;
    let snapshot = https_get_text(
        &config,
        origin,
        &snapshot_path,
        "application/json",
        tls_pins,
        timeout,
    )?;
    require_same_live_tls(&snapshot_path, &tls_certificate, &snapshot.tls_certificate)?;
    let ops = https_get_text(
        &config,
        origin,
        &ops_path,
        "application/json",
        tls_pins,
        timeout,
    )?;
    require_same_live_tls(&ops_path, &tls_certificate, &ops.tls_certificate)?;
    let backup = https_get_text(
        &config,
        origin,
        &backup_path,
        "application/json",
        tls_pins,
        timeout,
    )?;
    require_same_live_tls(&backup_path, &tls_certificate, &backup.tls_certificate)?;
    let rpc_status = https_post_json_rpc(&config, origin, "nebula_status", tls_pins, timeout)?;
    require_same_live_tls(
        "nebula_status",
        &tls_certificate,
        &rpc_status.tls_certificate,
    )?;
    let rpc_ops_status =
        https_post_json_rpc(&config, origin, "nebula_opsStatus", tls_pins, timeout)?;
    require_same_live_tls(
        "nebula_opsStatus",
        &tls_certificate,
        &rpc_ops_status.tls_certificate,
    )?;
    let rpc_backup_manifest =
        https_post_json_rpc(&config, origin, "nebula_backupManifest", tls_pins, timeout)?;
    require_same_live_tls(
        "nebula_backupManifest",
        &tls_certificate,
        &rpc_backup_manifest.tls_certificate,
    )?;
    let metrics = https_get_text(
        &config,
        origin,
        &metrics_path,
        "text/plain",
        tls_pins,
        timeout,
    )?;
    require_same_live_tls(&metrics_path, &tls_certificate, &metrics.tls_certificate)?;

    Ok(CapturedRuntimeSurface {
        tls_observation: tls_pin_from_live_certificate_info(&tls_certificate),
        health_json: health.body,
        status_json: status.body,
        snapshot_json: snapshot.body,
        ops_json: ops.body,
        backup_json: backup.body,
        rpc_status_json: rpc_status.body,
        rpc_ops_status_json: rpc_ops_status.body,
        rpc_backup_manifest_json: rpc_backup_manifest.body,
        metrics_text: metrics.body,
    })
}

fn public_runtime_tls_config() -> Result<ClientConfig, String> {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("failed to configure TLS protocol versions: {error}"))
        .map(|builder| {
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        })
}

fn https_get_text(
    config: &Arc<ClientConfig>,
    origin: &PublicRuntimeOrigin,
    path: &str,
    accept: &str,
    tls_pins: &[nebula_testnet::TlsEndpointPin],
    timeout: Duration,
) -> Result<CapturedHttpsText, String> {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: nebula-testnet/{}\r\nAccept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        origin.host_header,
        env!("CARGO_PKG_VERSION")
    );
    https_request_text(config, origin, path, &request, tls_pins, timeout)
}

fn https_post_json_rpc(
    config: &Arc<ClientConfig>,
    origin: &PublicRuntimeOrigin,
    method: &str,
    tls_pins: &[nebula_testnet::TlsEndpointPin],
    timeout: Duration,
) -> Result<CapturedHttpsText, String> {
    let path = runtime_capture_path(origin, "rpc");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": method,
        "method": method,
        "params": {},
    })
    .to_string();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: nebula-testnet/{}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        origin.host_header,
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    https_request_text(config, origin, &path, &request, tls_pins, timeout)
}

fn https_request_text(
    config: &Arc<ClientConfig>,
    origin: &PublicRuntimeOrigin,
    path: &str,
    request: &str,
    tls_pins: &[nebula_testnet::TlsEndpointPin],
    timeout: Duration,
) -> Result<CapturedHttpsText, String> {
    let mut tls = connect_public_runtime_tls(config, origin, timeout)
        .map_err(|error| format!("{path} HTTPS connection failed: {error}"))?;
    let certificates = tls
        .conn
        .peer_certificates()
        .ok_or_else(|| format!("{path} TLS peer did not present certificates"))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| format!("{path} TLS peer certificate chain is empty"))?;
    let tls_info = live_tls_certificate_info(leaf.as_ref())
        .map_err(|error| format!("{path} TLS certificate parse failed: {error}"))?;
    verify_live_tls_pin(path, tls_pins, &tls_info, current_unix_ms())?;

    tls.write_all(request.as_bytes())
        .map_err(|error| format!("{path} HTTPS request write failed: {error}"))?;
    tls.flush()
        .map_err(|error| format!("{path} HTTPS request flush failed: {error}"))?;
    let mut response = Vec::new();
    let mut limited = tls.take((MAX_PUBLIC_CAPTURE_RESPONSE_BYTES + 1) as u64);
    limited
        .read_to_end(&mut response)
        .map_err(|error| format!("{path} HTTPS response read failed: {error}"))?;
    if response.len() > MAX_PUBLIC_CAPTURE_RESPONSE_BYTES {
        return Err(format!(
            "{path} HTTPS response exceeded {MAX_PUBLIC_CAPTURE_RESPONSE_BYTES} bytes"
        ));
    }
    let body = parse_http_response_text(path, &response)?;
    Ok(CapturedHttpsText {
        body,
        tls_certificate: tls_info,
    })
}

fn connect_public_runtime_tls(
    config: &Arc<ClientConfig>,
    origin: &PublicRuntimeOrigin,
    timeout: Duration,
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let server_name = ServerName::try_from(origin.host.clone())
        .map_err(|error| format!("invalid TLS server name {}: {error}", origin.host))?;
    let stream = connect_public_runtime_tcp(origin, timeout)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;
    let connection = ClientConnection::new(config.clone(), server_name)
        .map_err(|error| format!("failed to create TLS client: {error}"))?;
    let mut tls = StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|error| format!("TLS handshake failed: {error}"))?;
    }
    Ok(tls)
}

fn connect_public_runtime_tcp(
    origin: &PublicRuntimeOrigin,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let addresses = (origin.host.as_str(), origin.port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve {}:{}: {error}", origin.host, origin.port))?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "failed to connect to {}:{}: {}",
        origin.host,
        origin.port,
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "no resolved addresses".to_string())
    ))
}

fn live_tls_certificate_info(leaf_der: &[u8]) -> Result<LiveTlsCertificateInfo, String> {
    let (_, certificate) = parse_x509_certificate(leaf_der)
        .map_err(|error| format!("failed to parse leaf certificate DER: {error:?}"))?;
    let not_after_seconds = certificate.validity().not_after.timestamp();
    let not_after_unix_ms = u128::try_from(not_after_seconds)
        .map_err(|_| "leaf certificate not_after is before UNIX epoch".to_string())?
        .checked_mul(1_000)
        .ok_or_else(|| "leaf certificate not_after overflows unix ms".to_string())?;
    Ok(LiveTlsCertificateInfo {
        cert_sha256: sha256_hex(leaf_der),
        public_key_sha256: sha256_hex(certificate.public_key().raw),
        not_after_unix_ms,
    })
}

fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

fn tls_pin_from_live_certificate_info(
    live: &LiveTlsCertificateInfo,
) -> nebula_testnet::TlsEndpointPin {
    nebula_testnet::TlsEndpointPin {
        cert_sha256: live.cert_sha256.clone(),
        public_key_sha256: live.public_key_sha256.clone(),
        not_after_unix_ms: live.not_after_unix_ms,
    }
}

fn require_same_live_tls(
    label: &str,
    expected: &LiveTlsCertificateInfo,
    actual: &LiveTlsCertificateInfo,
) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    Err(format!(
        "{label} TLS observation changed during public runtime capture"
    ))
}

fn verify_live_tls_pin(
    path: &str,
    tls_pins: &[nebula_testnet::TlsEndpointPin],
    live: &LiveTlsCertificateInfo,
    now_unix_ms: u128,
) -> Result<(), String> {
    if live.not_after_unix_ms <= now_unix_ms {
        return Err(format!("{path} TLS leaf certificate is expired"));
    }
    if tls_pins.iter().any(|pin| {
        pin.cert_sha256.eq_ignore_ascii_case(&live.cert_sha256)
            && pin
                .public_key_sha256
                .eq_ignore_ascii_case(&live.public_key_sha256)
            && pin.not_after_unix_ms == live.not_after_unix_ms
    }) {
        return Ok(());
    }
    Err(format!(
        "{path} TLS pin mismatch: live cert_sha256={}, public_key_sha256={}, not_after_unix_ms={} did not match any deployment attestation tls_pins row",
        live.cert_sha256, live.public_key_sha256, live.not_after_unix_ms
    ))
}

fn parse_http_response_text(path: &str, response: &[u8]) -> Result<String, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| format!("{path} HTTPS response was missing HTTP headers"))?;
    let head = std::str::from_utf8(&response[..header_end])
        .map_err(|error| format!("{path} HTTPS response headers were not UTF-8: {error}"))?;
    let mut lines = head.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| format!("{path} HTTPS response was missing status line"))?;
    let status_code = parse_http_status_code(status_line)
        .ok_or_else(|| format!("{path} HTTPS response had invalid status line: {status_line}"))?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect::<Vec<_>>();
    if status_code != 200 {
        return Err(format!("{path} HTTPS response returned {status_line}"));
    }
    let mut body = response[header_end + 4..].to_vec();
    if header_value(&headers, "transfer-encoding")
        .map(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
    {
        body = decode_chunked_body(&body)
            .map_err(|error| format!("{path} HTTPS response chunked body was invalid: {error}"))?;
    } else if let Some(content_length) = header_value(&headers, "content-length") {
        let expected = content_length
            .parse::<usize>()
            .map_err(|error| format!("{path} Content-Length was invalid: {error}"))?;
        if body.len() < expected {
            return Err(format!(
                "{path} HTTPS response body was shorter than Content-Length {expected}"
            ));
        }
        body.truncate(expected);
    }
    String::from_utf8(body)
        .map_err(|error| format!("{path} HTTPS response body was not UTF-8: {error}"))
}

fn parse_http_status_code(status_line: &str) -> Option<u16> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut cursor = 0;
    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| "missing chunk-size line ending".to_string())?;
        let line = std::str::from_utf8(&body[cursor..cursor + line_end])
            .map_err(|error| format!("chunk-size line was not UTF-8: {error}"))?;
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| format!("chunk-size was not hex: {error}"))?;
        cursor += line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| "chunk-size overflowed response length".to_string())?;
        if end > body.len() {
            return Err("chunk data exceeded response length".to_string());
        }
        decoded.extend_from_slice(&body[cursor..end]);
        cursor = end;
        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err("chunk data was not followed by CRLF".to_string());
        }
        cursor += 2;
    }
}

fn build_live_rpc_devnet_runtime_surface(args: &[String], wants_json: bool) {
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_live_rpc_devnet_runtime_surface_evidence_json_pretty(
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_runtime_surface_evidence_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn sign_bridge_observer_evidence(args: &[String], wants_json: bool) {
    let deposit = read_required_bridge_json::<nebula_testnet::runtime::RuntimeBridgeDeposit>(
        args,
        "--bridge-deposit",
        wants_json,
    );
    if deposit.observed_at_unix_ms == 0 {
        print_bridge_evidence_error(
            wants_json,
            &[
                "bridge deposit observed_at_unix_ms must be set before observer signing"
                    .to_string(),
            ],
        );
        process::exit(1);
    }
    let observer_id = required_bridge_arg(args, "--observer-id", wants_json);
    if !deposit
        .observer_ids
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&observer_id))
    {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--observer-id {observer_id} must appear in bridge deposit observer_ids"
            )],
        );
        process::exit(1);
    }
    let observer_secret_key = required_bridge_arg(args, "--observer-secret-key", wants_json);
    let observer_public_key_hex =
        match nebula_testnet::runtime::public_key_hex_for_secret(&observer_secret_key) {
            Ok(public_key) => public_key,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let payload_root = nebula_testnet::runtime::bridge_observer_deposit_payload_root(&deposit);
    let signature =
        match nebula_testnet::runtime::sign_runtime_root(&observer_secret_key, &payload_root) {
            Ok(signature) => signature,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let mut evidence = nebula_testnet::runtime::RuntimeBridgeObserverEvidence {
        observer_id,
        observer_public_key_hex,
        payload_root,
        signature,
        signed_at_unix_ms: parse_u128_arg(args, "--signed-at-unix-ms", current_unix_ms()),
        evidence_root: String::new(),
    };
    evidence.evidence_root = nebula_testnet::runtime::bridge_observer_evidence_root(&evidence);
    println!(
        "{}",
        serde_json::to_string_pretty(&evidence).expect("observer evidence serializes")
    );
}

fn assemble_bridge_deposit(args: &[String], wants_json: bool) {
    let mut deposit = read_required_bridge_json::<nebula_testnet::runtime::RuntimeBridgeDeposit>(
        args,
        "--bridge-deposit",
        wants_json,
    );
    let evidence_paths = arg_values(args, "--observer-evidence");
    if evidence_paths.is_empty() {
        print_bridge_evidence_error(
            wants_json,
            &["missing --observer-evidence <path>; repeat once per observer signer".to_string()],
        );
        process::exit(1);
    }
    let mut observer_evidence = evidence_paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let evidence = read_bridge_json_file::<
                nebula_testnet::runtime::RuntimeBridgeObserverEvidence,
            >(path, wants_json);
            validate_observer_evidence_for_deposit(&deposit, &evidence, index, path, wants_json);
            evidence
        })
        .collect::<Vec<_>>();
    sort_observer_evidence_for_deposit(&deposit, &mut observer_evidence, wants_json);
    deposit.observer_signature_roots = observer_evidence
        .iter()
        .map(|evidence| evidence.evidence_root.clone())
        .collect();
    deposit.observer_evidence = observer_evidence;
    println!(
        "{}",
        serde_json::to_string_pretty(&deposit).expect("bridge deposit serializes")
    );
}

fn sign_withdrawal_operator_approval(args: &[String], wants_json: bool) {
    let withdrawal = read_required_bridge_json::<nebula_testnet::runtime::RuntimeWithdrawalRequest>(
        args,
        "--withdrawal",
        wants_json,
    );
    if withdrawal.status != "operator_pending" {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "withdrawal {} must be operator_pending before operator approval signing",
                withdrawal.withdrawal_id
            )],
        );
        process::exit(1);
    }
    let finalized_monero_tx_id = required_bridge_arg(args, "--finalized-monero-tx-id", wants_json);
    let finalization_proof_root =
        required_bridge_arg(args, "--finalization-proof-root", wants_json);
    validate_hex_arg(
        &finalized_monero_tx_id,
        "--finalized-monero-tx-id",
        64,
        wants_json,
    );
    validate_hex_arg(
        &finalization_proof_root,
        "--finalization-proof-root",
        64,
        wants_json,
    );
    let operator_id = required_bridge_arg(args, "--operator-id", wants_json);
    let operator_secret_key = required_bridge_arg(args, "--operator-secret-key", wants_json);
    let operator_public_key_hex =
        match nebula_testnet::runtime::public_key_hex_for_secret(&operator_secret_key) {
            Ok(public_key) => public_key,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let payload_root = nebula_testnet::runtime::withdrawal_operator_finalization_payload_root(
        &withdrawal,
        &finalized_monero_tx_id,
        &finalization_proof_root,
    );
    let signature =
        match nebula_testnet::runtime::sign_runtime_root(&operator_secret_key, &payload_root) {
            Ok(signature) => signature,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let mut approval = nebula_testnet::runtime::RuntimeWithdrawalOperatorApproval {
        operator_id,
        operator_public_key_hex,
        payload_root,
        signature,
        signed_at_unix_ms: parse_u128_arg(args, "--signed-at-unix-ms", current_unix_ms()),
        approval_root: String::new(),
    };
    approval.approval_root = nebula_testnet::runtime::withdrawal_operator_approval_root(&approval);
    println!(
        "{}",
        serde_json::to_string_pretty(&approval).expect("operator approval serializes")
    );
}

fn assemble_finalize_withdrawal(args: &[String], wants_json: bool) {
    let withdrawal = read_required_bridge_json::<nebula_testnet::runtime::RuntimeWithdrawalRequest>(
        args,
        "--withdrawal",
        wants_json,
    );
    let finalized_monero_tx_id = required_bridge_arg(args, "--finalized-monero-tx-id", wants_json);
    let finalization_proof_root =
        required_bridge_arg(args, "--finalization-proof-root", wants_json);
    validate_hex_arg(
        &finalized_monero_tx_id,
        "--finalized-monero-tx-id",
        64,
        wants_json,
    );
    validate_hex_arg(
        &finalization_proof_root,
        "--finalization-proof-root",
        64,
        wants_json,
    );
    let approval_paths = arg_values(args, "--operator-approval");
    if approval_paths.is_empty() {
        print_bridge_evidence_error(
            wants_json,
            &["missing --operator-approval <path>; repeat once per operator signer".to_string()],
        );
        process::exit(1);
    }
    let approvals = approval_paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let approval = read_bridge_json_file::<
                nebula_testnet::runtime::RuntimeWithdrawalOperatorApproval,
            >(path, wants_json);
            validate_operator_approval_for_withdrawal(
                &withdrawal,
                &finalized_monero_tx_id,
                &finalization_proof_root,
                &approval,
                index,
                path,
                wants_json,
            );
            approval
        })
        .collect::<Vec<_>>();
    validate_operator_approval_set(&approvals, wants_json);
    let mut params = serde_json::json!({
        "withdrawal_id": withdrawal.withdrawal_id,
        "finalized_monero_tx_id": finalized_monero_tx_id,
        "finalization_proof_root": finalization_proof_root,
        "operator_approval_ids": approvals
            .iter()
            .map(|approval| approval.operator_id.clone())
            .collect::<Vec<_>>(),
        "operator_approval_roots": approvals
            .iter()
            .map(|approval| approval.approval_root.clone())
            .collect::<Vec<_>>(),
        "operator_approvals": approvals,
    });
    if let Some(admin_token) = arg_value(args, "--admin-token") {
        params["admin_token"] = serde_json::Value::String(admin_token.to_string());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&params).expect("finalize params serialize")
    );
}

fn sign_sequencer_rotation_approval(args: &[String], wants_json: bool) {
    let new_public_key_hex = required_bridge_arg(args, "--new-sequencer-public-key", wants_json);
    let payload_root = sequencer_rotation_payload_root_from_args(
        args,
        &new_public_key_hex,
        "--new-sequencer-public-key",
        wants_json,
    );
    let operator_id = required_bridge_arg(args, "--operator-id", wants_json);
    let operator_secret_key = required_bridge_arg(args, "--operator-secret-key", wants_json);
    let operator_public_key_hex =
        match nebula_testnet::runtime::public_key_hex_for_secret(&operator_secret_key) {
            Ok(public_key) => public_key,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let signature =
        match nebula_testnet::runtime::sign_runtime_root(&operator_secret_key, &payload_root) {
            Ok(signature) => signature,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let mut approval = nebula_testnet::runtime::RuntimeSequencerKeyRotationApproval {
        operator_id,
        operator_public_key_hex,
        payload_root,
        signature,
        signed_at_unix_ms: parse_u128_arg(args, "--signed-at-unix-ms", current_unix_ms()),
        approval_root: String::new(),
    };
    approval.approval_root =
        nebula_testnet::runtime::sequencer_key_rotation_approval_root(&approval);
    println!(
        "{}",
        serde_json::to_string_pretty(&approval).expect("sequencer rotation approval serializes")
    );
}

fn assemble_sequencer_rotation(args: &[String], wants_json: bool) {
    let new_sequencer_secret_key_hex =
        required_bridge_arg(args, "--new-sequencer-secret-key-hex", wants_json);
    let new_public_key_hex =
        match nebula_testnet::runtime::public_key_hex_for_secret(&new_sequencer_secret_key_hex) {
            Ok(public_key) => public_key,
            Err(error) => {
                print_bridge_evidence_error(wants_json, &[error]);
                process::exit(1);
            }
        };
    let rotation_proof_root = required_bridge_arg(args, "--rotation-proof-root", wants_json);
    validate_hex_arg(
        &rotation_proof_root,
        "--rotation-proof-root",
        64,
        wants_json,
    );
    let expected_payload_root = sequencer_rotation_payload_root_from_args(
        args,
        &new_public_key_hex,
        "public key derived from --new-sequencer-secret-key-hex",
        wants_json,
    );
    let approval_paths = arg_values(args, "--operator-approval");
    if approval_paths.is_empty() {
        print_bridge_evidence_error(
            wants_json,
            &["missing --operator-approval <path>; repeat once per operator signer".to_string()],
        );
        process::exit(1);
    }
    let approvals = approval_paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            let approval = read_bridge_json_file::<
                nebula_testnet::runtime::RuntimeSequencerKeyRotationApproval,
            >(path, wants_json);
            validate_operator_approval_for_sequencer_rotation(
                &expected_payload_root,
                &approval,
                index,
                path,
                wants_json,
            );
            approval
        })
        .collect::<Vec<_>>();
    validate_sequencer_rotation_operator_approval_set(&approvals, wants_json);

    let operator_approval_ids = approvals
        .iter()
        .map(|approval| approval.operator_id.clone())
        .collect::<Vec<_>>();
    let operator_approval_roots = approvals
        .iter()
        .map(|approval| approval.approval_root.clone())
        .collect::<Vec<_>>();
    let mut params = serde_json::json!({
        "new_sequencer_secret_key_hex": new_sequencer_secret_key_hex,
        "rotation_proof_root": rotation_proof_root,
        "operator_approval_ids": operator_approval_ids,
        "operator_approval_roots": operator_approval_roots,
        "operator_approvals": approvals,
    });
    if let Some(admin_token) = arg_value(args, "--admin-token") {
        params["admin_token"] = serde_json::Value::String(admin_token.to_string());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&params).expect("sequencer rotation params serialize")
    );
}

fn sequencer_rotation_payload_root_from_args(
    args: &[String],
    new_public_key_hex: &str,
    new_public_key_name: &str,
    wants_json: bool,
) -> String {
    let launch_package_bundle_root =
        required_bridge_arg(args, "--launch-package-bundle-root", wants_json);
    let previous_sequencer_key_history_root =
        required_bridge_arg(args, "--previous-sequencer-key-history-root", wants_json);
    let activation_height = required_bridge_u64_arg(args, "--activation-height", wants_json);
    let old_public_key_hex = required_bridge_arg(args, "--old-sequencer-public-key", wants_json);
    let rotation_proof_root = required_bridge_arg(args, "--rotation-proof-root", wants_json);

    validate_hex_arg(
        &launch_package_bundle_root,
        "--launch-package-bundle-root",
        64,
        wants_json,
    );
    validate_hex_arg(
        &previous_sequencer_key_history_root,
        "--previous-sequencer-key-history-root",
        64,
        wants_json,
    );
    validate_hex_arg(
        &old_public_key_hex,
        "--old-sequencer-public-key",
        64,
        wants_json,
    );
    validate_hex_arg(new_public_key_hex, new_public_key_name, 64, wants_json);
    validate_hex_arg(
        &rotation_proof_root,
        "--rotation-proof-root",
        64,
        wants_json,
    );

    nebula_testnet::runtime::sequencer_key_rotation_payload_root_for_context(
        &nebula_testnet::runtime::RuntimeSequencerKeyRotationPayloadContext {
            chain_id: nebula_testnet::CHAIN_ID,
            runtime_version: nebula_testnet::VERSION,
            launch_package_bundle_root: Some(&launch_package_bundle_root),
            previous_sequencer_key_history_root: &previous_sequencer_key_history_root,
            activation_height,
            old_public_key_hex: &old_public_key_hex,
            new_public_key_hex,
            rotation_proof_root: &rotation_proof_root,
        },
    )
}

fn validate_hex_arg(value: &str, name: &str, len: usize, wants_json: bool) {
    if value.len() != len || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        print_bridge_evidence_error(
            wants_json,
            &[format!("{name} must be {len} hex characters")],
        );
        process::exit(1);
    }
}

fn validate_operator_approval_for_sequencer_rotation(
    expected_payload_root: &str,
    approval: &nebula_testnet::runtime::RuntimeSequencerKeyRotationApproval,
    index: usize,
    path: &str,
    wants_json: bool,
) {
    if approval.payload_root != expected_payload_root {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--operator-approval[{index}] {path} payload_root does not match sequencer rotation"
            )],
        );
        process::exit(1);
    }
    let expected_approval_root =
        nebula_testnet::runtime::sequencer_key_rotation_approval_root(approval);
    if approval.approval_root != expected_approval_root {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--operator-approval[{index}] {path} approval_root does not match approval contents"
            )],
        );
        process::exit(1);
    }
    if let Err(error) = nebula_testnet::runtime::verify_runtime_root_signature(
        &approval.operator_public_key_hex,
        &approval.payload_root,
        &approval.signature,
    ) {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--operator-approval[{index}] {path} signature rejected: {error}"
            )],
        );
        process::exit(1);
    }
}

fn validate_observer_evidence_for_deposit(
    deposit: &nebula_testnet::runtime::RuntimeBridgeDeposit,
    evidence: &nebula_testnet::runtime::RuntimeBridgeObserverEvidence,
    index: usize,
    path: &str,
    wants_json: bool,
) {
    let expected_payload_root =
        nebula_testnet::runtime::bridge_observer_deposit_payload_root(deposit);
    if evidence.payload_root != expected_payload_root {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--observer-evidence[{index}] {path} payload_root does not match --bridge-deposit"
            )],
        );
        process::exit(1);
    }
    let expected_evidence_root = nebula_testnet::runtime::bridge_observer_evidence_root(evidence);
    if evidence.evidence_root != expected_evidence_root {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--observer-evidence[{index}] {path} evidence_root does not match evidence contents"
            )],
        );
        process::exit(1);
    }
    if let Err(error) = nebula_testnet::runtime::verify_runtime_root_signature(
        &evidence.observer_public_key_hex,
        &evidence.payload_root,
        &evidence.signature,
    ) {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--observer-evidence[{index}] {path} signature rejected: {error}"
            )],
        );
        process::exit(1);
    }
    if !deposit
        .observer_ids
        .iter()
        .any(|observer_id| observer_id.eq_ignore_ascii_case(&evidence.observer_id))
    {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--observer-evidence[{index}] {} observer_id is not in bridge deposit observer_ids",
                evidence.observer_id
            )],
        );
        process::exit(1);
    }
}

fn sort_observer_evidence_for_deposit(
    deposit: &nebula_testnet::runtime::RuntimeBridgeDeposit,
    observer_evidence: &mut [nebula_testnet::runtime::RuntimeBridgeObserverEvidence],
    wants_json: bool,
) {
    if observer_evidence.len() != deposit.observer_ids.len() {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "observer evidence count {} must match bridge deposit observer_ids count {}",
                observer_evidence.len(),
                deposit.observer_ids.len()
            )],
        );
        process::exit(1);
    }

    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut seen_roots = BTreeSet::new();
    for evidence in observer_evidence.iter() {
        if !seen_ids.insert(evidence.observer_id.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate observer evidence for observer_id {}",
                    evidence.observer_id
                )],
            );
            process::exit(1);
        }
        if !seen_keys.insert(evidence.observer_public_key_hex.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate observer evidence public key for observer_id {}",
                    evidence.observer_id
                )],
            );
            process::exit(1);
        }
        if !seen_roots.insert(evidence.evidence_root.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate observer evidence root for observer_id {}",
                    evidence.observer_id
                )],
            );
            process::exit(1);
        }
    }

    for observer_id in &deposit.observer_ids {
        if !seen_ids.contains(&observer_id.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "missing observer evidence for observer_id {observer_id}"
                )],
            );
            process::exit(1);
        }
    }

    observer_evidence.sort_by_key(|evidence| {
        deposit
            .observer_ids
            .iter()
            .position(|observer_id| observer_id.eq_ignore_ascii_case(&evidence.observer_id))
            .unwrap_or(usize::MAX)
    });
}

fn validate_operator_approval_for_withdrawal(
    withdrawal: &nebula_testnet::runtime::RuntimeWithdrawalRequest,
    finalized_monero_tx_id: &str,
    finalization_proof_root: &str,
    approval: &nebula_testnet::runtime::RuntimeWithdrawalOperatorApproval,
    index: usize,
    path: &str,
    wants_json: bool,
) {
    let expected_payload_root =
        nebula_testnet::runtime::withdrawal_operator_finalization_payload_root(
            withdrawal,
            finalized_monero_tx_id,
            finalization_proof_root,
        );
    if approval.payload_root != expected_payload_root {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--operator-approval[{index}] {path} payload_root does not match withdrawal finalization"
            )],
        );
        process::exit(1);
    }
    let expected_approval_root =
        nebula_testnet::runtime::withdrawal_operator_approval_root(approval);
    if approval.approval_root != expected_approval_root {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--operator-approval[{index}] {path} approval_root does not match approval contents"
            )],
        );
        process::exit(1);
    }
    if let Err(error) = nebula_testnet::runtime::verify_runtime_root_signature(
        &approval.operator_public_key_hex,
        &approval.payload_root,
        &approval.signature,
    ) {
        print_bridge_evidence_error(
            wants_json,
            &[format!(
                "--operator-approval[{index}] {path} signature rejected: {error}"
            )],
        );
        process::exit(1);
    }
}

fn validate_operator_approval_set(
    approvals: &[nebula_testnet::runtime::RuntimeWithdrawalOperatorApproval],
    wants_json: bool,
) {
    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut seen_roots = BTreeSet::new();
    for approval in approvals {
        if !seen_ids.insert(approval.operator_id.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate operator approval for operator_id {}",
                    approval.operator_id
                )],
            );
            process::exit(1);
        }
        if !seen_keys.insert(approval.operator_public_key_hex.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate operator approval public key for operator_id {}",
                    approval.operator_id
                )],
            );
            process::exit(1);
        }
        if !seen_roots.insert(approval.approval_root.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate operator approval root for operator_id {}",
                    approval.operator_id
                )],
            );
            process::exit(1);
        }
    }
}

fn validate_sequencer_rotation_operator_approval_set(
    approvals: &[nebula_testnet::runtime::RuntimeSequencerKeyRotationApproval],
    wants_json: bool,
) {
    let mut seen_ids = BTreeSet::new();
    let mut seen_keys = BTreeSet::new();
    let mut seen_roots = BTreeSet::new();
    for approval in approvals {
        if !seen_ids.insert(approval.operator_id.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate sequencer rotation operator approval for operator_id {}",
                    approval.operator_id
                )],
            );
            process::exit(1);
        }
        if !seen_keys.insert(approval.operator_public_key_hex.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate sequencer rotation operator approval public key for operator_id {}",
                    approval.operator_id
                )],
            );
            process::exit(1);
        }
        if !seen_roots.insert(approval.approval_root.to_ascii_lowercase()) {
            print_bridge_evidence_error(
                wants_json,
                &[format!(
                    "duplicate sequencer rotation operator approval root for operator_id {}",
                    approval.operator_id
                )],
            );
            process::exit(1);
        }
    }
}

fn build_deployment_attestation(args: &[String], wants_json: bool) {
    let public_status_json =
        read_required_deployment_builder_input(args, "--public-status", wants_json);
    let public_probe_json =
        read_required_deployment_builder_input(args, "--public-probe", wants_json);
    let preflight_receipt_json =
        read_required_deployment_builder_input(args, "--preflight-receipt", wants_json);
    let runbook_receipt_json =
        read_required_deployment_builder_input(args, "--runbook-receipt", wants_json);
    let generated_at_unix_ms = parse_u128_arg(args, "--generated-at-unix-ms", current_unix_ms());
    let expires_at_unix_ms = parse_u128_arg(
        args,
        "--expires-at-unix-ms",
        generated_at_unix_ms + 86_400_000,
    );
    let rollback_plan_sha3_256 = required_arg(args, "--rollback-plan-sha3-256", wants_json);
    let rollback_recovery_point_root = required_arg(args, "--rollback-recovery-root", wants_json);
    let rollback_last_drill_unix_ms =
        parse_u128_arg(args, "--rollback-last-drill-unix-ms", generated_at_unix_ms);
    let input = nebula_testnet::DeploymentAttestationBuildInput {
        public_status_json,
        public_probe_json,
        preflight_receipt_json,
        runbook_receipt_json,
        artifact_sha3_256: arg_value(args, "--artifact-sha3-256")
            .map(str::to_string)
            .unwrap_or_else(nebula_testnet::default_artifact_sha3_256),
        cargo_lock_sha3_256: arg_value(args, "--cargo-lock-sha3-256")
            .map(str::to_string)
            .unwrap_or_else(nebula_testnet::default_cargo_lock_sha3_256),
        generated_at_unix_ms,
        expires_at_unix_ms,
        tls_pins: parse_tls_pins(args, wants_json),
        bootstrap_nodes: parse_bootstrap_nodes(args, wants_json),
        operators: parse_operators(args, wants_json),
        observers: parse_observers(args, wants_json),
        rollback_plan_sha3_256,
        rollback_last_drill_unix_ms,
        rollback_recovery_point_root,
    };
    match nebula_testnet::build_deployment_attestation_json_pretty(input) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_deployment_attestation_builder_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_deployment_attestation_builder_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn public_surface_build_input(
    args: &[String],
    endpoint_url: &str,
) -> nebula_testnet::PublicSurfaceBuildInput {
    nebula_testnet::PublicSurfaceBuildInput {
        endpoint_url: endpoint_url.to_string(),
        artifact_sha3_256: arg_value(args, "--artifact-sha3-256")
            .map(str::to_string)
            .unwrap_or_else(nebula_testnet::default_artifact_sha3_256),
        cargo_lock_sha3_256: arg_value(args, "--cargo-lock-sha3-256")
            .map(str::to_string)
            .unwrap_or_else(nebula_testnet::default_cargo_lock_sha3_256),
    }
}

fn required_arg(args: &[String], name: &str, wants_json: bool) -> String {
    let Some(value) = arg_value(args, name) else {
        print_deployment_attestation_builder_error(
            wants_json,
            &[format!("missing {name} <value>")],
        );
        process::exit(1);
    };
    value.to_string()
}

fn parse_tls_pins(args: &[String], wants_json: bool) -> Vec<nebula_testnet::TlsEndpointPin> {
    parse_rows(args, "--tls-pin", 3, wants_json)
        .into_iter()
        .map(|fields| nebula_testnet::TlsEndpointPin {
            cert_sha256: fields[0].clone(),
            public_key_sha256: fields[1].clone(),
            not_after_unix_ms: fields[2].parse::<u128>().unwrap_or_else(|error| {
                print_deployment_attestation_builder_error(
                    wants_json,
                    &[format!(
                        "--tls-pin not_after_unix_ms must be an unsigned integer: {error}"
                    )],
                );
                process::exit(1);
            }),
        })
        .collect()
}

fn parse_runtime_surface_tls_observation(
    args: &[String],
    wants_json: bool,
) -> Option<nebula_testnet::TlsEndpointPin> {
    let values = arg_values(args, "--runtime-surface-tls-pin");
    if values.is_empty() {
        return None;
    }
    if values.len() != 1 {
        print_runtime_surface_evidence_error(
            wants_json,
            &["--runtime-surface-tls-pin may be supplied at most once".to_string()],
        );
        process::exit(1);
    }
    let fields = values[0]
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
        print_runtime_surface_evidence_error(
            wants_json,
            &["--runtime-surface-tls-pin expected 3 non-empty comma-separated fields".to_string()],
        );
        process::exit(1);
    }
    Some(nebula_testnet::TlsEndpointPin {
        cert_sha256: fields[0].clone(),
        public_key_sha256: fields[1].clone(),
        not_after_unix_ms: fields[2].parse::<u128>().unwrap_or_else(|error| {
            print_runtime_surface_evidence_error(
                wants_json,
                &[format!(
                    "--runtime-surface-tls-pin not_after_unix_ms must be an unsigned integer: {error}"
                )],
            );
            process::exit(1);
        }),
    })
}

fn parse_bootstrap_nodes(
    args: &[String],
    wants_json: bool,
) -> Vec<nebula_testnet::BootstrapNodeBuildInput> {
    parse_rows(args, "--bootstrap-node", 4, wants_json)
        .into_iter()
        .map(|fields| nebula_testnet::BootstrapNodeBuildInput {
            node_id: fields[0].clone(),
            operator_id: fields[1].clone(),
            region: fields[2].clone(),
            endpoint: fields[3].clone(),
        })
        .collect()
}

fn parse_operators(args: &[String], wants_json: bool) -> Vec<nebula_testnet::OperatorBuildInput> {
    parse_rows(args, "--operator", 3, wants_json)
        .into_iter()
        .map(|fields| nebula_testnet::OperatorBuildInput {
            operator_id: fields[0].clone(),
            region: fields[1].clone(),
            public_key: fields[2].clone(),
        })
        .collect()
}

fn parse_observers(args: &[String], wants_json: bool) -> Vec<nebula_testnet::ObserverBuildInput> {
    parse_rows_range(args, "--observer", 3, 4, wants_json)
        .into_iter()
        .map(|fields| nebula_testnet::ObserverBuildInput {
            observer_id: fields[0].clone(),
            region: fields[1].clone(),
            public_key: fields[2].clone(),
            secret_key_hex: fields.get(3).cloned(),
        })
        .collect()
}

fn parse_rows_range(
    args: &[String],
    name: &str,
    min_field_count: usize,
    max_field_count: usize,
    wants_json: bool,
) -> Vec<Vec<String>> {
    let values = arg_values(args, name);
    if values.is_empty() {
        print_deployment_attestation_builder_error(
            wants_json,
            &[format!(
                "missing {name}; expected {min_field_count} to {max_field_count} comma-separated fields"
            )],
        );
        process::exit(1);
    }
    values
        .into_iter()
        .map(|value| {
            let fields = value
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>();
            if fields.len() < min_field_count
                || fields.len() > max_field_count
                || fields.iter().any(|field| field.is_empty())
            {
                print_deployment_attestation_builder_error(
                    wants_json,
                    &[format!(
                        "{name} expected {min_field_count} to {max_field_count} non-empty comma-separated fields"
                    )],
                );
                process::exit(1);
            }
            fields
        })
        .collect()
}

fn parse_rows(
    args: &[String],
    name: &str,
    field_count: usize,
    wants_json: bool,
) -> Vec<Vec<String>> {
    let values = arg_values(args, name);
    if values.is_empty() {
        print_deployment_attestation_builder_error(
            wants_json,
            &[format!(
                "missing {name}; expected {field_count} comma-separated fields"
            )],
        );
        process::exit(1);
    }
    values
        .into_iter()
        .map(|value| {
            let fields = value
                .split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>();
            if fields.len() != field_count || fields.iter().any(|field| field.is_empty()) {
                print_deployment_attestation_builder_error(
                    wants_json,
                    &[format!(
                        "{name} expected {field_count} non-empty comma-separated fields"
                    )],
                );
                process::exit(1);
            }
            fields
        })
        .collect()
}

fn verify_public_status(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_status_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_public_status_manifest_json(&input) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("public status report serializes")
                );
            } else {
                println!(
                    "Public status verified at {}.",
                    report.public_status_manifest_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_status_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_status_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_public_probe(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_probe_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_public_probe_json(&input) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("public probe report serializes")
                );
            } else {
                println!("Public probe verified at {}.", report.public_probe_root);
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_probe_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_probe_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_preflight_receipt(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_receipt_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_preflight_receipt_json(&input) {
        Ok(report) => print_receipt_report(&report, wants_json),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_receipt_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_receipt_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_runbook_receipt(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_receipt_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_runbook_receipt_json(&input) {
        Ok(report) => print_receipt_report(&report, wants_json),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_receipt_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_receipt_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_runtime_surface_evidence(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_runtime_surface_evidence_json(&input) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("runtime surface evidence report serializes")
                );
            } else {
                println!(
                    "Runtime surface evidence verified at {}.",
                    report.runtime_surface_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_runtime_surface_evidence_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_runtime_surface_evidence_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_attestation(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_verification_error(wants_json, &[error]);
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

fn verify_launch_package(args: &[String], wants_json: bool) {
    let Some(deployment_path) = arg_value(args, "--deployment-attestation") else {
        print_launch_package_error(
            wants_json,
            &["missing --deployment-attestation <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(public_status_path) = arg_value(args, "--public-status") else {
        print_launch_package_error(wants_json, &["missing --public-status <path>".to_string()]);
        process::exit(1);
    };
    let Some(public_probe_path) = arg_value(args, "--public-probe") else {
        print_launch_package_error(wants_json, &["missing --public-probe <path>".to_string()]);
        process::exit(1);
    };
    let Some(validator_set_path) = arg_value(args, "--validator-set") else {
        print_launch_package_error(wants_json, &["missing --validator-set <path>".to_string()]);
        process::exit(1);
    };
    let Some(operator_handoff_path) = arg_value(args, "--operator-handoff") else {
        print_launch_package_error(
            wants_json,
            &["missing --operator-handoff <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(operator_acceptance_path) = arg_value(args, "--operator-acceptance") else {
        print_launch_package_error(
            wants_json,
            &["missing --operator-acceptance <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(genesis_path) = arg_value(args, "--genesis-manifest") else {
        print_launch_package_error(
            wants_json,
            &["missing --genesis-manifest <path>".to_string()],
        );
        process::exit(1);
    };

    let deployment_input = match read_text_file(deployment_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let public_status_input = match read_text_file(public_status_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let public_probe_input = match read_text_file(public_probe_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let validator_set_input = match read_text_file(validator_set_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let operator_handoff_input = match read_text_file(operator_handoff_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let operator_acceptance_input = match read_text_file(operator_acceptance_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let genesis_input = match read_text_file(genesis_path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_launch_package_with_operator_acceptance_jsons(
        &deployment_input,
        &public_status_input,
        &public_probe_input,
        &validator_set_input,
        &operator_handoff_input,
        &operator_acceptance_input,
        &genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("launch package report serializes")
                );
            } else {
                println!("Launch package verified at {}.", report.genesis_root);
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_launch_package_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_launch_package_bundle(args: &[String], wants_json: bool) {
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_launch_package_bundle_json_pretty(
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_launch_package_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_launch_package_bundle(path: &str, args: &[String], wants_json: bool) {
    let bundle_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_launch_package_bundle_jsons(
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("launch package bundle report serializes")
                );
            } else {
                println!(
                    "Launch package bundle verified at {}.",
                    report.launch_package_bundle_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_launch_package_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_launch_package_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_public_testnet_peer_manifest(args: &[String], wants_json: bool) {
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_public_testnet_peer_manifest_json_pretty(
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_testnet_peer_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_testnet_peer_manifest_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_public_testnet_peer_manifest(path: &str, args: &[String], wants_json: bool) {
    let peer_manifest_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_testnet_peer_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_public_testnet_peer_manifest_jsons(
        &peer_manifest_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("public testnet peer manifest report serializes")
                );
            } else {
                println!(
                    "Public testnet peer manifest verified at {}.",
                    report.public_testnet_peer_manifest_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_testnet_peer_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_testnet_peer_manifest_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_validator_activation(args: &[String], wants_json: bool) {
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_validator_activation_json_pretty(
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_validator_activation_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_validator_activation_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_validator_activation(path: &str, args: &[String], wants_json: bool) {
    let activation_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_validator_activation_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_validator_activation_jsons(
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("validator activation report serializes")
                );
            } else {
                println!(
                    "Validator activation verified at {}.",
                    report.validator_activation_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_validator_activation_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_validator_activation_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_validator_join(args: &[String], wants_json: bool) {
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_validator_join_receipt_json_pretty(
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_validator_join_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_validator_join_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_validator_join(path: &str, args: &[String], wants_json: bool) {
    let join_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_validator_join_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_validator_join_receipt_jsons(
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("validator join report serializes")
                );
            } else {
                println!("Validator join verified at {}.", report.validator_join_root);
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_validator_join_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_validator_join_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_operator_join_confirmation(args: &[String], wants_json: bool) {
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_operator_join_confirmation_json_pretty(
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_operator_join_confirmation_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_operator_join_confirmation_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_operator_join_confirmation(path: &str, args: &[String], wants_json: bool) {
    let confirmation_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_join_confirmation_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_operator_join_confirmation_jsons(
        &confirmation_input,
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("operator join confirmation report serializes")
                );
            } else {
                println!(
                    "Operator join confirmation verified at {}.",
                    report.operator_join_confirmation_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_operator_join_confirmation_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_operator_join_confirmation_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_public_observer_confirmation(args: &[String], wants_json: bool) {
    let operator_join_confirmation_input = read_operator_join_confirmation_input(args, wants_json);
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_public_observer_confirmation_json_pretty(
        &operator_join_confirmation_input,
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_observer_confirmation_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_observer_confirmation_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_public_observer_confirmation(path: &str, args: &[String], wants_json: bool) {
    let observer_confirmation_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_observer_confirmation_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let operator_join_confirmation_input = read_operator_join_confirmation_input(args, wants_json);
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_public_observer_confirmation_jsons(
        &observer_confirmation_input,
        &operator_join_confirmation_input,
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("public observer confirmation report serializes")
                );
            } else {
                println!(
                    "Public observer confirmation verified at {}.",
                    report.public_observer_confirmation_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_observer_confirmation_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_observer_confirmation_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_public_testnet_launch_certificate(args: &[String], wants_json: bool) {
    let public_observer_confirmation_input =
        read_public_observer_confirmation_input(args, wants_json);
    let runtime_surface_evidence_input = read_runtime_surface_evidence_input(args, wants_json);
    let operator_join_confirmation_input = read_operator_join_confirmation_input(args, wants_json);
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::build_public_testnet_launch_certificate_json_pretty(
        &public_observer_confirmation_input,
        &runtime_surface_evidence_input,
        &operator_join_confirmation_input,
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_testnet_launch_certificate_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_testnet_launch_certificate_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_public_testnet_launch_certificate(path: &str, args: &[String], wants_json: bool) {
    let certificate_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_testnet_launch_certificate_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let public_observer_confirmation_input =
        read_public_observer_confirmation_input(args, wants_json);
    let runtime_surface_evidence_input = read_runtime_surface_evidence_input(args, wants_json);
    let operator_join_confirmation_input = read_operator_join_confirmation_input(args, wants_json);
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_public_testnet_launch_certificate_jsons(
        &certificate_input,
        &public_observer_confirmation_input,
        &runtime_surface_evidence_input,
        &operator_join_confirmation_input,
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("public testnet launch certificate report serializes")
                );
            } else {
                println!(
                    "Public testnet launch certificate verified at {}.",
                    report.public_testnet_launch_certificate_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_testnet_launch_certificate_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_testnet_launch_certificate_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_public_testnet_launch_readiness(path: &str, args: &[String], wants_json: bool) {
    let certificate_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_public_testnet_launch_readiness_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let public_observer_confirmation_input =
        read_public_observer_confirmation_input(args, wants_json);
    let runtime_surface_evidence_input = read_runtime_surface_evidence_input(args, wants_json);
    let live_rpc_devnet_rehearsal_input = read_live_rpc_devnet_rehearsal_input(args, wants_json);
    let live_rpc_devnet_runtime_surface_evidence_input =
        read_live_rpc_devnet_runtime_surface_evidence_input(args, wants_json);
    let operator_join_confirmation_input = read_operator_join_confirmation_input(args, wants_json);
    let join_input = read_validator_join_input(args, wants_json);
    let activation_input = read_validator_activation_input(args, wants_json);
    let bundle_input = read_launch_package_bundle_input(args, wants_json);
    let inputs = read_launch_package_inputs(args, wants_json);

    match nebula_testnet::verify_public_testnet_launch_readiness_jsons(
        &certificate_input,
        &public_observer_confirmation_input,
        &runtime_surface_evidence_input,
        &live_rpc_devnet_rehearsal_input,
        &live_rpc_devnet_runtime_surface_evidence_input,
        &operator_join_confirmation_input,
        &join_input,
        &activation_input,
        &bundle_input,
        &inputs.deployment_input,
        &inputs.public_status_input,
        &inputs.public_probe_input,
        &inputs.validator_set_input,
        &inputs.operator_handoff_input,
        &inputs.operator_acceptance_input,
        &inputs.genesis_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("public testnet launch readiness report serializes")
                );
            } else {
                println!(
                    "Public testnet launch readiness verified at {}.",
                    report.public_launch_readiness_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_public_testnet_launch_readiness_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_public_testnet_launch_readiness_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_genesis_manifest(args: &[String], wants_json: bool) {
    let Some(deployment_path) = arg_value(args, "--deployment-attestation") else {
        print_genesis_manifest_error(
            wants_json,
            &["missing --deployment-attestation <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(validator_set_path) = arg_value(args, "--validator-set") else {
        print_genesis_manifest_error(wants_json, &["missing --validator-set <path>".to_string()]);
        process::exit(1);
    };

    let deployment_input = match read_text_file(deployment_path) {
        Ok(input) => input,
        Err(error) => {
            print_genesis_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let validator_set_input = match read_text_file(validator_set_path) {
        Ok(input) => input,
        Err(error) => {
            print_genesis_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::build_genesis_manifest_json_pretty(
        &deployment_input,
        &validator_set_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_genesis_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_genesis_manifest_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_operator_handoff(args: &[String], wants_json: bool) {
    let Some(deployment_path) = arg_value(args, "--deployment-attestation") else {
        print_operator_handoff_error(
            wants_json,
            &["missing --deployment-attestation <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(validator_set_path) = arg_value(args, "--validator-set") else {
        print_operator_handoff_error(wants_json, &["missing --validator-set <path>".to_string()]);
        process::exit(1);
    };

    let deployment_input = match read_text_file(deployment_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let validator_set_input = match read_text_file(validator_set_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::build_operator_handoff_json_pretty(
        &deployment_input,
        &validator_set_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_operator_handoff_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_operator_handoff(path: &str, args: &[String], wants_json: bool) {
    let Some(deployment_path) = arg_value(args, "--deployment-attestation") else {
        print_operator_handoff_error(
            wants_json,
            &["missing --deployment-attestation <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(validator_set_path) = arg_value(args, "--validator-set") else {
        print_operator_handoff_error(wants_json, &["missing --validator-set <path>".to_string()]);
        process::exit(1);
    };

    let handoff_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let deployment_input = match read_text_file(deployment_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let validator_set_input = match read_text_file(validator_set_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_operator_handoff_jsons(
        &handoff_input,
        &deployment_input,
        &validator_set_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("operator handoff report serializes")
                );
            } else {
                println!(
                    "Operator handoff verified at {}.",
                    report.operator_handoff_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_operator_handoff_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_operator_handoff_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn build_operator_acceptance(args: &[String], wants_json: bool) {
    let Some(handoff_path) = arg_value(args, "--operator-handoff") else {
        print_operator_acceptance_error(
            wants_json,
            &["missing --operator-handoff <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(deployment_path) = arg_value(args, "--deployment-attestation") else {
        print_operator_acceptance_error(
            wants_json,
            &["missing --deployment-attestation <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(validator_set_path) = arg_value(args, "--validator-set") else {
        print_operator_acceptance_error(
            wants_json,
            &["missing --validator-set <path>".to_string()],
        );
        process::exit(1);
    };

    let handoff_input = match read_text_file(handoff_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let deployment_input = match read_text_file(deployment_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let validator_set_input = match read_text_file(validator_set_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::build_operator_acceptance_json_pretty(
        &handoff_input,
        &deployment_input,
        &validator_set_input,
    ) {
        Ok(output) => println!("{output}"),
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_operator_acceptance_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_operator_acceptance(path: &str, args: &[String], wants_json: bool) {
    let Some(handoff_path) = arg_value(args, "--operator-handoff") else {
        print_operator_acceptance_error(
            wants_json,
            &["missing --operator-handoff <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(deployment_path) = arg_value(args, "--deployment-attestation") else {
        print_operator_acceptance_error(
            wants_json,
            &["missing --deployment-attestation <path>".to_string()],
        );
        process::exit(1);
    };
    let Some(validator_set_path) = arg_value(args, "--validator-set") else {
        print_operator_acceptance_error(
            wants_json,
            &["missing --validator-set <path>".to_string()],
        );
        process::exit(1);
    };

    let acceptance_input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let handoff_input = match read_text_file(handoff_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let deployment_input = match read_text_file(deployment_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };
    let validator_set_input = match read_text_file(validator_set_path) {
        Ok(input) => input,
        Err(error) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_operator_acceptance_jsons(
        &acceptance_input,
        &handoff_input,
        &deployment_input,
        &validator_set_input,
    ) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("operator acceptance report serializes")
                );
            } else {
                println!(
                    "Operator acceptance verified at {}.",
                    report.operator_acceptance_root
                );
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_operator_acceptance_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_operator_acceptance_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_genesis_manifest(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_genesis_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_genesis_manifest_json(&input) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .expect("genesis manifest report serializes")
                );
            } else {
                println!("Genesis manifest verified at {}.", report.genesis_root);
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_genesis_manifest_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_genesis_manifest_error(wants_json, &errors);
            process::exit(1);
        }
    }
}

fn verify_validator_set(path: &str, wants_json: bool) {
    let input = match read_text_file(path) {
        Ok(input) => input,
        Err(error) => {
            print_validator_set_error(wants_json, &[error]);
            process::exit(1);
        }
    };

    match nebula_testnet::verify_validator_set_json(&input) {
        Ok(report) => {
            if wants_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("validator set report serializes")
                );
            } else {
                println!("Validator set verified at {}.", report.validator_set_root);
            }
        }
        Err(nebula_testnet::AttestationError::MalformedJson(error)) => {
            print_validator_set_error(wants_json, &[error]);
            process::exit(1);
        }
        Err(nebula_testnet::AttestationError::Invalid(errors)) => {
            print_validator_set_error(wants_json, &errors);
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

fn print_deployment_attestation_builder_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "deployment_attestation_ready": false,
                "level": "deployment-attestation-build-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Deployment attestation build rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_public_status_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "public_status_ready": false,
                "level": "public-status-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Public status rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_public_probe_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "public_probe_ready": false,
                "level": "public-probe-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Public probe rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_runtime_launch_binding_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "runtime_launch_binding_ready": false,
                "level": "runtime-launch-binding-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Runtime launch binding rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_runtime_surface_evidence_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "runtime_surface_ready": false,
                "level": "runtime-surface-evidence-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Runtime surface evidence rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_receipt_report(report: &nebula_testnet::ReceiptReport, wants_json: bool) {
    if wants_json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).expect("receipt report serializes")
        );
    } else {
        println!("Receipt verified at {}.", report.receipt_root);
    }
}

fn print_bridge_evidence_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "bridge_evidence_ready": false,
                "level": "bridge-evidence-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Bridge evidence rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_receipt_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "receipt_ready": false,
                "level": "receipt-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Receipt rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_validator_set_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "validator_set_ready": false,
                "level": "validator-set-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Validator set rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_genesis_manifest_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "genesis_ready": false,
                "level": "genesis-manifest-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Genesis manifest rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_operator_handoff_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "operator_handoff_ready": false,
                "level": "operator-handoff-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Operator handoff rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_operator_acceptance_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "operator_acceptance_ready": false,
                "level": "operator-acceptance-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Operator acceptance rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_launch_package_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "launch_package_ready": false,
                "level": "launch-package-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Launch package rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_public_testnet_peer_manifest_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "public_testnet_peer_manifest_ready": false,
                "level": "public-testnet-peer-manifest-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Public testnet peer manifest rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_validator_activation_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "validator_activation_ready": false,
                "level": "validator-activation-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Validator activation rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_validator_join_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "validator_join_ready": false,
                "level": "validator-join-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Validator join rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_operator_join_confirmation_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "operator_join_confirmation_ready": false,
                "level": "operator-join-confirmation-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Operator join confirmation rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_public_observer_confirmation_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "public_observer_confirmation_ready": false,
                "level": "public-observer-confirmation-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Public observer confirmation rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_public_testnet_launch_certificate_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        println!(
            "{}",
            serde_json::json!({
                "public_testnet_launch_certificate_ready": false,
                "level": "public-testnet-launch-certificate-rejected",
                "errors": errors,
            })
        );
    } else {
        eprintln!("Public testnet launch certificate rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_public_testnet_launch_readiness_error(wants_json: bool, errors: &[String]) {
    if wants_json {
        let report = nebula_testnet::public_testnet_launch_readiness_rejection_report(errors);
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .expect("public testnet launch readiness rejection serializes")
        );
    } else {
        eprintln!("Public testnet launch readiness rejected:");
        for error in errors {
            eprintln!("- {error}");
        }
    }
}

fn print_help() {
    println!(
        "nebula-testnet\n\nUSAGE:\n    nebula-testnet [--mainnet-readiness] [--json]\n    nebula-testnet --prove-local-public-testnet [--json]\n    nebula-testnet --prove-live-rpc-devnet [--launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>] [--live-rpc-devnet-runtime-surface-out <path>] [--json]\n    nebula-testnet --run-rpc [--sequencer|--follower] [--rpc-bind <addr:port>] [--admin-rpc-bind <addr:port>] [--block-ms <ms>] [--validator-id <id>] [--sequencer-public-key <hex>] [--sequencer-secret-key <hex>] [--admin-token <token>] [--data-dir <path>] [--bootstrap-rpc <url>] [--sync-rpc <url>]... [--sync-peer-quorum <count>] [--public-testnet-peer-manifest <path>] [--disable-nbla-faucet] [--max-mempool-transactions <count>] [--max-request-bytes <bytes>] [--max-requests-per-minute <count>] [--max-active-connections <count>] [--admin-max-active-connections <count>]\n    nebula-testnet --build-public-status --endpoint-url <url> [--artifact-sha3-256 <hex>] [--cargo-lock-sha3-256 <hex>]\n    nebula-testnet --build-public-probe --endpoint-url <url> [--artifact-sha3-256 <hex>] [--cargo-lock-sha3-256 <hex>]\n    nebula-testnet --build-runtime-surface-evidence --endpoint-url <url> --health <path> --status <path> --snapshot <path> --ops <path> --backup <path> --rpc-status <path> --rpc-ops-status <path> --rpc-backup-manifest <path> --metrics <path> [--captured-at-unix-ms <ms>]\n    nebula-testnet --verify-runtime-surface-evidence <path> [--json]\n    nebula-testnet --build-deployment-attestation --public-status <path> --public-probe <path> --preflight-receipt <path> --runbook-receipt <path> --tls-pin <cert_sha256,public_key_sha256,not_after_unix_ms>... --bootstrap-node <node_id,operator_id,region,endpoint>... --operator <operator_id,region,public_key>... --observer <observer_id,region,public_key[,secret_key_hex]>... --rollback-plan-sha3-256 <hex> --rollback-recovery-root <hex> [--rollback-last-drill-unix-ms <ms>] [--generated-at-unix-ms <ms>] [--expires-at-unix-ms <ms>] [--artifact-sha3-256 <hex>] [--cargo-lock-sha3-256 <hex>]\n    nebula-testnet --sample-public-status\n    nebula-testnet --verify-public-status <path> [--json]\n    nebula-testnet --sample-public-probe\n    nebula-testnet --verify-public-probe <path> [--json]\n    nebula-testnet --sample-preflight-receipt\n    nebula-testnet --verify-preflight-receipt <path> [--json]\n    nebula-testnet --sample-runbook-receipt\n    nebula-testnet --verify-runbook-receipt <path> [--json]\n    nebula-testnet --sample-deployment-attestation\n    nebula-testnet --verify-deployment-attestation <path> [--json]\n    nebula-testnet --sample-validator-set\n    nebula-testnet --verify-validator-set <path> [--json]\n    nebula-testnet --sample-operator-handoff\n    nebula-testnet --build-operator-handoff --deployment-attestation <path> --validator-set <path>\n    nebula-testnet --verify-operator-handoff <path> --deployment-attestation <path> --validator-set <path> [--json]\n    nebula-testnet --sample-operator-acceptance\n    nebula-testnet --build-operator-acceptance --operator-handoff <path> --deployment-attestation <path> --validator-set <path>\n    nebula-testnet --verify-operator-acceptance <path> --operator-handoff <path> --deployment-attestation <path> --validator-set <path> [--json]\n    nebula-testnet --sample-genesis-manifest\n    nebula-testnet --build-genesis-manifest --deployment-attestation <path> --validator-set <path>\n    nebula-testnet --verify-genesis-manifest <path> [--json]\n    nebula-testnet --verify-launch-package --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]\n    nebula-testnet --build-launch-package-bundle --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>\n    nebula-testnet --verify-launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]\n    nebula-testnet --build-validator-activation --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>\n    nebula-testnet --verify-validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]
    nebula-testnet --build-public-testnet-peer-manifest --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>
    nebula-testnet --verify-public-testnet-peer-manifest <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]
    nebula-testnet --build-live-rpc-devnet-runtime-surface --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>
    nebula-testnet --sign-bridge-observer-evidence --bridge-deposit <path> --observer-id <id> --observer-secret-key <hex> [--signed-at-unix-ms <ms>]
    nebula-testnet --assemble-bridge-deposit --bridge-deposit <path> --observer-evidence <path>...
    nebula-testnet --sign-withdrawal-operator-approval --withdrawal <path> --finalized-monero-tx-id <hex> --finalization-proof-root <hex> --operator-id <id> --operator-secret-key <hex> [--signed-at-unix-ms <ms>]
    nebula-testnet --assemble-finalize-withdrawal --withdrawal <path> --finalized-monero-tx-id <hex> --finalization-proof-root <hex> --operator-approval <path>... [--admin-token <token>]
    nebula-testnet --sign-sequencer-rotation-approval --launch-package-bundle-root <hex> --previous-sequencer-key-history-root <hex> --activation-height <height> --old-sequencer-public-key <hex> --new-sequencer-public-key <hex> --rotation-proof-root <hex> --operator-id <id> --operator-secret-key <hex> [--signed-at-unix-ms <ms>]
    nebula-testnet --assemble-sequencer-rotation --launch-package-bundle-root <hex> --previous-sequencer-key-history-root <hex> --activation-height <height> --old-sequencer-public-key <hex> --new-sequencer-secret-key-hex <hex> --rotation-proof-root <hex> --operator-approval <path>... [--admin-token <token>]
    nebula-testnet --build-validator-join --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>
    nebula-testnet --verify-validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]
    nebula-testnet --build-operator-join-confirmation --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>
    nebula-testnet --verify-operator-join-confirmation <path> --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]
    nebula-testnet --build-public-observer-confirmation --operator-join-confirmation <path> --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>
    nebula-testnet --verify-public-observer-confirmation <path> --operator-join-confirmation <path> --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]
    nebula-testnet --build-public-testnet-launch-certificate --public-observer-confirmation <path> --runtime-surface-evidence <path> --operator-join-confirmation <path> --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path>
    nebula-testnet --verify-public-testnet-launch-certificate <path> --public-observer-confirmation <path> --runtime-surface-evidence <path> --operator-join-confirmation <path> --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]
    nebula-testnet --verify-public-testnet-launch-readiness <path> --public-observer-confirmation <path> --runtime-surface-evidence <path> --live-rpc-devnet-rehearsal <path> --live-rpc-devnet-runtime-surface-evidence <path> --operator-join-confirmation <path> --validator-join <path> --validator-activation <path> --launch-package-bundle <path> --deployment-attestation <path> --public-status <path> --public-probe <path> --validator-set <path> --operator-handoff <path> --operator-acceptance <path> --genesis-manifest <path> [--json]

FINAL PUBLIC LAUNCH READINESS:
    --verify-public-testnet-launch-readiness is the only artifact-bound gate
    that emits public_launch_ready=true. It requires the final launch
    certificate plus external-public runtime-surface evidence captured from the
    advertised endpoint, a live RPC devnet rehearsal report, and the verified
    loopback-devnet runtime-surface evidence whose root the rehearsal reports.

LOCAL PUBLIC TESTNET REHEARSAL:
    --prove-local-public-testnet builds and verifies a coherent local launch
    artifact chain from public status/probe samples through deployment
    attestation, validator activation, public observer confirmation, and the
    public testnet launch-candidate certificate. The report proves local
    launch mechanics are rehearsed while public_launch_ready stays false until
    live deployment attestation is supplied.
    --prove-live-rpc-devnet starts loopback sequencer and follower RPC nodes,
    produces sub-second blocks, exercises nXMR bridge deposit, nXMR gas
    buyback/reward accounting, withdrawal finalization, follower sync, and
    runtime surface evidence while keeping public_launch_ready false until
    live deployment attestation is supplied. When launch artifacts are supplied,
    the report is root-bound to that endpoint and launch-package bundle for
    final public launch readiness.

RPC USER SPEND SIGNATURES:
    Public spend calls require Ed25519 account ownership. For
    nebula_sendTransaction, tx.from is the 32-byte account public key hex and
    tx.signature signs RuntimeTransaction::signing_root(). For
    nebula_requestWithdrawal, nonce and signature bind
    withdrawal_authorization_root(account, monero_address, amount_nxmr_units,
    nonce) before nXMR is burned into operator_pending.

RPC BRIDGE POLICY:
    Policy discovery uses nebula_bridgePolicy. Deposits use
    nebula_observeBridgeDeposit with monero_tx_id, account, amount_nxmr_units,
    confirmations, observer_id, proof_root, custody_proof_root,
    relayer_set_root, observer_signature_roots, signed observer_evidence, and
    observed_at_unix_ms.
    Public testnet policy requires the Monero confirmation floor, custody
    proof, relayer/observer evidence, and replay protection before crediting
    nXMR. The faucet must keep faucet_nxmr_units at zero; bridge_only_nxmr,
    bridge_custody_reconciled, and nxmr_custody_deficit_units must prove that
    nXMR balances are backed by bridge deposits.
    Withdrawals use nebula_requestWithdrawal with account, monero_address,
    amount_nxmr_units, nonce, and signature, then remain operator_pending until
    nebula_finalizeWithdrawal binds withdrawal_id, finalized_monero_tx_id,
    finalization_proof_root, operator_approval_roots, and signed
    operator_approvals. /health, /status, and nebula_status expose bridge
    policy readiness.

BRIDGE EVIDENCE TOOLING:
    Run --sign-bridge-observer-evidence on each observer signer, then
    --assemble-bridge-deposit before submitting nebula_observeBridgeDeposit.
    Run --sign-withdrawal-operator-approval on each operator signer, then
    --assemble-finalize-withdrawal to build nebula_finalizeWithdrawal params.
    Run --sign-sequencer-rotation-approval on each launch-attested operator
    signer, then --assemble-sequencer-rotation to build
    nebula_rotateSequencerKey params. Rotation approvals are bound to the
    launch-package bundle root, previous key-history root, activation height,
    old/new sequencer public keys, and rotation proof root.

RPC OPERATOR OPS, BACKUP, AND METRICS:
    Operator ops discovery uses /ops and nebula_opsStatus. Backup discovery
    uses /backup and nebula_backupManifest. Scrapeable monitoring uses
    /metrics. Public operators must verify block freshness, latest height/hash,
    state and snapshot roots, persisted snapshot path and presence, sync peer
    count/quorum, sync quorum height/hash/state root, successful sync peer
    count, sync attempt/success/failure/import and quorum rejection counts,
    mempool capacity and full/admission rejection counts, RPC
    request-size/rate-limit policy, private admin listener state, public-admin
    isolation, non-dev sequencer-key status, bridge policy root, bridge
    custody reconciliation, backup manifest root, and public ops readiness
    gauges before opening a public testnet endpoint. Runtime surface evidence
    binds captured /health, /status, /snapshot, /ops, /backup, JSON-RPC mirror
    responses, and /metrics text into one root so observers can reject stale
    or split-brain endpoint views.

RPC ADMIN BOUNDARY:
    Public RPC methods remain callable without an admin token. Operator-only
    methods require --admin-rpc-bind, --admin-token, and JSON-RPC
    params.admin_token on the private admin listener:
    nebula_importSnapshot, nebula_observeBridgeDeposit,
    nebula_finalizeWithdrawal, nebula_rotateSequencerKey,
    nebula_reportEquivocation, and nebula_produceBlock. The public listener
    rejects those methods even with a valid token. Accountability evidence
    disables block production and state mutations until the operator resolves it.

RPC SEQUENCER KEY ACCOUNTABILITY:
    Key/accountability discovery uses /health, /status, and nebula_status. Public
    operators must verify the active sequencer public key, key-rotation
    history/root, latest rotation activation height, accountability evidence
    root, equivocation evidence, and mis-signing evidence before opening a
    public endpoint.
    Key rotation uses nebula_rotateSequencerKey with admin_token,
    new_sequencer_secret_key_hex, rotation_proof_root, operator_approval_ids,
    operator_approval_roots, and signed operator_approvals; the response binds
    old/new sequencer keys, activation height, approval quorum, and rotation root.
    Equivocation reporting uses nebula_reportEquivocation with admin_token,
    height, first_block_hash, second_block_hash, reporter_id, and evidence_root.
    Unresolved accountability evidence keeps the endpoint fail-closed.

LIVE RPC RUNTIME SURFACE:
    --build-live-rpc-devnet-runtime-surface starts loopback launch-bound
    sequencer and follower RPC nodes from a verified launch package and emits
    loopback-devnet runtime-surface evidence for inspection and certificate
    rehearsal.
    --prove-live-rpc-devnet --live-rpc-devnet-runtime-surface-out <path> writes
    the matching loopback runtime-surface evidence captured during the same
    rehearsal run.
    --capture-public-runtime-surface fetches the deployment attestation's
    HTTPS /status origin, captures /health, /status, /snapshot, /ops, /backup,
    /metrics, and JSON-RPC mirrors, and requires each response TLS leaf cert,
    SPKI, and not_after to match an attested tls_pins row before recording that
    live TLS observation into external-public-endpoint runtime-surface evidence.
    Usage: nebula-testnet --capture-public-runtime-surface
    --deployment-attestation <path> [--endpoint-url <url>] [--timeout-ms <ms>]
    Manual --build-runtime-surface-evidence runs must supply
    --runtime-surface-tls-pin <cert_sha256,public_key_sha256,not_after_unix_ms>.
    RPC bootstrap and follower sync reject peer HTTP responses above
    --max-snapshot-response-bytes before snapshot parsing.
    Public HTTPS deployments behind reverse proxies must use
    --trusted-proxy-ip <ip> for each immediate proxy. The proxy must strip
    inbound Forwarded/X-Forwarded-For headers and set one canonical client IP.
    --trust-private-proxy-headers is for loopback/private local rehearsals only
    and does not satisfy public launch readiness.

PEER MANIFEST:
    --build-public-testnet-peer-manifest emits the launch-bound RPC/status/snapshot
    peer manifest from the verified launch-package bundle and launch artifacts.
    --verify-public-testnet-peer-manifest verifies that peer manifest against the
    same bundle, validator set, endpoint, and artifact roots.

OPTIONS:\n    --mainnet-readiness              Emit the public launch readiness contract\n    --prove-local-public-testnet     Build and verify the local launch rehearsal chain\n    --prove-live-rpc-devnet          Start loopback RPC nodes and prove live devnet behavior\n    --run-rpc                        Run the public-testnet RPC node with bridge and ops/backup status\n    --sequencer                      Produce sub-second blocks locally (default)\n    --follower                       Disable local production and follow a sequencer peer set\n    --rpc-bind                       RPC bind address, default 127.0.0.1:9944\n    --block-ms                       Block target in ms; public testnet requires < 1000\n    --validator-id                   Local validator producer ID for block rewards\n    --sequencer-public-key           Expected Ed25519 sequencer public key for signed blocks\n    --sequencer-secret-key           Local Ed25519 sequencer signing seed; never exported in snapshots\n    --admin-token <token>            Enables operator-only JSON-RPC methods; never printed\n    --data-dir                       Persist node snapshots under this directory\n    --bootstrap-rpc                  Import an ahead peer snapshot before serving\n    --sync-rpc                       Repeatable snapshot peer for continuous follower sync/failover\n    --sync-peer-quorum               Matching sync peer snapshots required before follower import\n    --public-testnet-peer-manifest   Verify launch peer manifest and derive follower sync peers\n    --disable-nbla-faucet            Set the public NBLA faucet amount to zero for launch-bound RPC\n    --max-mempool-transactions       Maximum pending transactions admitted to local mempool\n    --max-request-bytes              Maximum accepted HTTP request body size in bytes\n    --max-requests-per-minute        Per-client RPC request budget per listener per minute\n    --max-active-connections         Maximum active public RPC connections before listener rejection\n    --admin-max-active-connections   Maximum active private admin RPC connections before listener rejection\n    --build-public-status            Build public status for a real endpoint URL\n    --build-public-probe             Build public probe evidence for a real endpoint URL\n    --build-runtime-surface-evidence Build root-bound evidence from captured live RPC surfaces\n    --verify-runtime-surface-evidence Verify captured runtime-surface evidence\n    --health                         Captured GET /health JSON for runtime-surface evidence\n    --status                         Captured GET /status JSON for runtime-surface evidence\n    --snapshot                       Captured GET /snapshot JSON for runtime-surface evidence\n    --ops                            Captured GET /ops JSON for runtime-surface evidence\n    --backup                         Captured GET /backup JSON for runtime-surface evidence\n    --rpc-status                     Captured nebula_status JSON-RPC response\n    --rpc-ops-status                 Captured nebula_opsStatus JSON-RPC response\n    --rpc-backup-manifest            Captured nebula_backupManifest JSON-RPC response\n    --metrics                        Captured GET /metrics text for runtime-surface evidence\n    --captured-at-unix-ms            Override runtime-surface evidence capture time\n    --runtime-surface-evidence       Runtime surface evidence input for launch certificate\n    --live-rpc-devnet-rehearsal      Live RPC devnet rehearsal input for final launch readiness\n    --live-rpc-devnet-runtime-surface-out Write matching loopback runtime evidence during rehearsal\n    --live-rpc-devnet-runtime-surface-evidence Verified loopback surface evidence for final launch readiness\n    --build-deployment-attestation   Build deployment evidence from public surface and receipt files\n    --endpoint-url                   HTTPS public status/probe/runtime endpoint URL for builders\n    --artifact-sha3-256              64-hex package artifact hash for builder identity\n    --cargo-lock-sha3-256            64-hex Cargo.lock hash for builder identity\n    --preflight-receipt              Preflight receipt input for deployment-attestation builder\n    --runbook-receipt                Runbook receipt input for deployment-attestation builder\n    --tls-pin                        Repeatable cert_sha256,public_key_sha256,not_after_unix_ms row\n    --bootstrap-node                 Repeatable node_id,operator_id,region,endpoint row\n    --operator                       Repeatable operator_id,region,public_key row\n    --observer                       Repeatable observer_id,region,public_key[,secret_key_hex] row\n    --rollback-plan-sha3-256         64-hex rollback plan hash for deployment evidence\n    --rollback-recovery-root         64-hex recovery point root for deployment evidence\n    --rollback-last-drill-unix-ms    Rollback drill completion time for deployment evidence\n    --generated-at-unix-ms           Override generated time for deployment evidence\n    --expires-at-unix-ms             Override expiry time for deployment evidence\n    --sample-public-status           Emit a public status manifest sample\n    --verify-public-status           Verify a public status manifest file\n    --sample-public-probe            Emit a public probe sample\n    --verify-public-probe            Verify a public probe file\n    --sample-preflight-receipt       Emit a preflight receipt sample\n    --verify-preflight-receipt       Verify a preflight receipt file\n    --sample-runbook-receipt         Emit a runbook receipt sample\n    --verify-runbook-receipt         Verify a runbook receipt file\n    --sample-deployment-attestation  Emit a fillable deployment attestation sample\n    --verify-deployment-attestation  Verify a deployment attestation file\n    --sample-validator-set           Emit a fillable validator-set manifest sample\n    --verify-validator-set           Verify a validator-set manifest file\n    --sample-operator-handoff        Emit a sample operator handoff manifest\n    --build-operator-handoff         Build operator handoff from attestation and validator set\n    --verify-operator-handoff        Verify an operator handoff manifest file\n    --sample-operator-acceptance     Emit a sample operator acceptance manifest\n    --build-operator-acceptance      Build operator acceptance from handoff, attestation, and validator set\n    --verify-operator-acceptance     Verify an operator acceptance manifest file\n    --operator-handoff               Operator handoff input for acceptance/package verification\n    --operator-acceptance            Operator acceptance input for launch package verification\n    --sample-genesis-manifest        Emit a sample genesis manifest built from samples\n    --build-genesis-manifest         Build genesis manifest from attestation and validator set\n    --deployment-attestation         Deployment attestation input for genesis build/package verification\n    --public-status                  Public status manifest input for launch package verification\n    --public-probe                   Public probe input for launch package verification\n    --validator-set                  Validator-set input for genesis build/package verification\n    --genesis-manifest               Genesis manifest input for launch package verification\n    --verify-genesis-manifest        Verify a genesis manifest file\n    --verify-launch-package          Verify deployment, public surface, validator set, genesis, handoff, and acceptance agree\n    --build-launch-package-bundle    Build the external validator launch-package bundle manifest\n    --verify-launch-package-bundle   Verify launch-package bundle hashes and roots against the artifact files\n    --launch-package-bundle          Launch-package bundle input for validator activation/join\n    --validator-activation           Validator activation input for join receipt verification\n    --validator-join                 Validator join input for operator confirmation\n    --operator-join-confirmation     Operator join confirmation input for public observer confirmation\n    --public-observer-confirmation   Public observer confirmation input for launch certificate\n    --build-validator-activation     Build validator activation from a verified launch-package bundle\n    --verify-validator-activation    Verify validators activated against the launch-package bundle\n    --build-validator-join           Build validator join receipt from activation and bundle evidence\n    --verify-validator-join          Verify validators joined at/after activation height\n    --build-operator-join-confirmation  Build operator confirmation from joined validators\n    --verify-operator-join-confirmation Verify operators confirmed the validator join receipt\n    --build-public-observer-confirmation Build observer confirmation from public endpoint evidence\n    --verify-public-observer-confirmation Verify observers confirmed the public endpoint post-join\n    --build-public-testnet-launch-certificate Build the final public testnet launch-candidate certificate\n    --verify-public-testnet-launch-certificate Verify the final launch-candidate certificate\n    --json                           Emit JSON output\n    -h, --help                       Show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls_pin(
        cert_sha256: &str,
        public_key_sha256: &str,
        not_after_unix_ms: u128,
    ) -> nebula_testnet::TlsEndpointPin {
        nebula_testnet::TlsEndpointPin {
            cert_sha256: cert_sha256.to_string(),
            public_key_sha256: public_key_sha256.to_string(),
            not_after_unix_ms,
        }
    }

    #[test]
    fn runtime_surface_tls_observation_parses_manual_pin() {
        assert!(parse_runtime_surface_tls_observation(&[], false).is_none());
        let args = vec![
            "--runtime-surface-tls-pin".to_string(),
            format!("{},{},{}", "aa".repeat(32), "bb".repeat(32), 9_999),
        ];

        let parsed = parse_runtime_surface_tls_observation(&args, false)
            .expect("runtime surface TLS observation parses");

        assert_eq!(parsed.cert_sha256, "aa".repeat(32));
        assert_eq!(parsed.public_key_sha256, "bb".repeat(32));
        assert_eq!(parsed.not_after_unix_ms, 9_999);
    }

    #[test]
    fn public_runtime_status_url_derives_sibling_paths() {
        let origin =
            parse_public_runtime_status_url("https://testnet.nebula.example:9443/rpc/status")
                .expect("status URL parses");

        assert_eq!(origin.host, "testnet.nebula.example");
        assert_eq!(origin.port, 9443);
        assert_eq!(origin.host_header, "testnet.nebula.example:9443");
        assert_eq!(origin.status_path, "/rpc/status");
        assert_eq!(runtime_capture_path(&origin, "health"), "/rpc/health");
        assert_eq!(runtime_capture_path(&origin, "metrics"), "/rpc/metrics");
    }

    #[test]
    fn public_runtime_status_url_rejects_ambiguous_paths() {
        let error = parse_public_runtime_status_url("https://testnet.nebula.example/ready")
            .expect_err("non-status paths are rejected");
        assert!(error.contains("must end with /status"));

        let error = parse_public_runtime_status_url("https://testnet.nebula.example/status?x=1")
            .expect_err("query strings are rejected");
        assert!(error.contains("query or fragment"));
    }

    #[test]
    fn chunked_http_response_decodes_extensions() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;foo=bar\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

        let body = parse_http_response_text("/metrics", response).expect("chunked body decodes");

        assert_eq!(body, "hello world");
    }

    #[test]
    fn http_response_rejects_redirects() {
        let response = b"HTTP/1.1 302 Found\r\nLocation: https://other.example/status\r\nContent-Length: 0\r\n\r\n";

        let error =
            parse_http_response_text("/status", response).expect_err("redirects are rejected");

        assert!(error.contains("302 Found"));
    }

    #[test]
    fn live_tls_pin_requires_cert_key_and_expiry_match() {
        let live = LiveTlsCertificateInfo {
            cert_sha256: "aa".repeat(32),
            public_key_sha256: "bb".repeat(32),
            not_after_unix_ms: 2_000,
        };
        let pins = vec![tls_pin(
            &live.cert_sha256,
            &live.public_key_sha256,
            live.not_after_unix_ms,
        )];

        verify_live_tls_pin("/status", &pins, &live, 1_000).expect("matching pin verifies");

        let wrong_cert = vec![tls_pin(
            "cc",
            &live.public_key_sha256,
            live.not_after_unix_ms,
        )];
        let error = verify_live_tls_pin("/status", &wrong_cert, &live, 1_000)
            .expect_err("cert mismatch rejects");
        assert!(error.contains("TLS pin mismatch"));

        let wrong_key = vec![tls_pin(&live.cert_sha256, "dd", live.not_after_unix_ms)];
        let error = verify_live_tls_pin("/status", &wrong_key, &live, 1_000)
            .expect_err("key mismatch rejects");
        assert!(error.contains("TLS pin mismatch"));

        let wrong_expiry = vec![tls_pin(&live.cert_sha256, &live.public_key_sha256, 3_000)];
        let error = verify_live_tls_pin("/status", &wrong_expiry, &live, 1_000)
            .expect_err("expiry mismatch rejects");
        assert!(error.contains("TLS pin mismatch"));

        let error =
            verify_live_tls_pin("/status", &pins, &live, 2_001).expect_err("expired cert rejects");
        assert!(error.contains("expired"));

        let changed = LiveTlsCertificateInfo {
            cert_sha256: live.cert_sha256.clone(),
            public_key_sha256: "ee".repeat(32),
            not_after_unix_ms: live.not_after_unix_ms,
        };
        let error = require_same_live_tls("/snapshot", &live, &changed)
            .expect_err("changed TLS observation rejects");
        assert!(error.contains("TLS observation changed"));
    }
}
