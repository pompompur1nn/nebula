use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, TARGET_BLOCK_MS,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceBenchmarkRun {
    pub benchmark_id: String,
    pub scenario: String,
    pub measured_at_height: i64,
    pub measured_at_ms: u64,
    pub include_pending: bool,
    pub benchmarker_label: String,
    pub profile_root: String,
    pub fee_curve_root: String,
    pub local_fee_market_root: String,
    pub confirmed_summary: Value,
    pub pending_summary: Value,
    pub latency_targets: Value,
    pub fee_curve: Vec<Value>,
    pub authorization: Authorization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceCalibrationRecord {
    pub calibration_id: String,
    pub source_benchmark_id: String,
    pub calibrated_at_height: i64,
    pub calibrated_at_ms: u64,
    pub calibrator_label: String,
    pub measured_proof_bytes: u64,
    pub measured_authorization_bytes: u64,
    pub measured_da_encoded_bytes: u64,
    pub measured_contract_runtime_ms: u64,
    pub measured_prover_ms: u64,
    pub measured_signer_ms: u64,
    pub measured_total_latency_ms: u64,
    pub estimated_proof_bytes: u64,
    pub estimated_authorization_bytes: u64,
    pub estimated_da_encoded_bytes: u64,
    pub estimated_execution_fuel: u64,
    pub estimated_privacy_proof_count: u64,
    pub estimated_authorization_count: u64,
    pub estimated_contract_call_count: u64,
    pub target_latency_ms: u64,
    pub proof_size_multiplier_bps: u64,
    pub authorization_size_multiplier_bps: u64,
    pub da_bandwidth_multiplier_bps: u64,
    pub contract_runtime_micros_per_fuel: u64,
    pub prover_micros_per_proof: u64,
    pub signer_micros_per_authorization: u64,
    pub target_latency_delta_ms: i64,
    pub calibrated_summary_root: String,
    pub authorization: Authorization,
}

fn value_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
pub fn benchmark_payload(
    scenario: &str,
    measured_at_height: i64,
    measured_at_ms: u64,
    include_pending: bool,
    benchmarker_label: &str,
    profile_root: &str,
    confirmed_summary: Value,
    pending_summary: Value,
    latency_targets: Value,
    fee_curve: Vec<Value>,
) -> Value {
    let fee_curve_root = merkle_root("DEVNET-PROFILE-FEE-CURVE", &fee_curve);
    let local_fee_market_root = merkle_root(
        "DEVNET-BENCHMARK-LOCAL-FEE-MARKET",
        &[
            json!(value_u64(&confirmed_summary, "max_fee_density_microunits")),
            json!(value_u64(&pending_summary, "max_fee_density_microunits")),
            json!(value_u64(&confirmed_summary, "tx_count")),
            json!(value_u64(&pending_summary, "tx_count")),
        ],
    );
    json!({
        "kind": "performance_benchmark_run",
        "chain_id": CHAIN_ID,
        "scenario": scenario,
        "measured_at_height": measured_at_height,
        "measured_at_ms": measured_at_ms,
        "include_pending": include_pending,
        "benchmarker_label": benchmarker_label,
        "profile_root": profile_root,
        "fee_curve_root": fee_curve_root,
        "local_fee_market_root": local_fee_market_root,
        "confirmed_summary": confirmed_summary,
        "pending_summary": pending_summary,
        "latency_targets": latency_targets,
        "fee_curve": fee_curve,
    })
}

pub fn benchmark_id_for_payload(payload: &Value) -> String {
    domain_hash("PERFORMANCE-BENCHMARK-ID", &[HashPart::Json(payload)], 32)
}

pub fn unsigned_benchmark_record(payload: &Value) -> Value {
    let mut record = payload.clone();
    let benchmark_id = benchmark_id_for_payload(payload);
    record["benchmark_id"] = json!(benchmark_id);
    record
}

pub fn benchmark_root(unsigned_record: &Value) -> String {
    domain_hash(
        "PERFORMANCE-BENCHMARK-RUN",
        &[HashPart::Json(unsigned_record)],
        32,
    )
}

pub fn sign_benchmark(payload: Value) -> PerformanceBenchmarkRun {
    let unsigned = unsigned_benchmark_record(&payload);
    let benchmarker_label = payload["benchmarker_label"]
        .as_str()
        .expect("benchmarker label");
    let authorization =
        sign_authorization(benchmarker_label, "performance_benchmark_run", &unsigned);
    PerformanceBenchmarkRun {
        benchmark_id: unsigned["benchmark_id"]
            .as_str()
            .expect("benchmark id")
            .to_string(),
        scenario: payload["scenario"].as_str().expect("scenario").to_string(),
        measured_at_height: payload["measured_at_height"].as_i64().expect("height"),
        measured_at_ms: payload["measured_at_ms"].as_u64().expect("timestamp"),
        include_pending: payload["include_pending"]
            .as_bool()
            .expect("include pending"),
        benchmarker_label: benchmarker_label.to_string(),
        profile_root: payload["profile_root"]
            .as_str()
            .expect("profile root")
            .to_string(),
        fee_curve_root: payload["fee_curve_root"]
            .as_str()
            .expect("fee curve root")
            .to_string(),
        local_fee_market_root: payload["local_fee_market_root"]
            .as_str()
            .expect("local fee root")
            .to_string(),
        confirmed_summary: payload["confirmed_summary"].clone(),
        pending_summary: payload["pending_summary"].clone(),
        latency_targets: payload["latency_targets"].clone(),
        fee_curve: payload["fee_curve"].as_array().expect("fee curve").clone(),
        authorization,
    }
}

pub fn verify_benchmark(run: &PerformanceBenchmarkRun) -> bool {
    let payload = benchmark_payload(
        &run.scenario,
        run.measured_at_height,
        run.measured_at_ms,
        run.include_pending,
        &run.benchmarker_label,
        &run.profile_root,
        run.confirmed_summary.clone(),
        run.pending_summary.clone(),
        run.latency_targets.clone(),
        run.fee_curve.clone(),
    );
    let unsigned = unsigned_benchmark_record(&payload);
    run.benchmark_id == unsigned["benchmark_id"].as_str().unwrap_or_default()
        && verify_authorization(
            &run.benchmarker_label,
            "performance_benchmark_run",
            &unsigned,
            &run.authorization,
        )
}

fn calibration_estimates(benchmark: &PerformanceBenchmarkRun) -> Value {
    let summaries = [&benchmark.confirmed_summary, &benchmark.pending_summary];
    let estimated_da_encoded_bytes = summaries
        .iter()
        .map(|summary| {
            let encoded = value_u64(summary, "da_encoded_bytes");
            if encoded == 0 {
                value_u64(summary, "batched_da_bytes")
            } else {
                encoded
            }
        })
        .sum::<u64>();
    let mut block_windows = value_u64(&benchmark.confirmed_summary, "block_count");
    if value_u64(&benchmark.pending_summary, "tx_count") > 0 {
        block_windows += 1;
    }
    json!({
        "estimated_proof_bytes": summaries.iter().map(|s| value_u64(s, "estimated_proof_bytes")).sum::<u64>(),
        "estimated_authorization_bytes": summaries.iter().map(|s| value_u64(s, "estimated_authorization_bytes")).sum::<u64>(),
        "estimated_da_encoded_bytes": estimated_da_encoded_bytes,
        "estimated_execution_fuel": summaries.iter().map(|s| value_u64(s, "execution_fuel")).sum::<u64>(),
        "estimated_privacy_proof_count": summaries.iter().map(|s| value_u64(s, "privacy_proof_count")).sum::<u64>(),
        "estimated_authorization_count": summaries.iter().map(|s| value_u64(s, "authorization_count")).sum::<u64>(),
        "estimated_contract_call_count": summaries.iter().map(|s| value_u64(s, "contract_call_count")).sum::<u64>(),
        "target_latency_ms": std::cmp::max(TARGET_BLOCK_MS, block_windows * TARGET_BLOCK_MS),
    })
}

fn ratio_bps(measured: u64, estimated: u64) -> u64 {
    (measured * 10_000).checked_div(estimated).unwrap_or(0)
}

fn micros_per(measured_ms: u64, count: u64) -> u64 {
    (measured_ms * 1_000).checked_div(count).unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
pub fn calibration_payload(
    benchmark: &PerformanceBenchmarkRun,
    calibrated_at_height: i64,
    calibrated_at_ms: u64,
    calibrator_label: &str,
    measured_proof_bytes: u64,
    measured_authorization_bytes: u64,
    measured_da_encoded_bytes: u64,
    measured_contract_runtime_ms: u64,
    measured_prover_ms: u64,
    measured_signer_ms: u64,
    measured_total_latency_ms: u64,
) -> Value {
    let estimates = calibration_estimates(benchmark);
    let estimated_proof_bytes = value_u64(&estimates, "estimated_proof_bytes");
    let estimated_authorization_bytes = value_u64(&estimates, "estimated_authorization_bytes");
    let estimated_da_encoded_bytes = value_u64(&estimates, "estimated_da_encoded_bytes");
    let estimated_execution_fuel = value_u64(&estimates, "estimated_execution_fuel");
    let estimated_privacy_proof_count = value_u64(&estimates, "estimated_privacy_proof_count");
    let estimated_authorization_count = value_u64(&estimates, "estimated_authorization_count");
    let target_latency_ms = value_u64(&estimates, "target_latency_ms");
    let summary = json!({
        "source_benchmark_id": benchmark.benchmark_id,
        "estimated_proof_bytes": estimated_proof_bytes,
        "estimated_authorization_bytes": estimated_authorization_bytes,
        "estimated_da_encoded_bytes": estimated_da_encoded_bytes,
        "estimated_execution_fuel": estimated_execution_fuel,
        "estimated_privacy_proof_count": estimated_privacy_proof_count,
        "estimated_authorization_count": estimated_authorization_count,
        "estimated_contract_call_count": value_u64(&estimates, "estimated_contract_call_count"),
        "target_latency_ms": target_latency_ms,
        "measured_proof_bytes": measured_proof_bytes,
        "measured_authorization_bytes": measured_authorization_bytes,
        "measured_da_encoded_bytes": measured_da_encoded_bytes,
        "measured_contract_runtime_ms": measured_contract_runtime_ms,
        "measured_prover_ms": measured_prover_ms,
        "measured_signer_ms": measured_signer_ms,
        "measured_total_latency_ms": measured_total_latency_ms,
        "proof_size_multiplier_bps": ratio_bps(measured_proof_bytes, estimated_proof_bytes),
        "authorization_size_multiplier_bps": ratio_bps(measured_authorization_bytes, estimated_authorization_bytes),
        "da_bandwidth_multiplier_bps": ratio_bps(measured_da_encoded_bytes, estimated_da_encoded_bytes),
        "contract_runtime_micros_per_fuel": micros_per(measured_contract_runtime_ms, estimated_execution_fuel),
        "prover_micros_per_proof": micros_per(measured_prover_ms, estimated_privacy_proof_count),
        "signer_micros_per_authorization": micros_per(measured_signer_ms, estimated_authorization_count),
        "target_latency_delta_ms": measured_total_latency_ms as i64 - target_latency_ms as i64,
    });
    let mut payload = json!({
        "kind": "performance_calibration_payload",
        "chain_id": CHAIN_ID,
        "source_benchmark_id": benchmark.benchmark_id,
        "calibrated_at_height": calibrated_at_height,
        "calibrated_at_ms": calibrated_at_ms,
        "calibrator_label": calibrator_label,
    });
    for (key, value) in summary.as_object().expect("summary object") {
        payload[key] = value.clone();
    }
    payload["calibrated_summary_root"] = json!(domain_hash(
        "PERFORMANCE-CALIBRATION-SUMMARY",
        &[HashPart::Json(&summary)],
        32,
    ));
    payload["calibration_id"] = json!(domain_hash(
        "PERFORMANCE-CALIBRATION-ID",
        &[HashPart::Json(&payload)],
        32,
    ));
    payload
}

pub fn unsigned_calibration_record(payload: &Value) -> Value {
    json!({
        "kind": "performance_calibration_record",
        "chain_id": CHAIN_ID,
        "calibration_id": payload["calibration_id"],
        "source_benchmark_id": payload["source_benchmark_id"],
        "calibrated_at_height": payload["calibrated_at_height"],
        "calibrated_at_ms": payload["calibrated_at_ms"],
        "calibrator_label": payload["calibrator_label"],
        "measured_proof_bytes": payload["measured_proof_bytes"],
        "measured_authorization_bytes": payload["measured_authorization_bytes"],
        "measured_da_encoded_bytes": payload["measured_da_encoded_bytes"],
        "measured_contract_runtime_ms": payload["measured_contract_runtime_ms"],
        "measured_prover_ms": payload["measured_prover_ms"],
        "measured_signer_ms": payload["measured_signer_ms"],
        "measured_total_latency_ms": payload["measured_total_latency_ms"],
        "estimated_proof_bytes": payload["estimated_proof_bytes"],
        "estimated_authorization_bytes": payload["estimated_authorization_bytes"],
        "estimated_da_encoded_bytes": payload["estimated_da_encoded_bytes"],
        "estimated_execution_fuel": payload["estimated_execution_fuel"],
        "estimated_privacy_proof_count": payload["estimated_privacy_proof_count"],
        "estimated_authorization_count": payload["estimated_authorization_count"],
        "estimated_contract_call_count": payload["estimated_contract_call_count"],
        "target_latency_ms": payload["target_latency_ms"],
        "proof_size_multiplier_bps": payload["proof_size_multiplier_bps"],
        "authorization_size_multiplier_bps": payload["authorization_size_multiplier_bps"],
        "da_bandwidth_multiplier_bps": payload["da_bandwidth_multiplier_bps"],
        "contract_runtime_micros_per_fuel": payload["contract_runtime_micros_per_fuel"],
        "prover_micros_per_proof": payload["prover_micros_per_proof"],
        "signer_micros_per_authorization": payload["signer_micros_per_authorization"],
        "target_latency_delta_ms": payload["target_latency_delta_ms"],
        "calibrated_summary_root": payload["calibrated_summary_root"],
    })
}

pub fn calibration_root(unsigned_record: &Value) -> String {
    domain_hash(
        "PERFORMANCE-CALIBRATION-RECORD",
        &[HashPart::Json(unsigned_record)],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reference_benchmark() -> PerformanceBenchmarkRun {
        let payload = benchmark_payload(
            "go-parity",
            3,
            1_234_567_890,
            true,
            "bench-go",
            &"aa".repeat(32),
            json!({
                "tx_count": 2,
                "estimated_proof_bytes": 4096,
                "estimated_authorization_bytes": 7168,
                "da_encoded_bytes": 8192,
                "batched_da_bytes": 4096,
                "execution_fuel": 33,
                "privacy_proof_count": 2,
                "authorization_count": 2,
                "contract_call_count": 1,
                "block_count": 1,
                "max_fee_density_microunits": 0,
            }),
            json!({
                "tx_count": 1,
                "estimated_proof_bytes": 2048,
                "estimated_authorization_bytes": 3584,
                "da_encoded_bytes": 0,
                "batched_da_bytes": 512,
                "execution_fuel": 7,
                "privacy_proof_count": 1,
                "authorization_count": 1,
                "contract_call_count": 0,
                "block_count": 0,
                "max_fee_density_microunits": 0,
            }),
            json!({
                "next_block_target_ms": TARGET_BLOCK_MS,
                "epoch_anchor_target_ms": 5000,
                "pending_batch_target_ms": TARGET_BLOCK_MS,
            }),
            vec![],
        );
        sign_benchmark(payload)
    }

    #[test]
    fn benchmark_matches_python_reference() {
        let benchmark = reference_benchmark();
        let unsigned = unsigned_benchmark_record(&benchmark_payload(
            &benchmark.scenario,
            benchmark.measured_at_height,
            benchmark.measured_at_ms,
            benchmark.include_pending,
            &benchmark.benchmarker_label,
            &benchmark.profile_root,
            benchmark.confirmed_summary.clone(),
            benchmark.pending_summary.clone(),
            benchmark.latency_targets.clone(),
            benchmark.fee_curve.clone(),
        ));
        assert_eq!(
            benchmark.benchmark_id,
            "e27105d20ee24f9cfb3db11404e9f1440bb85a51bc9465bbdfa271df5eae0359"
        );
        assert_eq!(
            benchmark_root(&unsigned),
            "37d351ec71c10064e5f694b57d5f6c79f902290ba44537ec5e9b589d97049253"
        );
        assert_eq!(
            benchmark.authorization.auth_signature,
            "5600632548d1eeae6f5507d390103e3ff8fd14d35d6f1dd10e6ab085b6cd4e46dbf936b56981ea1fceefae61b8996c9db2fd6b5dcfb64194b83003c78545537b"
        );
        assert!(verify_benchmark(&benchmark));
    }

    #[test]
    fn calibration_matches_python_reference_shape() {
        let benchmark = reference_benchmark();
        let payload = calibration_payload(
            &benchmark,
            3,
            1_234_567_999,
            "cal-go",
            7000,
            12000,
            9000,
            4,
            12,
            5,
            1111,
        );
        let unsigned = unsigned_calibration_record(&payload);
        let auth = sign_authorization("cal-go", "performance_calibration_record", &unsigned);
        assert_eq!(payload["estimated_proof_bytes"], json!(6144));
        assert_eq!(payload["estimated_authorization_bytes"], json!(10752));
        assert_eq!(payload["estimated_da_encoded_bytes"], json!(8704));
        assert_eq!(payload["proof_size_multiplier_bps"], json!(11393));
        assert_eq!(payload["authorization_size_multiplier_bps"], json!(11160));
        assert_eq!(payload["da_bandwidth_multiplier_bps"], json!(10340));
        assert_eq!(payload["target_latency_delta_ms"], json!(111));
        assert_eq!(
            payload["calibration_id"],
            json!("907af06cb63d30c9ac87b9dbd236d9c79ad25dcb304187e1aaaa908d57523cf5")
        );
        assert_eq!(
            payload["calibrated_summary_root"],
            json!("c18dfb1aff93063fd9e352b798b0772b68412833f079279f9c8801ee51322a6e")
        );
        assert_eq!(
            calibration_root(&unsigned),
            "1175b1a8cb9ba22ecb758d7187723cb8c4e80a679e8062b0f06deaf2b199b0ea"
        );
        assert_eq!(
            auth.auth_signature,
            "e83d30bcfa5b1dc193f3c50386cd85e1112d0e55ed70fe905fee03bc72c9bc46feb6a83ca2786e9bb52fcf4a421fc558d7203a3a0ee31c73da12463eea62da76"
        );
        assert!(verify_authorization(
            "cal-go",
            "performance_calibration_record",
            &unsigned,
            &auth
        ));
    }
}
