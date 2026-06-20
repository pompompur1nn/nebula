#!/usr/bin/env python3
"""Tests for the Nebula L2 devnet scaffold."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import devnet


def note_amounts(notes, asset_id: str):
    return sorted(note["amount"] for note in notes if note["asset_id"] == asset_id)


class NebulaL2DevnetTests(unittest.TestCase):
    def assertRelayMetadata(
        self,
        record,
        *,
        policy: str,
        prefix: str = "relay_path",
        raw_path: str | None = None,
        min_hops: int = 1,
    ) -> None:
        self.assertNotIn(prefix, record)
        self.assertEqual(record[f"{prefix}_policy"], policy)
        self.assertGreaterEqual(record[f"{prefix}_hop_count"], min_hops)
        self.assertEqual(len(record[f"{prefix}_commitment"]), 64)
        if raw_path is not None:
            self.assertNotIn(raw_path, json.dumps(record))

    def test_crypto_policy_root_is_committed_and_vectors_verify(self) -> None:
        policy = devnet.crypto_policy_record()
        roles = {suite["role"]: suite for suite in policy["suites"]}
        self.assertEqual(policy["policy_version"], devnet.CRYPTO_POLICY_VERSION)
        self.assertEqual(policy["crypto_policy_root"], devnet.crypto_policy_root())
        self.assertEqual(policy["crypto_suite"]["account_signature"], "ML-DSA-65")
        self.assertEqual(policy["crypto_suite"]["recovery_signature"], "SLH-DSA-SHAKE-128s")
        self.assertEqual(policy["crypto_suite"]["key_establishment"], "ML-KEM-768")
        self.assertEqual(roles["validator_signature"]["scheme"], "ML-DSA-65")
        self.assertEqual(roles["key_establishment"]["standard"], "NIST FIPS 203")

        vectors = {vector["name"]: vector for vector in policy["test_vectors"]}
        account_vector = vectors["account_authorization"]
        self.assertTrue(
            devnet.verify_authorization(
                account_vector["signer_label"],
                account_vector["domain"],
                account_vector["payload"],
                account_vector["auth_scheme"],
                account_vector["auth_public_key"],
                account_vector["auth_transcript_hash"],
                account_vector["auth_signature"],
            )
        )
        recovery_vector = vectors["recovery_authorization"]
        self.assertTrue(
            devnet.verify_recovery_authorization(
                recovery_vector["recovery_label"],
                recovery_vector["domain"],
                recovery_vector["payload"],
                recovery_vector["recovery_scheme"],
                recovery_vector["recovery_public_key"],
                recovery_vector["recovery_transcript_hash"],
                recovery_vector["recovery_signature"],
            )
        )
        kem_vector = vectors["ml_kem_mempool_ciphertext"]
        self.assertEqual(len(kem_vector["committee_key_id"]), 64)
        self.assertEqual(len(kem_vector["encrypted_payload_hash"]), 64)
        self.assertEqual(len(kem_vector["kem_ciphertext_hash"]), 64)
        self.assertRelayMetadata(
            kem_vector,
            policy="dandelion",
            raw_path="dandelion-stem-fluff",
        )

        net = devnet.NebulaL2Devnet()
        self.assertEqual(
            net.public_snapshot()["crypto_policy_root"],
            devnet.crypto_policy_root(),
        )
        state_record = net.state_record()
        self.assertEqual(state_record["crypto_policy_root"], devnet.crypto_policy_root())
        self.assertNotIn("test_vectors", state_record["crypto_policy"])
        self.assertEqual(
            devnet.NebulaL2Devnet.from_state_record(state_record).state_record()[
                "crypto_policy_root"
            ],
            devnet.crypto_policy_root(),
        )

        block = net.produce_block()
        self.assertEqual(block.header.crypto_policy_root, devnet.crypto_policy_root())
        self.assertEqual(
            block.header.public_record()["crypto_policy_root"],
            devnet.crypto_policy_root(),
        )

        bad_root = json.loads(json.dumps(state_record))
        bad_root["crypto_policy_root"] = "00"
        with self.assertRaisesRegex(ValueError, "unsupported crypto policy root"):
            devnet.NebulaL2Devnet.from_state_record(bad_root)

        bad_suite = json.loads(json.dumps(state_record))
        bad_suite["crypto_suite"]["account_signature"] = "ECDSA-P256"
        with self.assertRaisesRegex(ValueError, "unsupported crypto suite"):
            devnet.NebulaL2Devnet.from_state_record(bad_suite)

    def test_private_transfer_requires_valid_owner_authorization(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)

        with self.assertRaisesRegex(ValueError, "signer does not own"):
            net.submit_private_transfer(
                note.note_id,
                "bob-view-key",
                amount=100,
                fee=1,
                signer_label="mallory-view-key",
            )

        tx = net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        self.assertEqual(tx.auth_scheme, devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertTrue(tx.auth_public_key)
        self.assertTrue(tx.auth_transcript_hash)
        self.assertTrue(tx.auth_signature)
        self.assertIsNotNone(tx.privacy_proof)
        self.assertIn("proof_root", tx.public_record()["proof_bundle"])
        self.assertNotIn("private_witness_hash", tx.public_record()["proof_bundle"])

        net.pending[0] = replace(tx, auth_signature="00")
        with self.assertRaisesRegex(ValueError, "invalid transaction authorization"):
            net.produce_block()

    def test_private_transfer_rejects_tampered_privacy_proof(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        tx = net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        self.assertIsNotNone(tx.privacy_proof)

        bad_proof = replace(tx.privacy_proof, proof_root="00")
        bad_tx = replace(tx, privacy_proof=bad_proof)
        bad_tx = net._authorize_transaction(bad_tx, tx.signer_label)
        net.pending[0] = bad_tx

        with self.assertRaisesRegex(ValueError, "invalid privacy proof"):
            net.produce_block()

    def test_private_batch_transfer_spends_many_notes_for_one_fee(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        first = net.mint(asset.asset_id, "alice-view-key", 1_000)
        second = net.mint(asset.asset_id, "alice-view-key", 500)

        with self.assertRaisesRegex(ValueError, "signer must own"):
            net.submit_private_transfer_batch(
                (first.note_id, second.note_id),
                ("bob-view-key",),
                (100,),
                fee=1,
                signer_label="mallory-view-key",
            )

        tx = net.submit_private_transfer_batch(
            (first.note_id, second.note_id),
            ("bob-view-key", "carol-view-key"),
            (200, 300),
            fee=5,
        )
        public_tx = tx.public_record()
        self.assertEqual(public_tx["input_count"], 2)
        self.assertEqual(len(public_tx["nullifiers"]), 2)
        self.assertEqual(public_tx["fee"], 5)
        self.assertNotIn("spent_note_ids", public_tx)
        self.assertNotIn("private_witness_hash", public_tx["proof_bundle"])
        self.assertIsNotNone(tx.privacy_proof)

        block = net.produce_block()
        self.assertEqual(block.header.execution_profile.tx_count, 1)
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(block.header.execution_profile.authorization_count, 1)
        self.assertGreater(
            block.header.execution_profile.estimated_proof_bytes,
            devnet.DEVNET_PRIVACY_PROOF_BYTES,
        )
        self.assertEqual(net.fees_collected[asset.asset_id], 5)
        self.assertEqual(net.public_snapshot()["spent_nullifier_count"], 2)
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), asset.asset_id), [995])
        self.assertEqual(note_amounts(net.wallet_notes("bob-view-key"), asset.asset_id), [200])
        self.assertEqual(note_amounts(net.wallet_notes("carol-view-key"), asset.asset_id), [300])

    def test_private_batch_transfer_rejects_tampered_value_balance(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        first = net.mint(asset.asset_id, "alice-view-key", 1_000)
        second = net.mint(asset.asset_id, "alice-view-key", 500)
        tx = net.submit_private_transfer_batch(
            (first.note_id, second.note_id),
            ("bob-view-key", "carol-view-key"),
            (200, 300),
            fee=5,
        )

        bad_output = devnet.Note.create(
            "carol-view-key",
            asset.asset_id,
            301,
            net._next_nonce(),
        )
        bad_tx = replace(tx, output_notes=(tx.output_notes[0], bad_output, tx.output_notes[2]))
        net.pending[0] = bad_tx

        with self.assertRaisesRegex(ValueError, "not value balanced"):
            net.produce_block()

    def test_validator_votes_drive_soft_finality_metadata(self) -> None:
        net = devnet.NebulaL2Devnet()
        second = net.register_validator("validator-two", stake=500)
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)

        block = net.produce_block(proposer_id="validator-two")
        self.assertEqual(block.header.proposer_id, second.validator_id)
        self.assertEqual(block.header.validator_vote_count, 2)
        self.assertEqual(block.header.validator_stake_weight, 1_500)
        self.assertTrue(block.header.soft_finality)
        self.assertEqual(len(block.header.validator_set_root), 64)
        self.assertEqual(len(block.header.pq_vote_root), 64)

        with self.assertRaisesRegex(ValueError, "unknown or inactive proposer"):
            net.produce_block(proposer_id="missing-validator")

    def test_account_rotation_updates_pq_registry_and_retires_old_label(self) -> None:
        net = devnet.NebulaL2Devnet()
        account = net.register_account("alice-v1")
        contract = net.deploy_contract("counter", owner_label="alice-v1", fuel_limit=100)
        account_root_before = net.account_root()

        rotation = net.submit_account_rotation(
            account.account_id,
            new_label="alice-v2",
            recovery_label="alice-v1",
        )
        self.assertEqual(rotation.recovery_scheme, devnet.RECOVERY_SIGNATURE_SCHEME)
        self.assertNotIn("new_label", rotation.public_record())
        self.assertTrue(rotation.recovery_signature)

        block = net.produce_block()
        rotated = net.accounts[account.account_id]
        self.assertEqual(rotated.current_label, "alice-v2")
        self.assertEqual(rotated.rotation_nonce, 1)
        self.assertIn("alice-v1", net.retired_account_labels)
        self.assertNotEqual(account_root_before, net.account_root())
        self.assertEqual(block.header.account_root, net.account_root())

        with self.assertRaisesRegex(ValueError, "retired"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="alice-v1",
                fuel_limit=20,
            )

        call = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 3},
            signer_label="alice-v2",
            fuel_limit=20,
        )
        self.assertEqual(call.auth_public_key, rotated.spend_public_key)
        net.produce_block()
        self.assertEqual(net.contracts[contract.contract_id].storage["count"], 3)

        bob = net.register_account("bob-v1")
        with self.assertRaisesRegex(ValueError, "recovery key mismatch"):
            net.submit_account_rotation(
                bob.account_id,
                new_label="bob-v2",
                recovery_label="mallory",
            )

    def test_wallet_session_receipts_bind_ml_kem_network_keys_and_rotation(self) -> None:
        net = devnet.NebulaL2Devnet()
        account = net.register_account("alice-v1")
        session = net.open_wallet_session(
            account.account_id,
            signer_label="alice-v1",
            relay_path="tor-stem",
            expires_in_blocks=1,
        )
        public_session = session.public_record()
        self.assertEqual(public_session["account_id"], account.account_id)
        self.assertEqual(public_session["auth_scheme"], devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertEqual(public_session["wallet_network_public_key"], account.network_public_key)
        self.assertEqual(len(public_session["kem_ciphertext_hash"]), 64)
        self.assertEqual(len(public_session["session_transcript_hash"]), 64)
        self.assertRelayMetadata(public_session, policy="tor", raw_path="tor-stem")
        self.assertNotIn("alice-v1", json.dumps(public_session))
        self.assertEqual(net.public_snapshot()["wallet_session_count"], 1)
        self.assertEqual(net.public_snapshot()["wallet_session_root"], net.wallet_session_root())
        self.assertEqual(net.wallet_session_status(session.session_id)["status"], "active")
        self.assertEqual(net.state_record()["wallet_sessions"][0]["relay_path"], "tor-stem")

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.wallet_session_root(), net.wallet_session_root())
        self.assertEqual(
            round_trip.wallet_sessions[session.session_id].public_record(),
            public_session,
        )

        tampered = net.state_record()
        tampered["wallet_sessions"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid wallet session authorization"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

        net.produce_block()
        net.produce_block()
        expired = net.wallet_session_status(session.session_id)
        self.assertEqual(expired["status"], "expired")
        self.assertEqual(expired["blocks_until_expiry"], 0)

        active_net = devnet.NebulaL2Devnet()
        active_account = active_net.register_account("carol-v1")
        active_session = active_net.open_wallet_session(
            active_account.account_id,
            signer_label="carol-v1",
            expires_in_blocks=10,
        )
        active_root = active_net.wallet_session_root()
        active_net.submit_account_rotation(
            active_account.account_id,
            new_label="carol-v2",
            recovery_label="carol-v1",
        )
        active_net.produce_block()
        self.assertEqual(
            active_net.wallet_session_status(active_session.session_id)["status"],
            "revoked",
        )
        self.assertNotEqual(active_root, active_net.wallet_session_root())

    def test_block_execution_profile_tracks_batch_costs(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        first = net.mint(asset.asset_id, "alice-view-key", 1_000)
        second = net.mint(asset.asset_id, "carol-view-key", 2_000)

        net.submit_private_transfer(first.note_id, "bob-view-key", amount=100, fee=2)
        net.submit_private_transfer(second.note_id, "dave-view-key", amount=200, fee=3)
        pending_profile = net.public_snapshot()["pending_execution_profile"]
        self.assertEqual(pending_profile["tx_count"], 2)
        self.assertEqual(pending_profile["privacy_proof_count"], 2)
        self.assertEqual(pending_profile["observed_fee_units"], 5)
        self.assertEqual(pending_profile["fee_asset_count"], 1)
        self.assertEqual(pending_profile["local_fee_lane_count"], 2)
        self.assertEqual(len(pending_profile["local_fee_market_root"]), 64)
        self.assertLessEqual(
            pending_profile["batched_da_bytes"],
            pending_profile["uncompressed_da_bytes"],
        )
        pending_fee_markets = net.local_fee_market_report(pending=True)
        self.assertEqual(
            pending_fee_markets["local_fee_market_root"],
            pending_profile["local_fee_market_root"],
        )
        lanes_by_type = {
            (lane["lane_type"], lane["lane_key"]): lane
            for lane in pending_fee_markets["lanes"]
        }
        self.assertEqual(lanes_by_type[("operation", "private_transfer")]["tx_count"], 2)
        self.assertEqual(lanes_by_type[("operation", "private_transfer")]["observed_fee_units"], 5)
        self.assertEqual(lanes_by_type[("asset", asset.asset_id)]["tx_count"], 2)
        self.assertNotIn("alice-view-key", json.dumps(pending_fee_markets))
        self.assertNotIn("carol-view-key", json.dumps(pending_fee_markets))

        block = net.produce_block()
        profile = block.header.execution_profile
        self.assertEqual(profile.target_block_ms, devnet.TARGET_BLOCK_MS)
        self.assertEqual(profile.tx_count, 2)
        self.assertEqual(profile.privacy_proof_count, 2)
        self.assertEqual(profile.observed_fee_units, 5)
        self.assertEqual(profile.authorization_count, 2)
        self.assertEqual(profile.estimated_authorization_bytes, 2 * devnet.DEVNET_AUTH_BYTES)
        self.assertEqual(
            profile.amortized_da_bytes_per_tx,
            devnet.ceil_div(profile.batched_da_bytes, profile.tx_count),
        )
        self.assertEqual(profile.local_fee_lane_count, 2)
        self.assertEqual(profile.local_fee_market_root, pending_fee_markets["local_fee_market_root"])
        self.assertGreater(profile.max_local_fee_density_microunits, 0)
        block_fee_markets = net.local_fee_market_report(block_height=block.header.height)
        self.assertEqual(block_fee_markets["block_hash"], block.header.block_hash())
        self.assertEqual(block_fee_markets["local_fee_market_root"], profile.local_fee_market_root)
        self.assertEqual(block_fee_markets["execution_profile_root"], profile.local_fee_market_root)
        self.assertIn("execution_profile", block.header.public_record())
        self.assertEqual(net.public_snapshot()["pending_execution_profile"]["tx_count"], 0)

    def test_performance_profile_reports_speed_bandwidth_and_fee_curves(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        first = net.mint(asset.asset_id, "alice-view-key", 1_000)
        second = net.mint(asset.asset_id, "carol-view-key", 2_000)

        net.submit_private_transfer(first.note_id, "bob-view-key", amount=100, fee=2)
        net.submit_private_transfer(second.note_id, "dave-view-key", amount=200, fee=3)
        pending_record = [tx.public_record() for tx in net.pending]
        pending_report = net.performance_profile_report()
        self.assertEqual(pending_report["confirmed_block_count"], 0)
        self.assertEqual(pending_report["pending_tx_count"], 2)
        self.assertEqual(pending_report["pending"]["tx_count"], 2)
        self.assertEqual(
            pending_report["pending"]["target_tps_microunits"],
            2 * 1_000_000 * 1_000 // devnet.TARGET_BLOCK_MS,
        )
        self.assertEqual(pending_report["latency_targets"]["next_block_target_ms"], devnet.TARGET_BLOCK_MS)
        self.assertEqual(len(pending_report["fee_curve_root"]), 64)
        self.assertEqual(len(pending_report["profile_root"]), 64)
        fee_ops = {row["operation"] for row in pending_report["fee_curve"]}
        self.assertIn("private-transfer", fee_ops)
        self.assertIn("contract-call-batch", fee_ops)
        self.assertIn("sealed-swap", fee_ops)
        self.assertNotIn("alice-view-key", json.dumps(pending_report))
        self.assertNotIn("carol-view-key", json.dumps(pending_report))
        self.assertEqual([tx.public_record() for tx in net.pending], pending_record)

        block = net.produce_block()
        confirmed_report = net.performance_profile_report()
        self.assertEqual(confirmed_report["confirmed_block_count"], 1)
        self.assertEqual(confirmed_report["confirmed"]["tx_count"], 2)
        self.assertEqual(confirmed_report["confirmed"]["observed_fee_units"], 5)
        self.assertEqual(
            confirmed_report["confirmed"]["target_tps_microunits"],
            2 * 1_000_000 * 1_000 // devnet.TARGET_BLOCK_MS,
        )
        self.assertEqual(
            confirmed_report["confirmed"]["batched_da_bytes"],
            block.header.execution_profile.batched_da_bytes,
        )
        self.assertEqual(
            confirmed_report["confirmed"]["estimated_proof_bytes"],
            block.header.execution_profile.estimated_proof_bytes,
        )
        self.assertGreater(confirmed_report["confirmed"]["projected_wire_bytes"], 0)
        self.assertEqual(confirmed_report["pending"]["tx_count"], 0)
        self.assertEqual(
            confirmed_report["latency_targets"]["epoch_anchor_target_ms"],
            net.epoch_size * devnet.TARGET_BLOCK_MS,
        )
        confirmed_only = net.performance_profile_report(include_pending=False)
        self.assertEqual(confirmed_only["pending_tx_count"], 0)
        self.assertEqual(confirmed_only["pending"]["tx_count"], 0)
        benchmark = net.publish_performance_benchmark(
            scenario="confirmed-private-transfer-mix",
            benchmarker_label="perf-watchtower-a",
        )
        self.assertEqual(benchmark.scenario, "confirmed-private-transfer-mix")
        self.assertEqual(benchmark.profile_root, confirmed_report["profile_root"])
        self.assertEqual(benchmark.fee_curve_root, confirmed_report["fee_curve_root"])
        self.assertEqual(
            benchmark.confirmed_summary["tx_count"],
            confirmed_report["confirmed"]["tx_count"],
        )
        self.assertEqual(
            benchmark.pending_summary["tx_count"],
            confirmed_report["pending"]["tx_count"],
        )
        self.assertEqual(benchmark.measured_at_height, block.header.height)
        self.assertTrue(benchmark.auth_signature)
        self.assertEqual(len(benchmark.benchmark_root()), 64)
        self.assertEqual(net.public_snapshot()["performance_benchmark_count"], 1)
        self.assertEqual(
            net.public_snapshot()["performance_benchmark_root"],
            net.performance_benchmark_root(),
        )
        public_benchmark = benchmark.public_record()
        self.assertNotIn("alice-view-key", json.dumps(public_benchmark))
        self.assertNotIn("carol-view-key", json.dumps(public_benchmark))
        measured_da_bytes = (
            benchmark.confirmed_summary["da_encoded_bytes"]
            or benchmark.confirmed_summary["batched_da_bytes"]
        ) + 128
        calibration = net.publish_performance_calibration(
            source_benchmark_id=benchmark.benchmark_id,
            calibrator_label="perf-calibrator-a",
            measured_proof_bytes=benchmark.confirmed_summary["estimated_proof_bytes"] + 512,
            measured_authorization_bytes=(
                benchmark.confirmed_summary["estimated_authorization_bytes"] + 256
            ),
            measured_da_encoded_bytes=measured_da_bytes,
            measured_contract_runtime_ms=0,
            measured_prover_ms=13,
            measured_signer_ms=5,
            measured_total_latency_ms=devnet.TARGET_BLOCK_MS + 75,
        )
        self.assertEqual(calibration.source_benchmark_id, benchmark.benchmark_id)
        self.assertEqual(calibration.calibrator_label, "perf-calibrator-a")
        self.assertEqual(
            calibration.estimated_proof_bytes,
            benchmark.confirmed_summary["estimated_proof_bytes"],
        )
        self.assertEqual(
            calibration.estimated_authorization_bytes,
            benchmark.confirmed_summary["estimated_authorization_bytes"],
        )
        self.assertEqual(calibration.measured_da_encoded_bytes, measured_da_bytes)
        self.assertGreater(calibration.proof_size_multiplier_bps, 10_000)
        self.assertGreater(calibration.authorization_size_multiplier_bps, 10_000)
        self.assertGreater(calibration.da_bandwidth_multiplier_bps, 10_000)
        self.assertGreater(calibration.prover_micros_per_proof, 0)
        self.assertGreater(calibration.signer_micros_per_authorization, 0)
        self.assertEqual(calibration.target_latency_delta_ms, 75)
        self.assertTrue(calibration.auth_signature)
        self.assertEqual(len(calibration.calibration_root()), 64)
        calibrated_report = net.performance_profile_report()
        self.assertEqual(calibrated_report["performance_calibration_count"], 1)
        self.assertEqual(
            calibrated_report["performance_calibration_root"],
            net.performance_calibration_root(),
        )
        self.assertEqual(
            calibrated_report["latest_performance_calibration_id"],
            calibration.calibration_id,
        )
        self.assertEqual(net.public_snapshot()["performance_calibration_count"], 1)
        self.assertNotIn("alice-view-key", json.dumps(calibration.public_record()))

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.performance_benchmark_root(),
            net.performance_benchmark_root(),
        )
        self.assertEqual(
            round_trip.performance_calibration_root(),
            net.performance_calibration_root(),
        )
        tampered = json.loads(json.dumps(net.state_record()))
        tampered["performance_benchmarks"][0]["fee_curve_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "performance benchmark"):
            devnet.NebulaL2Devnet.from_state_record(tampered)
        tampered_calibration = json.loads(json.dumps(net.state_record()))
        tampered_calibration["performance_calibrations"][0]["measured_proof_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "performance calibration"):
            devnet.NebulaL2Devnet.from_state_record(tampered_calibration)

    def test_fee_quote_projects_marginal_batch_cost_without_mutating_mempool(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        first = net.mint(asset.asset_id, "alice-view-key", 1_000)
        second = net.mint(asset.asset_id, "carol-view-key", 2_000)
        net.submit_private_transfer(first.note_id, "bob-view-key", amount=100, fee=2)
        net.submit_private_transfer(second.note_id, "dave-view-key", amount=200, fee=3)

        pending_ids = [tx.public_record() for tx in net.pending]
        admission_root = net.mempool_admission_root()
        quote = net.fee_quote(
            operation="batch-transfer",
            input_count=2,
            output_count=3,
            fee_asset_id=asset.asset_id,
        )

        self.assertEqual(quote["operation"], "batch-transfer")
        self.assertEqual(quote["pending_tx_count"], 2)
        self.assertEqual(quote["projected_tx_count"], 3)
        self.assertEqual(quote["candidate_profile"]["tx_count"], 1)
        self.assertEqual(quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertEqual(quote["candidate_profile"]["authorization_count"], 1)
        self.assertGreater(quote["candidate_profile"]["estimated_proof_bytes"], devnet.DEVNET_PRIVACY_PROOF_BYTES)
        self.assertLessEqual(
            quote["marginal_batched_da_bytes"],
            quote["candidate_profile"]["batched_da_bytes"],
        )
        self.assertGreaterEqual(quote["marginal_batch_savings_bps"], 0)
        self.assertGreaterEqual(quote["recommended_fee_units"], quote["minimum_fee_units"])
        self.assertGreaterEqual(quote["fast_fee_units"], quote["recommended_fee_units"])
        self.assertEqual(quote["target_block_ms"], devnet.TARGET_BLOCK_MS)
        self.assertEqual(len(quote["quote_hash"]), 64)
        self.assertEqual([tx.public_record() for tx in net.pending], pending_ids)
        self.assertEqual(net.mempool_admission_root(), admission_root)

        contract_quote = net.fee_quote(
            operation="contract-call",
            contract_fuel=41,
            fee_mode="paymaster",
            fee_asset_id=asset.asset_id,
            contract_id="contract-quote",
            paymaster_id="paymaster-quote",
        )
        self.assertEqual(contract_quote["candidate_profile"]["contract_call_count"], 1)
        self.assertEqual(contract_quote["candidate_profile"]["privacy_proof_count"], 0)
        self.assertEqual(contract_quote["minimum_fee_units"], net._contract_call_fee(41))
        self.assertEqual(contract_quote["candidate_profile"]["local_fee_lane_count"], 4)
        contract_quote_lanes = {
            (lane["lane_type"], lane["lane_key"])
            for lane in contract_quote["candidate_local_fee_markets"]
        }
        self.assertIn(("contract", "contract-quote"), contract_quote_lanes)
        self.assertIn(("paymaster", "paymaster-quote"), contract_quote_lanes)
        self.assertIn(("asset", asset.asset_id), contract_quote_lanes)

        private_contract_quote = net.fee_quote(
            operation="contract-call",
            contract_fuel=41,
            fee_mode="paymaster",
            fee_asset_id=asset.asset_id,
            contract_id="contract-quote",
            paymaster_id="paymaster-quote",
            private_args=True,
        )
        self.assertTrue(private_contract_quote["private_args"])
        self.assertEqual(
            private_contract_quote["candidate_profile"]["privacy_proof_count"],
            1,
        )
        self.assertEqual(private_contract_quote["minimum_fee_units"], net._contract_call_fee(41))

        deposit_quote = net.fee_quote(
            operation="contract-deposit",
            output_count=1,
            fee_asset_id=asset.asset_id,
        )
        self.assertEqual(deposit_quote["operation"], "contract-deposit")
        self.assertEqual(deposit_quote["fee_mode"], "private-note")
        self.assertEqual(deposit_quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertEqual(deposit_quote["candidate_profile"]["authorization_count"], 1)
        self.assertEqual(deposit_quote["candidate_profile"]["observed_fee_units"], 1)
        self.assertEqual(deposit_quote["minimum_fee_units"], 1)

        withdraw_quote = net.fee_quote(
            operation="contract-withdraw",
            output_count=3,
            fee_asset_id=asset.asset_id,
        )
        self.assertEqual(withdraw_quote["operation"], "contract-withdraw")
        self.assertEqual(withdraw_quote["fee_mode"], "contract-balance")
        self.assertEqual(withdraw_quote["output_count"], 1)
        self.assertEqual(withdraw_quote["candidate_profile"]["privacy_proof_count"], 0)
        self.assertEqual(withdraw_quote["candidate_profile"]["estimated_proof_bytes"], 0)
        self.assertEqual(withdraw_quote["candidate_profile"]["authorization_count"], 1)
        self.assertEqual(withdraw_quote["minimum_fee_units"], 1)

        reward_bundle_quote = net.fee_quote(
            operation="paymaster-reward-claim-batch",
            input_count=3,
            fee_asset_id=asset.asset_id,
        )
        self.assertEqual(reward_bundle_quote["operation"], "paymaster-reward-claim-batch")
        self.assertEqual(reward_bundle_quote["output_count"], 3)
        self.assertEqual(reward_bundle_quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertEqual(reward_bundle_quote["candidate_profile"]["authorization_count"], 1)
        self.assertGreaterEqual(reward_bundle_quote["minimum_fee_units"], 1)
        with self.assertRaisesRegex(ValueError, "exceeds max size"):
            net.fee_quote(
                operation="paymaster-reward-claim-batch",
                input_count=devnet.PAYMASTER_RELAYER_REWARD_CLAIM_BUNDLE_MAX_ITEMS + 1,
            )

    def test_view_key_disclosure_is_scoped_signed_and_tamper_checked(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        net.mint(wxmr.asset_id, "alice-view-key", 1_000)
        net.mint(dusd.asset_id, "alice-view-key", 250)
        net.mint(wxmr.asset_id, "bob-view-key", 500)

        disclosure = net.view_key_disclosure(
            "alice-view-key",
            audience_label="tax-auditor",
            asset_id=wxmr.asset_id,
            expires_in_blocks=2,
        )
        public_record = disclosure.public_record()
        self.assertEqual(public_record["audience_label"], "tax-auditor")
        self.assertEqual(public_record["asset_id"], wxmr.asset_id)
        self.assertEqual(public_record["note_count"], 1)
        self.assertEqual(public_record["asset_totals"], {wxmr.asset_id: 1_000})
        self.assertEqual(len(public_record["note_commitment_root"]), 64)
        self.assertNotIn("alice-view-key", json.dumps(public_record))
        self.assertNotIn("notes", public_record)

        audit_record = disclosure.audit_record("alice-view-key")
        self.assertEqual(audit_record["disclosed_view_key"], "alice-view-key")
        self.assertEqual(len(audit_record["notes"]), 1)
        self.assertNotIn("bob-view-key", json.dumps(audit_record))
        self.assertTrue(net.verify_view_key_disclosure(audit_record))

        tampered_notes = json.loads(json.dumps(audit_record))
        tampered_notes["notes"][0]["amount"] += 1
        with self.assertRaisesRegex(ValueError, "note root"):
            net.verify_view_key_disclosure(tampered_notes)

        tampered_auth = json.loads(json.dumps(audit_record))
        tampered_auth["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid view key disclosure authorization"):
            net.verify_view_key_disclosure(tampered_auth)

        expiring = net.view_key_disclosure(
            "alice-view-key",
            audience_label="short-audit",
            expires_in_blocks=1,
        ).audit_record("alice-view-key")
        net.produce_block()
        net.produce_block()
        with self.assertRaisesRegex(ValueError, "expired"):
            net.verify_view_key_disclosure(expiring)

    def test_wallet_history_recovers_confirmed_pending_and_current_notes(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        alice_note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(
            alice_note.note_id,
            "bob-view-key",
            amount=250,
            fee=5,
        )
        net.produce_block()

        bob_note = net.wallet_notes("bob-view-key")[0]
        net.submit_private_transfer(
            bob_note["note_id"],
            "carol-view-key",
            amount=100,
            fee=10,
        )
        pending_history = net.wallet_history("bob-view-key")
        self.assertEqual(pending_history["height"], 1)
        self.assertEqual(pending_history["current_totals"], {asset.asset_id: 250})
        self.assertEqual(pending_history["received_totals"], {asset.asset_id: 390})
        self.assertEqual(pending_history["spent_totals"], {asset.asset_id: 250})
        self.assertEqual(pending_history["fee_totals"], {asset.asset_id: 10})
        self.assertEqual(pending_history["unindexed_current_note_count"], 0)
        self.assertEqual(len(pending_history["history_root"]), 64)
        self.assertTrue(
            any(
                event["event"] == "spent" and event["status"] == "pending"
                for event in pending_history["events"]
            )
        )
        self.assertTrue(
            any(
                event["event"] == "received"
                and event["status"] == "pending"
                and event["amount"] == 140
                for event in pending_history["events"]
            )
        )
        pending_json = json.dumps(pending_history)
        self.assertNotIn("alice-view-key", pending_json)
        self.assertNotIn("bob-view-key", pending_json)
        self.assertNotIn("carol-view-key", pending_json)

        net.produce_block()
        history = net.wallet_history("bob-view-key")
        self.assertEqual(history["height"], 2)
        self.assertEqual(history["current_totals"], {asset.asset_id: 140})
        self.assertEqual(history["received_totals"], {asset.asset_id: 390})
        self.assertEqual(history["spent_totals"], {asset.asset_id: 250})
        self.assertEqual(history["fee_totals"], {asset.asset_id: 10})
        self.assertTrue(
            any(
                event["event"] == "received"
                and event["status"] == "spent"
                and event["amount"] == 250
                for event in history["events"]
            )
        )
        self.assertTrue(
            any(
                event["event"] == "received"
                and event["status"] == "current"
                and event["amount"] == 140
                for event in history["events"]
            )
        )

    def test_encrypted_mempool_admissions_survive_reload_and_clear_on_block(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)

        self.assertEqual(len(net.pending_admissions), 1)
        public_admission = net.pending_admissions[0].public_record()
        self.assertEqual(len(net.mempool_preconfirmations), 1)
        preconfirmation = next(iter(net.mempool_preconfirmations.values()))
        self.assertEqual(public_admission["mempool_sequence"], 0)
        self.assertEqual(len(public_admission["tx_public_hash"]), 64)
        self.assertEqual(len(public_admission["encrypted_payload_hash"]), 64)
        self.assertEqual(len(public_admission["committee_key_id"]), 64)
        self.assertEqual(len(public_admission["kem_ciphertext_hash"]), 64)
        self.assertTrue(public_admission["auth_signature"])
        public_json = json.dumps(public_admission)
        self.assertNotIn("alice-view-key", public_json)
        self.assertNotIn("bob-view-key", public_json)
        self.assertEqual(preconfirmation.admission_id, public_admission["admission_id"])
        self.assertEqual(preconfirmation.target_height, 0)
        self.assertEqual(preconfirmation.promised_pending_tx_count, 1)
        self.assertEqual(preconfirmation.promised_mempool_root, net.mempool_admission_root())
        self.assertEqual(len(preconfirmation.local_fee_market_root), 64)
        self.assertTrue(preconfirmation.auth_signature)
        self.assertNotIn("bob-view-key", json.dumps(preconfirmation.public_record()))

        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["pending_mempool_admission_count"], 1)
        self.assertEqual(len(snapshot["mempool_admission_root"]), 64)
        self.assertEqual(snapshot["mempool_preconfirmation_count"], 1)
        self.assertEqual(len(snapshot["mempool_preconfirmation_root"]), 64)
        self.assertEqual(snapshot["mempool_preconfirmation_miss_count"], 0)
        admission_root = snapshot["mempool_admission_root"]
        pending_status = net.mempool_admission_status(public_admission["admission_id"])
        self.assertEqual(pending_status["status"], "pending")
        self.assertEqual(pending_status["admission"]["admission_id"], public_admission["admission_id"])
        self.assertEqual(pending_status["preconfirmations"][0]["status"], "preconfirmed")
        self.assertEqual(
            pending_status["preconfirmations"][0]["preconfirmation"]["preconfirmation_id"],
            preconfirmation.preconfirmation_id,
        )
        self.assertEqual(pending_status["mempool_admission_root"], admission_root)
        self.assertEqual(pending_status["blocks_until_expiry"], 11)

        state_record = net.state_record()
        self.assertNotIn("bob-view-key", json.dumps(state_record["pending_mempool_admissions"]))
        self.assertNotIn("bob-view-key", json.dumps(state_record["mempool_preconfirmations"]))
        round_trip = devnet.NebulaL2Devnet.from_state_record(state_record)
        self.assertEqual(len(round_trip.pending_admissions), 1)
        self.assertEqual(round_trip.mempool_admission_root(), net.mempool_admission_root())
        self.assertEqual(
            round_trip.mempool_preconfirmation_root(),
            net.mempool_preconfirmation_root(),
        )

        block = round_trip.produce_block()
        self.assertEqual(block.header.execution_profile.tx_count, 1)
        self.assertEqual(block.header.mempool_admission_root, admission_root)
        self.assertEqual(block.header.mempool_admission_count, 1)
        self.assertEqual(
            block.header.public_record()["mempool_admission_root"],
            admission_root,
        )
        da_record = round_trip.da_records[block.header.height]
        payload = json.loads("".join(
            shard.data
            for shard in da_record.shards
            if shard.shard_kind == "data"
        ))
        self.assertEqual(payload["mempool_admission_root"], admission_root)
        self.assertEqual(payload["mempool_admission_count"], 1)
        self.assertEqual(len(payload["mempool_admissions"]), 1)
        self.assertNotIn("bob-view-key", json.dumps(payload["mempool_admissions"]))
        self.assertEqual(round_trip.pending_admissions, [])
        self.assertEqual(round_trip.public_snapshot()["pending_mempool_admission_count"], 0)
        included_status = round_trip.mempool_admission_status(public_admission["admission_id"])
        self.assertEqual(included_status["status"], "included")
        self.assertEqual(included_status["block_height"], block.header.height)
        self.assertEqual(included_status["block_hash"], block.header.block_hash())
        self.assertEqual(included_status["admission"]["admission_id"], public_admission["admission_id"])
        self.assertEqual(included_status["preconfirmations"][0]["status"], "fulfilled")
        self.assertEqual(included_status["mempool_admission_root"], admission_root)
        self.assertEqual(included_status["mempool_admission_count"], 1)
        self.assertEqual(included_status["settlement"]["status"], "soft_final")
        self.assertNotIn("bob-view-key", json.dumps(included_status))

        tampered_preconfirmation = net.state_record()
        tampered_preconfirmation["mempool_preconfirmations"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid mempool preconfirmation"):
            devnet.NebulaL2Devnet.from_state_record(tampered_preconfirmation)

        tampered = devnet.NebulaL2Devnet()
        tampered_asset = tampered.create_asset("WXMR", "devnet-bridge-threshold")
        tampered_note = tampered.mint(tampered_asset.asset_id, "alice-view-key", 1_000)
        tampered.submit_private_transfer(
            tampered_note.note_id,
            "bob-view-key",
            amount=100,
            fee=1,
        )
        tampered.pending_admissions[0] = replace(
            tampered.pending_admissions[0],
            encrypted_payload_hash="00",
        )
        with self.assertRaisesRegex(ValueError, "mempool admission"):
            tampered.produce_block()

        bad_auth = devnet.NebulaL2Devnet()
        bad_auth_asset = bad_auth.create_asset("WXMR", "devnet-bridge-threshold")
        bad_auth_note = bad_auth.mint(bad_auth_asset.asset_id, "alice-view-key", 1_000)
        bad_auth.submit_private_transfer(
            bad_auth_note.note_id,
            "bob-view-key",
            amount=100,
            fee=1,
        )
        bad_auth.pending_admissions[0] = replace(
            bad_auth.pending_admissions[0],
            auth_signature="00",
        )
        with self.assertRaisesRegex(ValueError, "invalid mempool admission authorization"):
            bad_auth.produce_block()

    def test_transaction_status_tracks_pending_included_and_monero_final(self) -> None:
        net = devnet.NebulaL2Devnet(epoch_size=2)
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        tx = net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        tx_public_hash = devnet.domain_hash("TX-PUBLIC", tx.public_record())
        mempool_tx_public_hash = devnet.domain_hash("MEMPOOL-TX-PUBLIC", tx.public_record())

        pending = net.transaction_status(tx_public_hash)
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(pending["inclusion_status"], "pending")
        self.assertEqual(pending["tx_public_hash"], tx_public_hash)
        self.assertEqual(pending["mempool_tx_public_hash"], mempool_tx_public_hash)
        self.assertEqual(pending["tx_kind"], "private_transfer")
        self.assertIsNone(pending["settlement"])
        self.assertEqual(pending["mempool_admission"]["tx_public_hash"], mempool_tx_public_hash)
        self.assertEqual(pending["preconfirmations"][0]["status"], "preconfirmed")
        self.assertNotIn("alice-view-key", json.dumps(pending))
        self.assertNotIn("bob-view-key", json.dumps(pending))
        self.assertEqual(
            net.transaction_status(mempool_tx_public_hash)["tx_public_hash"],
            tx_public_hash,
        )

        block = net.produce_block()
        included = net.transaction_status(tx_public_hash)
        self.assertEqual(included["status"], "soft_final")
        self.assertEqual(included["inclusion_status"], "included")
        self.assertEqual(included["block_height"], block.header.height)
        self.assertEqual(included["tx_index"], 0)
        self.assertEqual(included["block_hash"], block.header.block_hash())
        self.assertEqual(included["settlement"]["status"], "soft_final")
        self.assertEqual(included["validity_certificate_root"], net.validity_certificates[0].certificate_root())
        self.assertEqual(included["privacy_proof_aggregate_root"], net.privacy_proof_aggregates[0].aggregate_root())
        self.assertEqual(included["privacy_proof_item"]["tx_index"], 0)
        self.assertEqual(included["privacy_proof_item"]["tx_kind"], "private_transfer")
        self.assertNotIn("alice-view-key", json.dumps(included))
        self.assertNotIn("bob-view-key", json.dumps(included))

        submission = net.submit_anchor(
            block_height=block.header.height,
            submitter_label="anchor-operator-1",
            monero_txid="monero-anchor-tx-status",
        )
        anchored = net.transaction_status(tx_public_hash)
        self.assertEqual(anchored["status"], "anchored")
        self.assertEqual(anchored["settlement"]["best_anchor"]["anchor_id"], submission.anchor_id)

        net.confirm_anchor(submission.anchor_id, confirmations=10, finality_depth=10)
        final = net.transaction_status(mempool_tx_public_hash)
        self.assertEqual(final["status"], "monero_final")
        self.assertTrue(final["settlement"]["monero_final"])
        self.assertEqual(final["settlement"]["best_anchor"]["status"], "final")
        self.assertNotIn("monero-anchor-tx-status", json.dumps(final))
        with self.assertRaisesRegex(ValueError, "unknown transaction"):
            net.transaction_status("00")

    def test_mempool_preconfirmation_miss_slashes_without_revealing_payload(self) -> None:
        net = devnet.NebulaL2Devnet(epoch_size=3)
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        admission = net.pending_admissions[0]
        preconfirmation = next(iter(net.mempool_preconfirmations.values()))

        with self.assertRaisesRegex(ValueError, "target has not passed"):
            net.report_mempool_preconfirmation_miss(
                preconfirmation.preconfirmation_id,
                reporter_label="watchtower-a",
            )

        deferred = net.produce_block(include_pending=False)
        self.assertEqual(deferred.header.height, preconfirmation.target_height)
        self.assertEqual(len(net.pending), 1)
        missed_status = net.mempool_admission_status(admission.admission_id)
        self.assertEqual(missed_status["status"], "pending")
        self.assertEqual(missed_status["preconfirmations"][0]["status"], "target_missed")

        evidence = net.report_mempool_preconfirmation_miss(
            preconfirmation.preconfirmation_id,
            reporter_label="watchtower-a",
        )
        proposer_id = devnet.domain_hash("VALIDATOR-ID", "devnet-proposer")
        self.assertEqual(evidence.preconfirmation_id, preconfirmation.preconfirmation_id)
        self.assertEqual(evidence.admission_id, admission.admission_id)
        self.assertEqual(evidence.target_height, preconfirmation.target_height)
        self.assertEqual(evidence.missed_block_count, 1)
        self.assertEqual(evidence.penalty_units, 1)
        self.assertEqual(evidence.status, "slashed")
        self.assertEqual(evidence.slashed_validator_id, proposer_id)
        self.assertEqual(evidence.slashed_amount, 1)
        self.assertEqual(evidence.validator_stake_after, 999)
        self.assertEqual(len(net.pending), 1)
        self.assertEqual(len(net.pending_admissions), 1)
        public_evidence = json.dumps(evidence.public_record())
        self.assertNotIn("alice-view-key", public_evidence)
        self.assertNotIn("bob-view-key", public_evidence)
        validator = net.validators[proposer_id]
        self.assertEqual(validator.stake, 999)
        self.assertEqual(validator.slashed_stake, 1)
        self.assertEqual(validator.preconfirmation_miss_count, 1)
        self.assertEqual(validator.omission_count, 0)

        with self.assertRaisesRegex(ValueError, "already reported"):
            net.report_mempool_preconfirmation_miss(
                preconfirmation.preconfirmation_id,
                reporter_label="watchtower-a",
            )

        reported_status = net.mempool_admission_status(admission.admission_id)
        self.assertEqual(reported_status["preconfirmations"][0]["status"], "miss_reported")
        self.assertEqual(
            reported_status["preconfirmations"][0]["miss_evidence"][0]["evidence_id"],
            evidence.evidence_id,
        )

        included = net.produce_block()
        included_status = net.mempool_admission_status(admission.admission_id)
        self.assertEqual(included.header.height, 1)
        self.assertEqual(included_status["status"], "included")
        self.assertEqual(included_status["preconfirmations"][0]["status"], "missed_included_late")
        self.assertEqual(included_status["preconfirmation_miss_evidence"][0]["evidence_id"], evidence.evidence_id)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.mempool_preconfirmation_miss_root(),
            net.mempool_preconfirmation_miss_root(),
        )
        self.assertEqual(round_trip.validators[proposer_id].preconfirmation_miss_count, 1)

    def test_expired_mempool_admission_reports_omission_evidence(self) -> None:
        net = devnet.NebulaL2Devnet(epoch_size=2)
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        admission = net.pending_admissions[0]
        public_admission = admission.public_record()
        self.assertRelayMetadata(
            public_admission,
            policy="dandelion",
            raw_path="dandelion-stem-fluff",
        )
        self.assertEqual(net.state_record()["pending_mempool_admissions"][0]["relay_path"], "dandelion-stem-fluff")

        with self.assertRaisesRegex(ValueError, "not expired"):
            net.report_mempool_omission(admission.admission_id, reporter_label="watchtower-a")

        for _ in range(admission.expires_at_height + 1):
            block = net.produce_block(include_pending=False)
            self.assertEqual(block.header.execution_profile.tx_count, 0)
            self.assertEqual(block.header.mempool_admission_count, 0)
        self.assertEqual(len(net.pending), 1)
        self.assertEqual(len(net.pending_admissions), 1)

        root_before = net.mempool_omission_evidence_root()
        evidence = net.report_mempool_omission(
            admission.admission_id,
            reporter_label="watchtower-a",
        )
        proposer_id = devnet.domain_hash("VALIDATOR-ID", "devnet-proposer")
        self.assertEqual(evidence.admission_id, admission.admission_id)
        self.assertEqual(evidence.tx_public_hash, admission.tx_public_hash)
        self.assertEqual(evidence.encrypted_payload_hash, admission.encrypted_payload_hash)
        self.assertEqual(evidence.sequencer_label, "devnet-proposer")
        self.assertEqual(evidence.reporter_label, "watchtower-a")
        self.assertEqual(evidence.missed_block_count, 1)
        self.assertEqual(evidence.penalty_units, 1)
        self.assertEqual(evidence.status, "slashed")
        self.assertEqual(evidence.slashed_validator_id, proposer_id)
        self.assertEqual(evidence.slashed_amount, 1)
        self.assertEqual(evidence.validator_stake_after, 999)
        self.assertTrue(evidence.auth_signature)
        public_evidence = evidence.public_record()
        self.assertRelayMetadata(
            public_evidence,
            policy="dandelion",
            raw_path="dandelion-stem-fluff",
        )
        self.assertNotIn("alice-view-key", json.dumps(public_evidence))
        self.assertNotIn("bob-view-key", json.dumps(public_evidence))
        self.assertEqual(net.pending, [])
        self.assertEqual(net.pending_admissions, [])
        validator = net.validators[proposer_id]
        self.assertEqual(validator.stake, 999)
        self.assertEqual(validator.slashed_stake, 1)
        self.assertEqual(validator.omission_count, 1)
        self.assertEqual(validator.status, "active")
        self.assertNotEqual(root_before, net.mempool_omission_evidence_root())
        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["mempool_omission_evidence_count"], 1)
        self.assertEqual(
            snapshot["mempool_omission_evidence_root"],
            net.mempool_omission_evidence_root(),
        )
        omitted_status = net.mempool_admission_status(admission.admission_id)
        self.assertEqual(omitted_status["status"], "omitted")
        self.assertEqual(omitted_status["evidence_status"], "slashed")
        self.assertEqual(omitted_status["evidence"]["admission_id"], admission.admission_id)
        self.assertEqual(omitted_status["evidence"]["slashed_amount"], 1)
        self.assertEqual(omitted_status["forced_inclusion_count"], 0)
        self.assertNotIn("bob-view-key", json.dumps(omitted_status))

        with self.assertRaisesRegex(ValueError, "unknown mempool admission"):
            net.report_mempool_omission(admission.admission_id, reporter_label="watchtower-a")

        forced = net.force_include_omitted_admission(
            evidence.evidence_id,
            sequencer_label="devnet-proposer",
        )
        forced_record = forced.public_record()
        forced_admission = net.pending_admissions[0]
        self.assertEqual(forced.evidence_id, evidence.evidence_id)
        self.assertEqual(forced.admission_id, admission.admission_id)
        self.assertEqual(forced.tx_public_hash, admission.tx_public_hash)
        self.assertEqual(forced.old_encrypted_payload_hash, admission.encrypted_payload_hash)
        self.assertEqual(forced.new_admission_id, forced_admission.admission_id)
        self.assertEqual(forced.new_encrypted_payload_hash, forced_admission.encrypted_payload_hash)
        self.assertEqual(forced.new_relay_path, "forced-inclusion")
        self.assertNotEqual(forced.new_admission_id, admission.admission_id)
        self.assertTrue(forced.auth_signature)
        self.assertRelayMetadata(
            forced_record,
            policy="forced-inclusion",
            prefix="new_relay_path",
        )
        self.assertEqual(len(net.pending), 1)
        self.assertEqual(len(net.pending_admissions), 1)
        self.assertNotIn("alice-view-key", json.dumps(forced_record))
        self.assertNotIn("bob-view-key", json.dumps(forced_record))
        requeued_status = net.mempool_admission_status(admission.admission_id)
        self.assertEqual(requeued_status["forced_inclusion_count"], 1)
        self.assertEqual(
            requeued_status["forced_inclusions"][0]["forced_inclusion_id"],
            forced.forced_inclusion_id,
        )
        self.assertEqual(net.public_snapshot()["mempool_forced_inclusion_count"], 1)
        self.assertEqual(
            net.public_snapshot()["mempool_forced_inclusion_root"],
            net.mempool_forced_inclusion_root(),
        )
        with self.assertRaisesRegex(ValueError, "already has forced inclusion"):
            net.force_include_omitted_admission(evidence.evidence_id)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(len(round_trip.pending), 1)
        self.assertEqual(len(round_trip.pending_admissions), 1)
        self.assertEqual(
            round_trip.mempool_omission_evidence_root(),
            net.mempool_omission_evidence_root(),
        )
        self.assertEqual(
            round_trip.mempool_forced_inclusion_root(),
            net.mempool_forced_inclusion_root(),
        )
        self.assertEqual(
            next(iter(round_trip.mempool_omission_evidence.values())).admission_id,
            admission.admission_id,
        )
        self.assertEqual(round_trip.validators[proposer_id].stake, 999)
        self.assertEqual(round_trip.validators[proposer_id].slashed_stake, 1)
        included = round_trip.produce_block()
        new_status = round_trip.mempool_admission_status(forced.new_admission_id)
        self.assertEqual(included.header.mempool_admission_count, 1)
        self.assertEqual(new_status["status"], "included")
        self.assertRelayMetadata(
            new_status["admission"],
            policy="forced-inclusion",
        )
        self.assertEqual(note_amounts(round_trip.wallet_notes("bob-view-key"), asset.asset_id), [100])

        tampered = net.state_record()
        tampered["mempool_forced_inclusions"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid forced inclusion authorization"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_native_asset_issuer_mint_and_private_burn_flow(self) -> None:
        net = devnet.NebulaL2Devnet()
        with self.assertRaisesRegex(ValueError, "positive max supply"):
            net.create_asset("BAD", "issuer:treasury-key", supply_policy="fixed")
        asset = net.create_asset(
            "DGR",
            "issuer:treasury-key",
            supply_policy="fixed",
            max_supply=1_500,
        )
        self.assertEqual(asset.max_supply, 1_500)

        with self.assertRaisesRegex(ValueError, "issuer policy"):
            net.submit_asset_mint(
                asset.asset_id,
                "alice-view-key",
                amount=1_000,
                signer_label="mallory-key",
            )

        mint = net.submit_asset_mint(
            asset.asset_id,
            "alice-view-key",
            amount=1_000,
        )
        public_mint = mint.public_record()
        self.assertEqual(public_mint["kind"], "asset_mint")
        self.assertEqual(public_mint["amount"], 1_000)
        self.assertNotIn("alice-view-key", json.dumps(public_mint))
        self.assertNotIn("output_note", public_mint)
        self.assertTrue(public_mint["auth_signature"])
        mint_block = net.produce_block()

        supply = net.asset_supplies[asset.asset_id]
        self.assertEqual(supply.minted_amount, 1_000)
        self.assertEqual(supply.burned_amount, 0)
        self.assertEqual(supply.circulating_amount, 1_000)
        self.assertEqual(mint_block.header.asset_root, net.asset_root())
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), asset.asset_id), [1_000])
        self.assertEqual(mint_block.header.execution_profile.privacy_proof_count, 0)
        self.assertEqual(mint_block.header.execution_profile.authorization_count, 1)

        net.submit_asset_mint(asset.asset_id, "bob-view-key", amount=400)
        with self.assertRaisesRegex(ValueError, "max supply"):
            net.submit_asset_mint(asset.asset_id, "carol-view-key", amount=101)
        net.produce_block()
        self.assertEqual(net.asset_supplies[asset.asset_id].minted_amount, 1_400)

        note_id = net.wallet_notes("alice-view-key")[0]["note_id"]
        with self.assertRaisesRegex(ValueError, "signer does not own"):
            net.submit_asset_burn(note_id, amount=400, signer_label="mallory-key")

        burn = net.submit_asset_burn(note_id, amount=400)
        public_burn = burn.public_record()
        self.assertEqual(public_burn["kind"], "asset_burn")
        self.assertEqual(public_burn["amount"], 400)
        self.assertNotIn("spent_note_id", public_burn)
        self.assertNotIn("alice-view-key", json.dumps(public_burn))
        self.assertIn("proof_root", public_burn["proof_bundle"])

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        burn_block = round_trip.produce_block()
        supply = round_trip.asset_supplies[asset.asset_id]
        self.assertEqual(supply.minted_amount, 1_400)
        self.assertEqual(supply.burned_amount, 400)
        self.assertEqual(supply.circulating_amount, 1_000)
        self.assertEqual(
            note_amounts(round_trip.wallet_notes("alice-view-key"), asset.asset_id),
            [600],
        )
        self.assertEqual(
            note_amounts(round_trip.wallet_notes("bob-view-key"), asset.asset_id),
            [400],
        )
        self.assertEqual(burn_block.header.asset_root, round_trip.asset_root())
        self.assertEqual(burn_block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(burn_block.header.execution_profile.authorization_count, 1)

    def test_data_availability_record_commits_and_samples_block_payload(self) -> None:
        net = devnet.NebulaL2Devnet()
        net.register_validator("validator-two", stake=500)
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)

        block = net.produce_block(proposer_id="validator-two")
        record = net.da_records[block.header.height]
        self.assertEqual(block.header.da_root, record.da_root())
        self.assertEqual(record.tx_root, block.header.tx_root)
        self.assertEqual(len(record.attestations), 2)
        self.assertEqual(record.public_record()["attestation_count"], 2)
        self.assertEqual(net.public_snapshot()["data_availability_record_count"], 1)
        self.assertEqual(net.public_snapshot()["latest_da_root"], block.header.da_root)
        certificate = net.validity_certificates[block.header.height]
        self.assertEqual(certificate.block_hash, block.header.block_hash())
        self.assertEqual(certificate.state_root, block.header.state_root)
        self.assertEqual(certificate.tx_root, block.header.tx_root)
        self.assertEqual(certificate.da_root, block.header.da_root)
        self.assertEqual(certificate.prover_label, "validator-two")
        self.assertEqual(certificate.auth_scheme, devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertEqual(len(certificate.certificate_root()), 64)
        self.assertEqual(len(certificate.public_input_hash), 64)
        self.assertEqual(len(certificate.proof_root), 64)
        self.assertNotIn("alice-view-key", json.dumps(certificate.public_record()))
        self.assertNotIn("bob-view-key", json.dumps(certificate.public_record()))
        aggregate = net.privacy_proof_aggregates[block.header.height]
        self.assertEqual(aggregate.block_hash, block.header.block_hash())
        self.assertEqual(aggregate.tx_root, block.header.tx_root)
        self.assertEqual(aggregate.privacy_proof_count, 1)
        self.assertEqual(len(aggregate.aggregate_root()), 64)
        self.assertEqual(len(aggregate.aggregate_public_input_hash), 64)
        self.assertEqual(len(aggregate.aggregate_proof_root), 64)
        self.assertEqual(certificate.privacy_proof_aggregate_root, aggregate.aggregate_root())
        self.assertEqual(
            certificate.privacy_proof_aggregate_proof_root,
            aggregate.aggregate_proof_root,
        )
        self.assertEqual(aggregate.proof_items[0]["tx_index"], 0)
        self.assertEqual(aggregate.proof_items[0]["tx_kind"], "private_transfer")
        aggregate_json = json.dumps(aggregate.public_record())
        self.assertNotIn("private_witness_hash", aggregate_json)
        self.assertNotIn("alice-view-key", aggregate_json)
        self.assertNotIn("bob-view-key", aggregate_json)
        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["validity_certificate_count"], 1)
        self.assertEqual(snapshot["validity_root"], net.validity_root())
        self.assertEqual(
            snapshot["latest_validity_certificate_root"],
            certificate.certificate_root(),
        )
        self.assertEqual(snapshot["privacy_proof_aggregate_count"], 1)
        self.assertEqual(
            snapshot["privacy_proof_aggregate_root"],
            net.privacy_proof_aggregate_root(),
        )
        self.assertEqual(
            snapshot["latest_privacy_proof_aggregate_root"],
            aggregate.aggregate_root(),
        )

        sample = net.sample_data_availability(block.header.height, shard_index=0)
        self.assertTrue(sample["verified"])
        self.assertEqual(sample["da_root"], block.header.da_root)
        self.assertEqual(sample["shard"]["shard_kind"], "data")
        self.assertTrue(sample["shard"]["data"].startswith('{"chain_id"'))

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.da_records[0].da_root(), block.header.da_root)
        self.assertEqual(
            round_trip.validity_certificates[0].certificate_root(),
            certificate.certificate_root(),
        )
        self.assertEqual(
            round_trip.privacy_proof_aggregates[0].aggregate_root(),
            aggregate.aggregate_root(),
        )
        self.assertTrue(round_trip.sample_data_availability(0, 0)["verified"])

        tampered_state = net.state_record()
        tampered_state["data_availability_records"][0]["shards"][0]["data"] = "tampered"
        with self.assertRaisesRegex(ValueError, "DA record root mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered_state)

        tampered_certificate = net.state_record()
        tampered_certificate["validity_certificates"][0]["proof_root"] = "00"
        with self.assertRaisesRegex(ValueError, "validity certificate proof"):
            devnet.NebulaL2Devnet.from_state_record(tampered_certificate)

        tampered_aggregate = net.state_record()
        tampered_aggregate["privacy_proof_aggregates"][0]["aggregate_proof_root"] = "00"
        with self.assertRaisesRegex(ValueError, "privacy proof aggregate proof"):
            devnet.NebulaL2Devnet.from_state_record(tampered_aggregate)

    def test_watchtower_block_audits_and_challenges_are_public_evidence(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        block = net.produce_block()

        audit = net.audit_block(
            block.header.height,
            watchtower_label="watchtower-a",
            shard_indices=(0, 1),
        )
        self.assertEqual(audit.block_hash, block.header.block_hash())
        self.assertEqual(audit.da_root, block.header.da_root)
        self.assertEqual(audit.validity_certificate_root, net.validity_certificates[0].certificate_root())
        self.assertEqual(audit.privacy_proof_aggregate_root, net.privacy_proof_aggregates[0].aggregate_root())
        self.assertEqual(audit.sampled_shard_indices, (0, 1))
        self.assertEqual(audit.sampled_shard_count, 2)
        self.assertEqual(audit.audit_status, "available")
        self.assertTrue(audit.auth_signature)
        self.assertNotIn("alice-view-key", json.dumps(audit.public_record()))
        self.assertNotIn("bob-view-key", json.dumps(audit.public_record()))
        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["block_audit_report_count"], 1)
        self.assertEqual(snapshot["block_audit_report_root"], net.block_audit_report_root())

        with self.assertRaisesRegex(ValueError, "already reported"):
            net.audit_block(
                block.header.height,
                watchtower_label="watchtower-a",
                shard_indices=(1, 0),
            )

        external = net.report_block_challenge(
            block.header.height,
            "bridge-root-mismatch",
            reporter_label="watchtower-b",
            observed_root=devnet.domain_hash("EXTERNAL-BRIDGE-ROOT", "conflict"),
        )
        self.assertEqual(external.status, "external_dispute")
        self.assertEqual(external.slashed_amount, 0)
        proposer = net.validators[block.header.proposer_id]
        self.assertEqual(proposer.block_challenge_count, 0)
        self.assertEqual(net.public_snapshot()["block_challenge_report_count"], 1)
        self.assertNotIn("alice-view-key", json.dumps(external.public_record()))
        self.assertNotIn("bob-view-key", json.dumps(external.public_record()))

        missing_cert_state = net.state_record()
        missing_cert_state["validity_certificates"] = []
        missing_cert_state["block_audit_reports"] = []
        challenged = devnet.NebulaL2Devnet.from_state_record(missing_cert_state)
        missing = challenged.report_block_challenge(
            block.header.height,
            "missing-validity-certificate",
            reporter_label="watchtower-c",
        )
        self.assertEqual(missing.status, "slashed")
        self.assertEqual(missing.penalty_units, 1)
        self.assertEqual(missing.slashed_amount, 1)
        challenged_proposer = challenged.validators[block.header.proposer_id]
        self.assertEqual(challenged_proposer.slashed_stake, 1)
        self.assertEqual(challenged_proposer.block_challenge_count, 1)
        self.assertEqual(
            challenged.public_snapshot()["block_challenge_report_root"],
            challenged.block_challenge_report_root(),
        )

        round_trip = devnet.NebulaL2Devnet.from_state_record(challenged.state_record())
        self.assertEqual(round_trip.block_challenge_report_root(), challenged.block_challenge_report_root())
        self.assertEqual(round_trip.validators[block.header.proposer_id].block_challenge_count, 1)

        tampered_audit = net.state_record()
        tampered_audit["block_audit_reports"][0]["sampled_shard_root"] = "00"
        with self.assertRaisesRegex(ValueError, "sampled shard root"):
            devnet.NebulaL2Devnet.from_state_record(tampered_audit)

        tampered_challenge = challenged.state_record()
        tampered_challenge["block_challenge_reports"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid block challenge authorization"):
            devnet.NebulaL2Devnet.from_state_record(tampered_challenge)

    def test_contract_calls_update_storage_and_contract_root(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        fee_note = net.mint(fee_asset.asset_id, "bob-view-key", 10)
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        root_before = net.produce_block().header.contract_root

        tx = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 7},
            signer_label="bob-view-key",
            fuel_limit=20,
            fee_asset_id=fee_asset.asset_id,
            fee_note_id=fee_note.note_id,
            max_fee=1,
        )
        self.assertEqual(tx.auth_scheme, devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertEqual(tx.fuel_used, 11)
        self.assertEqual(tx.fee_asset_id, fee_asset.asset_id)
        self.assertEqual(tx.fee, 1)
        self.assertEqual(tx.fee_nullifier, net._note_nullifier(fee_note))
        self.assertIsNotNone(tx.privacy_proof)
        self.assertIn("proof_root", tx.public_record()["proof_bundle"])
        self.assertNotIn("fee_note_id", tx.public_record())
        block = net.produce_block()
        updated = net.contracts[contract.contract_id]
        self.assertEqual(updated.storage["count"], 7)
        self.assertEqual(updated.storage["last_caller"], "bob-view-key")
        self.assertNotEqual(root_before, block.header.contract_root)
        self.assertEqual(block.header.execution_profile.contract_call_count, 1)
        self.assertEqual(block.header.execution_profile.execution_fuel, 11)
        self.assertEqual(block.header.execution_profile.observed_fee_units, 1)
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(net.fees_collected[fee_asset.asset_id], 1)
        self.assertEqual(note_amounts(net.wallet_notes("bob-view-key"), fee_asset.asset_id), [9])
        self.assertEqual(block.header.contract_root, net.contract_root())
        self.assertEqual(len(net.contract_events), 1)
        event = next(iter(net.contract_events.values()))
        event_record = event.public_record()
        self.assertEqual(event_record["contract_id"], contract.contract_id)
        self.assertEqual(event_record["event_name"], "counter.incremented")
        self.assertEqual(event_record["emitted_at_height"], block.header.height)
        self.assertEqual(event_record["contract_storage_root"], updated.storage_root())
        self.assertEqual(
            event_record["previous_event_root"],
            devnet.merkle_root("CONTRACT-EVENT", []),
        )
        self.assertEqual(event_record["event_id"], event.expected_event_id())
        self.assertEqual(
            event_record["event_chain_root"],
            event.expected_event_chain_root(),
        )
        self.assertEqual(event_record["public_data"]["amount"], 7)
        self.assertEqual(event_record["public_data"]["new_count"], 7)
        self.assertEqual(
            event_record["public_data"]["caller_commitment"],
            devnet.domain_hash("CONTRACT-CALLER", "bob-view-key"),
        )
        self.assertNotIn("bob-view-key", json.dumps(event_record))
        self.assertEqual(len(net.contract_execution_receipts), 1)
        receipt = next(iter(net.contract_execution_receipts.values()))
        receipt_record = receipt.public_record()
        self.assertEqual(receipt_record["kind"], "contract_execution_receipt")
        self.assertEqual(receipt_record["contract_id"], contract.contract_id)
        self.assertEqual(receipt_record["template"], "counter")
        self.assertEqual(receipt_record["entrypoint"], "increment")
        self.assertEqual(receipt_record["call_index"], 0)
        self.assertEqual(receipt_record["block_height"], block.header.height)
        self.assertEqual(receipt_record["tx_index"], 0)
        self.assertEqual(receipt_record["args_commitment"], tx.args_commitment())
        self.assertEqual(receipt_record["private_args"], False)
        self.assertEqual(
            receipt_record["caller_commitment"],
            devnet.domain_hash("CONTRACT-CALLER", "bob-view-key"),
        )
        self.assertEqual(receipt_record["fuel_limit"], 20)
        self.assertEqual(receipt_record["fuel_used"], 11)
        self.assertEqual(receipt_record["storage_root_before"], contract.storage_root())
        self.assertEqual(receipt_record["storage_root_after"], updated.storage_root())
        self.assertEqual(receipt_record["event_id"], event.event_id)
        self.assertEqual(receipt_record["event_chain_root"], event.event_chain_root)
        self.assertEqual(receipt_record["receipt_id"], receipt.expected_receipt_id())
        self.assertNotIn("args", receipt_record)
        self.assertNotIn("bob-view-key", json.dumps(receipt_record))
        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["contract_event_count"], 1)
        self.assertEqual(snapshot["contract_event_root"], net.contract_event_root())
        self.assertEqual(snapshot["contract_execution_receipt_count"], 1)
        self.assertEqual(
            snapshot["contract_execution_receipt_root"],
            net.contract_execution_receipt_root(),
        )
        self.assertEqual(snapshot["contract_root"], net.contract_root())
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.contract_event_root(), net.contract_event_root())
        self.assertEqual(
            round_trip.contract_execution_receipt_root(),
            net.contract_execution_receipt_root(),
        )
        self.assertEqual(
            next(iter(round_trip.contract_events.values())).public_record(),
            event_record,
        )
        self.assertEqual(
            next(iter(round_trip.contract_execution_receipts.values())).public_record(),
            receipt_record,
        )
        tampered_events = net.state_record()
        tampered_events["contract_events"][0]["previous_event_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "previous root mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered_events)
        tampered_receipts = net.state_record()
        tampered_receipts["contract_execution_receipts"][0]["fuel_used"] = 12
        with self.assertRaisesRegex(ValueError, "execution receipt id mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered_receipts)

        tamper_fee_note = net.mint(fee_asset.asset_id, "bob-view-key", 10)
        tampered = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 1},
            signer_label="bob-view-key",
            fuel_limit=20,
            fee_asset_id=fee_asset.asset_id,
            fee_note_id=tamper_fee_note.note_id,
            max_fee=1,
        )
        bad_change = devnet.Note.create(
            "bob-view-key",
            fee_asset.asset_id,
            tamper_fee_note.amount - 2,
            net._next_nonce(),
        )
        bad_tx = replace(tampered, fee=2, fee_change_note=bad_change)
        bad_tx = net._attach_privacy_proof(bad_tx)
        bad_tx = net._authorize_transaction(bad_tx, tampered.signer_label)
        net.pending[-1] = bad_tx
        with self.assertRaisesRegex(ValueError, "invalid contract fee"):
            net.produce_block()
        net.pending.clear()

        with self.assertRaisesRegex(ValueError, "only the contract owner"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="set",
                args={"value": 1},
                signer_label="bob-view-key",
                fuel_limit=50,
            )
        with self.assertRaisesRegex(ValueError, "exceeds fuel"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 999},
                signer_label="bob-view-key",
                fuel_limit=1,
            )

    def test_private_contract_args_are_committed_not_published(self) -> None:
        net = devnet.NebulaL2Devnet()
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)

        tx = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 17},
            signer_label="bob-view-key",
            fuel_limit=20,
            private_args=True,
        )
        public_tx = tx.public_record()
        self.assertTrue(public_tx["private_args"])
        self.assertEqual(public_tx["args_commitment"], tx.args_commitment())
        self.assertNotIn("args", public_tx)
        self.assertEqual(tx.state_record()["args"], {"amount": 17})
        self.assertIsNotNone(tx.privacy_proof)
        self.assertIn("proof_root", public_tx["proof_bundle"])

        quote = net.fee_quote(
            operation="contract-call",
            contract_id=contract.contract_id,
            contract_fuel=tx.fuel_used,
            fee_mode="none",
            private_args=True,
        )
        self.assertEqual(quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertTrue(quote["private_args"])

        block = net.produce_block()
        block_tx = block.public_record()["transactions"][0]
        self.assertNotIn("args", block_tx)
        self.assertEqual(block_tx["args_commitment"], tx.args_commitment())
        self.assertEqual(net.contracts[contract.contract_id].storage["count"], 17)
        self.assertEqual(block.header.execution_profile.contract_call_count, 1)
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)

        event = next(iter(net.contract_events.values())).public_record()
        self.assertEqual(event["event_name"], "counter.incremented")
        self.assertEqual(event["public_data"]["args_commitment"], tx.args_commitment())
        self.assertTrue(event["public_data"]["private_args"])
        self.assertNotIn("amount", event["public_data"])
        self.assertNotIn("new_count", event["public_data"])
        public_dump = json.dumps({
            "transaction": block_tx,
            "event": event,
            "mempool": [admission.public_record() for admission in net.pending_admissions],
        })
        self.assertNotIn('"args":', public_dump)
        self.assertNotIn('"amount": 17', public_dump)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.contracts[contract.contract_id].storage["count"], 17)
        replay_tx = round_trip.blocks[0].transactions[0]
        self.assertIsInstance(replay_tx, devnet.ContractCall)
        self.assertEqual(replay_tx.state_record()["args"], {"amount": 17})
        self.assertNotIn("args", replay_tx.public_record())

    def test_contract_event_disclosure_opens_private_event_args_selectively(self) -> None:
        net = devnet.NebulaL2Devnet()
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        tx = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 19},
            signer_label="bob-view-key",
            fuel_limit=20,
            private_args=True,
        )
        net.produce_block()
        event = next(iter(net.contract_events.values()))
        event_record = event.public_record()
        self.assertEqual(event_record["public_data"]["args_commitment"], tx.args_commitment())
        self.assertNotIn("amount", event_record["public_data"])

        disclosure = net.contract_event_disclosure(
            event.event_id,
            signer_label="bob-view-key",
            audience_label="defi-indexer",
            expires_in_blocks=2,
        )
        public_record = disclosure.public_record()
        self.assertEqual(public_record["event_id"], event.event_id)
        self.assertEqual(public_record["audience_label"], "defi-indexer")
        self.assertEqual(public_record["args_commitment"], tx.args_commitment())
        self.assertEqual(public_record["caller_commitment"], event.public_data["caller_commitment"])
        self.assertNotIn("opening", public_record)
        self.assertNotIn("bob-view-key", json.dumps(public_record))
        self.assertNotIn('"amount": 19', json.dumps(public_record))

        audit_record = disclosure.audit_record("bob-view-key")
        self.assertEqual(audit_record["disclosed_signer_label"], "bob-view-key")
        self.assertEqual(audit_record["opening"]["entrypoint"], "increment")
        self.assertEqual(audit_record["opening"]["args"], {"amount": 19})
        self.assertTrue(net.verify_contract_event_disclosure(audit_record))
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertTrue(round_trip.verify_contract_event_disclosure(audit_record))

        tampered_args = json.loads(json.dumps(audit_record))
        tampered_args["opening"]["args"]["amount"] = 20
        with self.assertRaisesRegex(ValueError, "opening root|opening mismatch"):
            net.verify_contract_event_disclosure(tampered_args)

        tampered_auth = json.loads(json.dumps(audit_record))
        tampered_auth["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid contract event disclosure authorization"):
            net.verify_contract_event_disclosure(tampered_auth)

        with self.assertRaisesRegex(ValueError, "only the event signer"):
            net.contract_event_disclosure(
                event.event_id,
                signer_label="alice-view-key",
                audience_label="defi-indexer",
            )

        public_event_net = devnet.NebulaL2Devnet()
        public_contract = public_event_net.deploy_contract(
            "counter",
            owner_label="alice-view-key",
            fuel_limit=100,
        )
        public_event_net.submit_contract_call(
            public_contract.contract_id,
            entrypoint="increment",
            args={"amount": 1},
            signer_label="bob-view-key",
            fuel_limit=20,
        )
        public_event_net.produce_block()
        public_event = next(iter(public_event_net.contract_events.values()))
        with self.assertRaisesRegex(ValueError, "no private args"):
            public_event_net.contract_event_disclosure(
                public_event.event_id,
                signer_label="bob-view-key",
                audience_label="defi-indexer",
            )

        expiring = net.contract_event_disclosure(
            event.event_id,
            signer_label="bob-view-key",
            audience_label="short-audit",
            expires_in_blocks=1,
        ).audit_record("bob-view-key")
        net.produce_block()
        net.produce_block()
        with self.assertRaisesRegex(ValueError, "expired"):
            net.verify_contract_event_disclosure(expiring)

    def test_private_contract_storage_is_committed_not_published(self) -> None:
        net = devnet.NebulaL2Devnet()
        contract = net.deploy_contract(
            "counter",
            owner_label="alice-view-key",
            fuel_limit=100,
            private_storage=True,
        )
        public_contract = contract.public_record()
        self.assertTrue(public_contract["private_storage"])
        self.assertNotIn("storage", public_contract)
        self.assertEqual(public_contract["storage_commitment"], contract.storage_root())
        self.assertEqual(contract.state_record()["storage"]["count"], 0)
        root_before = net.contract_root()

        tx = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 23},
            signer_label="bob-view-key",
            fuel_limit=20,
            private_args=True,
        )
        block = net.produce_block()
        updated = net.contracts[contract.contract_id]
        self.assertEqual(updated.storage["count"], 23)
        self.assertNotEqual(root_before, block.header.contract_root)
        self.assertEqual(block.header.contract_root, net.contract_root())

        updated_public = updated.public_record()
        self.assertTrue(updated_public["private_storage"])
        self.assertNotIn("storage", updated_public)
        self.assertEqual(updated_public["storage_root"], updated.storage_root())
        self.assertEqual(updated_public["storage_commitment"], updated.storage_root())
        snapshot_contract = next(
            item
            for item in net.public_snapshot()["contracts"]
            if item["contract_id"] == contract.contract_id
        )
        self.assertNotIn("storage", snapshot_contract)
        public_dump = json.dumps({
            "contract": snapshot_contract,
            "block": block.public_record(),
            "events": [event.public_record() for event in net.contract_events.values()],
        })
        self.assertNotIn('"count": 23', public_dump)
        self.assertNotIn("bob-view-key", public_dump)
        self.assertIn(tx.args_commitment(), public_dump)

        state_record = net.state_record()
        state_contract = next(
            item for item in state_record["contracts"] if item["contract_id"] == contract.contract_id
        )
        self.assertEqual(state_contract["storage"]["count"], 23)
        round_trip = devnet.NebulaL2Devnet.from_state_record(state_record)
        self.assertEqual(round_trip.contracts[contract.contract_id].storage["count"], 23)
        self.assertNotIn("storage", round_trip.contracts[contract.contract_id].public_record())

    def test_contract_storage_disclosure_is_scoped_signed_and_tamper_checked(self) -> None:
        net = devnet.NebulaL2Devnet()
        contract = net.deploy_contract(
            "counter",
            owner_label="alice-view-key",
            fuel_limit=100,
            private_storage=True,
        )
        net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 31},
            signer_label="bob-view-key",
            fuel_limit=20,
            private_args=True,
        )
        net.produce_block()

        disclosure = net.contract_storage_disclosure(
            contract.contract_id,
            owner_label="alice-view-key",
            audience_label="defi-auditor",
            paths=("count",),
            expires_in_blocks=2,
        )
        public_record = disclosure.public_record()
        self.assertEqual(public_record["audience_label"], "defi-auditor")
        self.assertEqual(public_record["contract_id"], contract.contract_id)
        self.assertEqual(public_record["path_count"], 1)
        self.assertEqual(len(public_record["opening_root"]), 64)
        self.assertEqual(public_record["storage_root"], net.contracts[contract.contract_id].storage_root())
        self.assertNotIn("openings", public_record)
        self.assertNotIn("alice-view-key", json.dumps(public_record))
        self.assertNotIn('"count": 31', json.dumps(public_record))

        audit_record = disclosure.audit_record("alice-view-key")
        self.assertEqual(audit_record["disclosed_owner_label"], "alice-view-key")
        self.assertEqual(audit_record["openings"][0]["path"], "count")
        self.assertEqual(audit_record["openings"][0]["value"], 31)
        self.assertEqual(len(audit_record["openings"][0]["value_hash"]), 64)
        self.assertTrue(net.verify_contract_storage_disclosure(audit_record))

        tampered_value = json.loads(json.dumps(audit_record))
        tampered_value["openings"][0]["value"] = 32
        with self.assertRaisesRegex(ValueError, "opening root|opening mismatch"):
            net.verify_contract_storage_disclosure(tampered_value)

        tampered_auth = json.loads(json.dumps(audit_record))
        tampered_auth["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid contract storage disclosure authorization"):
            net.verify_contract_storage_disclosure(tampered_auth)

        with self.assertRaisesRegex(ValueError, "only the contract owner"):
            net.contract_storage_disclosure(
                contract.contract_id,
                owner_label="bob-view-key",
                audience_label="defi-auditor",
                paths=("count",),
            )
        with self.assertRaisesRegex(ValueError, "unknown contract storage path"):
            net.contract_storage_disclosure(
                contract.contract_id,
                owner_label="alice-view-key",
                audience_label="defi-auditor",
                paths=("missing",),
            )

        expiring = net.contract_storage_disclosure(
            contract.contract_id,
            owner_label="alice-view-key",
            audience_label="short-audit",
            paths=("count",),
            expires_in_blocks=1,
        ).audit_record("alice-view-key")
        net.produce_block()
        net.produce_block()
        with self.assertRaisesRegex(ValueError, "expired"):
            net.verify_contract_storage_disclosure(expiring)

    def test_contract_call_batch_uses_one_fee_auth_and_proof(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        fee_note = net.mint(fee_asset.asset_id, "bob-view-key", 10)
        contract = net.deploy_contract(
            "counter",
            owner_label="alice-view-key",
            fuel_limit=100,
            private_storage=True,
        )

        batch = net.submit_contract_call_batch(
            calls=[
                {
                    "contract_id": contract.contract_id,
                    "entrypoint": "increment",
                    "args": {"amount": 5},
                    "fuel_limit": 20,
                    "private_args": True,
                },
                {
                    "contract_id": contract.contract_id,
                    "entrypoint": "increment",
                    "args": {"amount": 7},
                    "fuel_limit": 20,
                    "private_args": True,
                },
            ],
            signer_label="bob-view-key",
            fee_asset_id=fee_asset.asset_id,
            fee_note_id=fee_note.note_id,
            max_fee=1,
        )
        public_batch = batch.public_record()
        self.assertEqual(public_batch["kind"], "contract_call_batch")
        self.assertEqual(public_batch["call_count"], 2)
        self.assertEqual(public_batch["total_fuel_used"], 22)
        self.assertEqual(public_batch["fee"], 1)
        self.assertNotIn("fee_note_id", public_batch)
        self.assertIn("proof_root", public_batch["proof_bundle"])
        self.assertTrue(all("args" not in call for call in public_batch["calls"]))
        self.assertEqual(batch.state_record()["calls"][0]["args"], {"amount": 5})
        self.assertEqual(batch.state_record()["calls"][1]["args"], {"amount": 7})

        quote = net.fee_quote(
            operation="contract-call-batch",
            input_count=2,
            contract_fuel=batch.total_fuel_used(),
            fee_asset_id=fee_asset.asset_id,
            contract_id=contract.contract_id,
            private_args=True,
        )
        self.assertEqual(quote["candidate_profile"]["contract_call_count"], 2)
        self.assertEqual(quote["candidate_profile"]["authorization_count"], 1)
        self.assertEqual(quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertEqual(quote["minimum_fee_units"], 1)

        block = net.produce_block()
        self.assertEqual(net.contracts[contract.contract_id].storage["count"], 12)
        self.assertEqual(block.header.execution_profile.tx_count, 1)
        self.assertEqual(block.header.execution_profile.contract_call_count, 2)
        self.assertEqual(block.header.execution_profile.authorization_count, 1)
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(block.header.execution_profile.observed_fee_units, 1)
        self.assertEqual(note_amounts(net.wallet_notes("bob-view-key"), fee_asset.asset_id), [9])
        self.assertEqual(len(net.contract_events), 2)
        self.assertEqual(len(net.contract_execution_receipts), 2)
        receipts = sorted(
            net.contract_execution_receipts.values(),
            key=lambda item: item.call_index,
        )
        self.assertEqual([receipt.call_index for receipt in receipts], [0, 1])
        self.assertEqual([receipt.tx_index for receipt in receipts], [0, 0])
        self.assertEqual([receipt.fuel_used for receipt in receipts], [11, 11])
        self.assertEqual(
            [receipt.args_commitment for receipt in receipts],
            [call.args_commitment() for call in batch.calls],
        )
        self.assertEqual(
            [receipt.private_args for receipt in receipts],
            [True, True],
        )
        self.assertEqual(
            [receipt.storage_root_after for receipt in receipts],
            [event.contract_storage_root for event in sorted(
                net.contract_events.values(),
                key=lambda item: (item.event_index, item.event_id),
            )],
        )
        self.assertEqual(
            net.public_snapshot()["contract_execution_receipt_root"],
            net.contract_execution_receipt_root(),
        )
        public_dump = json.dumps({
            "block": block.public_record(),
            "events": [event.public_record() for event in net.contract_events.values()],
            "receipts": [
                receipt.public_record()
                for receipt in net.contract_execution_receipts.values()
            ],
            "contract": net.contracts[contract.contract_id].public_record(),
        })
        self.assertNotIn('"args":', public_dump)
        self.assertNotIn('"amount": 5', public_dump)
        self.assertNotIn('"amount": 7', public_dump)
        self.assertNotIn('"count": 12', public_dump)
        self.assertNotIn("bob-view-key", public_dump)

        history = net.wallet_history("bob-view-key")
        spend_events = [event for event in history["events"] if event["event"] == "spent"]
        self.assertEqual(spend_events[0]["kind"], "contract_call_batch_fee")
        self.assertEqual(spend_events[0]["call_count"], 2)
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        replay_batch = round_trip.blocks[0].transactions[0]
        self.assertIsInstance(replay_batch, devnet.ContractCallBatch)
        self.assertEqual(round_trip.contracts[contract.contract_id].storage["count"], 12)
        self.assertNotIn("args", replay_batch.public_record()["calls"][0])
        self.assertEqual(
            round_trip.contract_execution_receipt_root(),
            net.contract_execution_receipt_root(),
        )

    def test_contract_upgrade_requires_owner_timelock_and_persists(self) -> None:
        net = devnet.NebulaL2Devnet()
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=20)
        root_before = net.contract_root()

        with self.assertRaisesRegex(ValueError, "exceeds contract policy"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="bob-view-key",
                fuel_limit=50,
            )

        with self.assertRaisesRegex(ValueError, "only the contract owner"):
            net.propose_contract_upgrade(
                contract.contract_id,
                proposed_version=2,
                proposer_label="mallory-view-key",
            )

        proposal = net.propose_contract_upgrade(
            contract.contract_id,
            proposed_version=2,
            proposed_fuel_limit=80,
            proposer_label="alice-view-key",
            timelock_blocks=2,
        )
        proposal_record = proposal.public_record()
        self.assertEqual(proposal.status, "pending")
        self.assertEqual(proposal.proposed_at_height, 0)
        self.assertEqual(proposal.executable_at_height, 2)
        self.assertEqual(proposal.proposed_code_hash, devnet.domain_hash("CONTRACT-CODE", "counter", 2))
        self.assertEqual(proposal.auth_scheme, devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertTrue(proposal.auth_signature)
        self.assertTrue(
            devnet.verify_authorization(
                "alice-view-key",
                "contract_upgrade_proposal",
                proposal.unsigned_record(),
                proposal.auth_scheme,
                proposal.auth_public_key,
                proposal.auth_transcript_hash,
                proposal.auth_signature,
            )
        )
        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["contract_upgrade_count"], 1)
        self.assertEqual(snapshot["contract_upgrade_root"], net.contract_upgrade_root())
        self.assertEqual(snapshot["contract_upgrade_proposals"][0], proposal_record)

        with self.assertRaisesRegex(ValueError, "pending upgrade"):
            net.propose_contract_upgrade(contract.contract_id, proposed_version=3)
        with self.assertRaisesRegex(ValueError, "timelock"):
            net.execute_contract_upgrade(proposal.proposal_id)

        net.produce_block()
        with self.assertRaisesRegex(ValueError, "timelock"):
            net.execute_contract_upgrade(proposal.proposal_id)
        net.produce_block()

        executed = net.execute_contract_upgrade(
            proposal.proposal_id,
            executor_label="upgrade-keeper",
        )
        upgraded = net.contracts[contract.contract_id]
        self.assertEqual(executed.status, "executed")
        self.assertEqual(executed.executed_at_height, 2)
        self.assertEqual(upgraded.version, 2)
        self.assertEqual(upgraded.fuel_limit, 80)
        self.assertEqual(upgraded.code_hash, proposal.proposed_code_hash)
        self.assertNotEqual(root_before, net.contract_root())
        self.assertEqual(net.public_snapshot()["contract_upgrade_count"], 1)

        upgrade_event = next(iter(net.contract_events.values())).public_record()
        self.assertEqual(upgrade_event["event_name"], "contract.upgraded")
        self.assertEqual(upgrade_event["public_data"]["proposal_id"], proposal.proposal_id)
        self.assertEqual(upgrade_event["public_data"]["new_version"], 2)
        self.assertEqual(upgrade_event["public_data"]["new_fuel_limit"], 80)
        self.assertEqual(
            upgrade_event["public_data"]["executor_commitment"],
            devnet.domain_hash("CONTRACT-UPGRADE-EXECUTOR", "upgrade-keeper"),
        )
        self.assertNotIn("upgrade-keeper", json.dumps(upgrade_event))

        with self.assertRaisesRegex(ValueError, "not pending"):
            net.execute_contract_upgrade(proposal.proposal_id)

        call = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 40},
            signer_label="bob-view-key",
            fuel_limit=50,
        )
        self.assertEqual(call.fuel_used, 12)
        net.produce_block()
        self.assertEqual(net.contracts[contract.contract_id].storage["count"], 40)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.contract_upgrade_root(), net.contract_upgrade_root())
        self.assertEqual(
            round_trip.contract_upgrade_proposals[proposal.proposal_id].public_record(),
            net.contract_upgrade_proposals[proposal.proposal_id].public_record(),
        )

        tampered = net.state_record()
        tampered["contract_upgrade_proposals"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid contract upgrade authorization"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_governor_contract_uses_committed_pq_voting(self) -> None:
        net = devnet.NebulaL2Devnet()
        governor = net.deploy_contract(
            "governor",
            owner_label="dao-owner-key",
            fuel_limit=300,
        )
        description_hash = devnet.domain_hash("DAO-DESCRIPTION", "raise paymaster cap")
        action_hash = devnet.domain_hash("DAO-ACTION", "paymaster-policy-v2")

        propose = net.submit_contract_call(
            governor.contract_id,
            entrypoint="propose",
            args={
                "description_hash": description_hash,
                "action_hash": action_hash,
                "voting_period_blocks": 2,
                "quorum": 2,
            },
            signer_label="alice-voter-key",
            fuel_limit=100,
        )
        self.assertEqual(propose.auth_scheme, devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertNotIn("alice-voter-key", json.dumps(propose.public_record()))
        proposal_block = net.produce_block()
        governor_state = net.contracts[governor.contract_id]
        proposals = dict(governor_state.storage["proposals"])
        self.assertEqual(len(proposals), 1)
        proposal_id = next(iter(proposals))
        proposal = proposals[proposal_id]
        self.assertEqual(proposal["description_hash"], description_hash)
        self.assertEqual(proposal["action_hash"], action_hash)
        self.assertEqual(proposal["quorum"], 2)
        self.assertEqual(proposal["start_height"], 0)
        self.assertEqual(proposal["end_height"], 2)
        self.assertEqual(
            proposal["proposer_commitment"],
            devnet.domain_hash("CONTRACT-CALLER", "alice-voter-key"),
        )
        self.assertNotIn("alice-voter-key", json.dumps(governor_state.public_record()))
        proposed_event = sorted(
            net.contract_events.values(),
            key=lambda item: item.event_index,
        )[-1].public_record()
        self.assertEqual(proposed_event["event_name"], "governor.proposed")
        self.assertEqual(proposed_event["public_data"]["proposal_id"], proposal_id)
        self.assertEqual(proposed_event["public_data"]["quorum"], 2)
        self.assertNotIn("alice-voter-key", json.dumps(proposed_event))
        self.assertEqual(proposal_block.header.execution_profile.contract_call_count, 1)

        with self.assertRaisesRegex(ValueError, "voting period has not ended"):
            net.submit_contract_call(
                governor.contract_id,
                entrypoint="execute",
                args={"proposal_id": proposal_id},
                signer_label="keeper-key",
                fuel_limit=80,
            )

        yes = net.submit_contract_call(
            governor.contract_id,
            entrypoint="vote",
            args={"proposal_id": proposal_id, "support": True, "weight": 2},
            signer_label="alice-voter-key",
            fuel_limit=80,
        )
        no = net.submit_contract_call(
            governor.contract_id,
            entrypoint="vote",
            args={"proposal_id": proposal_id, "support": False, "weight": 1},
            signer_label="bob-voter-key",
            fuel_limit=80,
        )
        self.assertTrue(yes.auth_signature)
        self.assertTrue(no.auth_signature)
        vote_block = net.produce_block()
        proposal = net.contracts[governor.contract_id].storage["proposals"][proposal_id]
        self.assertEqual(proposal["yes_weight"], 2)
        self.assertEqual(proposal["no_weight"], 1)
        self.assertEqual(
            sorted(proposal["voter_commitments"]),
            sorted([
                devnet.domain_hash("CONTRACT-CALLER", "alice-voter-key"),
                devnet.domain_hash("CONTRACT-CALLER", "bob-voter-key"),
            ]),
        )
        self.assertNotIn("alice-voter-key", json.dumps(proposal))
        self.assertNotIn("bob-voter-key", json.dumps(proposal))
        vote_events = [
            event.public_record()
            for event in sorted(net.contract_events.values(), key=lambda item: item.event_index)
            if event.event_name == "governor.voted"
        ]
        self.assertEqual(len(vote_events), 2)
        self.assertNotIn("alice-voter-key", json.dumps(vote_events))
        self.assertNotIn("bob-voter-key", json.dumps(vote_events))
        self.assertEqual(vote_block.header.execution_profile.contract_call_count, 2)

        with self.assertRaisesRegex(ValueError, "already voted"):
            net.submit_contract_call(
                governor.contract_id,
                entrypoint="vote",
                args={"proposal_id": proposal_id, "support": True, "weight": 1},
                signer_label="alice-voter-key",
                fuel_limit=80,
            )

        net.produce_block(include_pending=False)
        execute = net.submit_contract_call(
            governor.contract_id,
            entrypoint="execute",
            args={"proposal_id": proposal_id},
            signer_label="keeper-key",
            fuel_limit=80,
        )
        self.assertNotIn("keeper-key", json.dumps(execute.public_record()))
        execute_block = net.produce_block()
        proposal = net.contracts[governor.contract_id].storage["proposals"][proposal_id]
        self.assertEqual(proposal["status"], "executed")
        self.assertEqual(proposal["outcome"], "passed")
        self.assertEqual(proposal["executed_at_height"], 3)
        executed_event = sorted(
            net.contract_events.values(),
            key=lambda item: item.event_index,
        )[-1].public_record()
        self.assertEqual(executed_event["event_name"], "governor.executed")
        self.assertEqual(executed_event["public_data"]["outcome"], "passed")
        self.assertEqual(
            executed_event["public_data"]["executor_commitment"],
            devnet.domain_hash("CONTRACT-CALLER", "keeper-key"),
        )
        self.assertNotIn("keeper-key", json.dumps(executed_event))
        self.assertEqual(execute_block.header.contract_root, net.contract_root())

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.contract_root(), net.contract_root())
        self.assertEqual(
            round_trip.contracts[governor.contract_id].storage["proposals"][proposal_id],
            proposal,
        )

    def test_paymaster_sponsors_contract_call_fees(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        sponsor_note = net.mint(fee_asset.asset_id, "sponsor-view-key", 5)
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        paymaster = net.create_paymaster(
            contract.contract_id,
            fee_asset.asset_id,
            sponsor_label="sponsor-view-key",
        )

        deposit = net.submit_paymaster_deposit(
            paymaster.paymaster_id,
            sponsor_note.note_id,
            amount=3,
        )
        public_deposit = deposit.public_record()
        self.assertEqual(public_deposit["kind"], "paymaster_deposit")
        self.assertNotIn("spent_note_id", public_deposit)
        self.assertNotIn("sponsor-view-key", json.dumps(public_deposit))
        self.assertIn("proof_root", public_deposit["proof_bundle"])
        deposit_block = net.produce_block()
        self.assertEqual(net.paymasters[paymaster.paymaster_id].balance, 3)
        self.assertEqual(net.paymasters[paymaster.paymaster_id].deposit_count, 1)
        self.assertEqual(note_amounts(net.wallet_notes("sponsor-view-key"), fee_asset.asset_id), [2])
        self.assertEqual(deposit_block.header.execution_profile.privacy_proof_count, 1)

        call = net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 4},
            signer_label="bob-view-key",
            fuel_limit=20,
            paymaster_id=paymaster.paymaster_id,
            max_fee=1,
        )
        public_call = call.public_record()
        self.assertEqual(public_call["paymaster_id"], paymaster.paymaster_id)
        self.assertEqual(public_call["fee_asset_id"], fee_asset.asset_id)
        self.assertEqual(public_call["fee"], 1)
        self.assertFalse(public_call["fee_nullifier"])
        self.assertIsNone(public_call["proof_bundle"])
        call_block = net.produce_block()

        updated_paymaster = net.paymasters[paymaster.paymaster_id]
        self.assertEqual(updated_paymaster.balance, 2)
        self.assertEqual(updated_paymaster.spent_amount, 1)
        self.assertEqual(net.fees_collected[fee_asset.asset_id], 1)
        self.assertEqual(net.contracts[contract.contract_id].storage["count"], 4)
        self.assertEqual(net.contracts[contract.contract_id].storage["last_caller"], "bob-view-key")
        self.assertEqual(call_block.header.execution_profile.observed_fee_units, 1)
        self.assertEqual(call_block.header.execution_profile.privacy_proof_count, 0)

        net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 1},
            signer_label="carol-view-key",
            fuel_limit=20,
            paymaster_id=paymaster.paymaster_id,
            max_fee=1,
        )
        net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 1},
            signer_label="dave-view-key",
            fuel_limit=20,
            paymaster_id=paymaster.paymaster_id,
            max_fee=1,
        )
        with self.assertRaisesRegex(ValueError, "paymaster balance"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="erin-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )

    def test_paymaster_policy_limits_caller_spend(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        sponsor_note = net.mint(fee_asset.asset_id, "sponsor-view-key", 10)
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        paymaster = net.create_paymaster(
            contract.contract_id,
            fee_asset.asset_id,
            sponsor_label="sponsor-view-key",
            per_call_cap=1,
            per_caller_cap=2,
            allowed_caller_labels=("bob-view-key", "carol-view-key"),
        )
        public_paymaster = paymaster.public_record()
        bob_commitment = devnet.paymaster_caller_commitment("bob-view-key")
        carol_commitment = devnet.paymaster_caller_commitment("carol-view-key")
        self.assertEqual(public_paymaster["per_call_cap"], 1)
        self.assertEqual(public_paymaster["per_caller_cap"], 2)
        self.assertEqual(
            public_paymaster["allowed_caller_commitments"],
            sorted((bob_commitment, carol_commitment)),
        )
        self.assertNotIn("bob-view-key", json.dumps(public_paymaster))
        self.assertNotIn("carol-view-key", json.dumps(public_paymaster))

        net.submit_paymaster_deposit(
            paymaster.paymaster_id,
            sponsor_note.note_id,
            amount=5,
        )
        net.produce_block()

        with self.assertRaisesRegex(ValueError, "caller is not allowed"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="dave-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )

        for _ in range(2):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="bob-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )
        with self.assertRaisesRegex(ValueError, "per-caller cap"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="bob-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )
        net.produce_block()
        updated_paymaster = net.paymasters[paymaster.paymaster_id]
        self.assertEqual(updated_paymaster.balance, 3)
        self.assertEqual(updated_paymaster.spent_amount, 2)
        self.assertEqual(updated_paymaster.spent_by_caller[bob_commitment], 2)

        net.submit_contract_call(
            contract.contract_id,
            entrypoint="increment",
            args={"amount": 1},
            signer_label="carol-view-key",
            fuel_limit=20,
            paymaster_id=paymaster.paymaster_id,
            max_fee=1,
        )
        net.produce_block()
        updated_paymaster = net.paymasters[paymaster.paymaster_id]
        self.assertEqual(updated_paymaster.spent_by_caller[carol_commitment], 1)

    def test_paymaster_governance_pauses_replenishes_and_updates_policy(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        sponsor_note = net.mint(fee_asset.asset_id, "sponsor-view-key", 10)
        refill_note = net.mint(fee_asset.asset_id, "sponsor-view-key", 5)
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        paymaster = net.create_paymaster(
            contract.contract_id,
            fee_asset.asset_id,
            sponsor_label="sponsor-view-key",
            per_call_cap=1,
            per_caller_cap=2,
            allowed_caller_labels=("bob-view-key",),
            replenish_threshold=1,
            replenish_target=4,
        )
        net.submit_paymaster_deposit(paymaster.paymaster_id, sponsor_note.note_id, amount=3)
        net.produce_block()

        with self.assertRaisesRegex(ValueError, "sponsor mismatch"):
            net.pause_paymaster(
                paymaster.paymaster_id,
                sponsor_label="mallory-view-key",
                reason="bad signer",
            )

        pause = net.pause_paymaster(
            paymaster.paymaster_id,
            sponsor_label="sponsor-view-key",
            reason="contract incident",
        )
        public_pause = pause.public_record()
        self.assertEqual(public_pause["action"], "pause")
        self.assertEqual(public_pause["new_status"], "paused")
        self.assertNotIn("sponsor-view-key", json.dumps(public_pause))
        self.assertNotIn("contract incident", json.dumps(public_pause))
        self.assertEqual(net.paymasters[paymaster.paymaster_id].status, "paused")
        self.assertEqual(
            net.paymasters[paymaster.paymaster_id].last_governance_action_id,
            pause.action_id,
        )

        with self.assertRaisesRegex(ValueError, "paymaster is not active"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="bob-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )

        net.submit_paymaster_deposit(paymaster.paymaster_id, refill_note.note_id, amount=2)
        net.produce_block()
        self.assertEqual(net.paymasters[paymaster.paymaster_id].balance, 5)

        resume = net.resume_paymaster(
            paymaster.paymaster_id,
            sponsor_label="sponsor-view-key",
            reason="review complete",
        )
        self.assertEqual(resume.new_status, "active")
        self.assertEqual(net.paymasters[paymaster.paymaster_id].status, "active")

        carol_commitment = devnet.paymaster_caller_commitment("carol-view-key")
        policy = net.update_paymaster_policy(
            paymaster.paymaster_id,
            sponsor_label="sponsor-view-key",
            reason="rotate sponsored cohort",
            per_caller_cap=3,
            allowed_caller_labels=("carol-view-key",),
            replenish_threshold=2,
            replenish_target=6,
        )
        updated = net.paymasters[paymaster.paymaster_id]
        self.assertEqual(policy.action, "update_policy")
        self.assertEqual(updated.per_caller_cap, 3)
        self.assertEqual(updated.allowed_caller_commitments, (carol_commitment,))
        self.assertEqual(updated.replenish_threshold, 2)
        self.assertEqual(updated.replenish_target, 6)

        with self.assertRaisesRegex(ValueError, "caller is not allowed"):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="bob-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )

        for _ in range(3):
            net.submit_contract_call(
                contract.contract_id,
                entrypoint="increment",
                args={"amount": 1},
                signer_label="carol-view-key",
                fuel_limit=20,
                paymaster_id=paymaster.paymaster_id,
                max_fee=1,
            )
        net.produce_block()
        refill_plan = net.paymaster_refill_plan(paymaster.paymaster_id)
        self.assertTrue(refill_plan["needs_refill"])
        self.assertEqual(refill_plan["refill_amount"], 4)
        sponsor_refill_note_id = next(
            note["note_id"]
            for note in net.wallet_notes("sponsor-view-key")
            if note["amount"] >= 4
        )
        refill_bond_note = net.mint(fee_asset.asset_id, "refill-relayer", 2)
        refill_bond = net.bond_paymaster_refill_relayer(
            refill_bond_note.note_id,
            relayer_label="refill-relayer",
            amount=2,
        )
        candidates = net.paymaster_refill_relayer_candidates(paymaster.paymaster_id)
        self.assertEqual(candidates["candidate_count"], 1)
        self.assertEqual(
            candidates["candidates"][0]["relayer_commitment"],
            devnet.paymaster_relayer_commitment("refill-relayer"),
        )
        self.assertEqual(candidates["candidates"][0]["selectable_bond_amount"], 2)
        authorization = net.route_paymaster_refill_authorization(
            paymaster.paymaster_id,
            spent_note_id=sponsor_refill_note_id,
            sponsor_label="sponsor-view-key",
            max_refill_amount=4,
            expires_in_blocks=3,
        )
        public_authorization = authorization.public_record()
        self.assertEqual(public_authorization["status"], "open")
        self.assertEqual(public_authorization["max_refill_amount"], 4)
        self.assertNotIn("sponsor-view-key", json.dumps(public_authorization))
        self.assertNotIn("refill-relayer", json.dumps(public_authorization))
        with self.assertRaisesRegex(ValueError, "relayer mismatch"):
            net.submit_paymaster_refill(
                paymaster.paymaster_id,
                spent_note_id=sponsor_refill_note_id,
                authorization_id=authorization.authorization_id,
                relayer_label="wrong-relayer",
            )
        refill = net.submit_paymaster_refill(
            paymaster.paymaster_id,
            spent_note_id=sponsor_refill_note_id,
            authorization_id=authorization.authorization_id,
            relayer_label="refill-relayer",
        )
        self.assertEqual(refill.amount, 4)
        self.assertEqual(refill.refill_authorization_id, authorization.authorization_id)
        self.assertEqual(
            refill.refill_relayer_commitment,
            devnet.paymaster_relayer_commitment("refill-relayer"),
        )
        used_authorization = net.paymaster_refill_authorizations[
            authorization.authorization_id
        ]
        self.assertEqual(used_authorization.status, "used")
        self.assertTrue(used_authorization.deposit_tx_hash)
        self.assertEqual(len(net.paymaster_relayer_reward_receipts), 1)
        reward = next(iter(net.paymaster_relayer_reward_receipts.values()))
        public_reward = reward.public_record()
        self.assertEqual(public_reward["authorization_id"], authorization.authorization_id)
        self.assertEqual(public_reward["reward_units"], devnet.PAYMASTER_RELAYER_REFILL_REWARD_UNITS)
        self.assertEqual(public_reward["budget_units_before"], 0)
        self.assertEqual(public_reward["budget_units_after"], 1)
        self.assertEqual(public_reward["reward_budget"], 0)
        self.assertEqual(public_reward["budget_proof_root"], reward.expected_budget_proof_root())
        self.assertFalse(public_reward["claim_proof_root"])
        self.assertNotIn("refill-relayer", json.dumps(public_reward))
        with self.assertRaisesRegex(ValueError, "authorization is not open"):
            net.submit_paymaster_refill(
                paymaster.paymaster_id,
                spent_note_id=sponsor_refill_note_id,
                authorization_id=authorization.authorization_id,
                relayer_label="refill-relayer",
            )
        net.produce_block()
        self.assertEqual(net.paymasters[paymaster.paymaster_id].balance, 6)
        claimed_reward = net.claim_paymaster_relayer_reward(
            reward.reward_id,
            relayer_label="refill-relayer",
        )
        public_claimed_reward = claimed_reward.public_record()
        self.assertEqual(public_claimed_reward["status"], "claimed")
        self.assertEqual(public_claimed_reward["claimed_amount"], 1)
        self.assertTrue(public_claimed_reward["claim_note_commitment"])
        self.assertEqual(
            public_claimed_reward["claim_proof_root"],
            claimed_reward.expected_claim_proof_root(),
        )
        self.assertNotIn("refill-relayer", json.dumps(public_claimed_reward))
        self.assertEqual(
            note_amounts(net.wallet_notes("refill-relayer"), fee_asset.asset_id),
            [1],
        )
        with self.assertRaisesRegex(ValueError, "not claimable"):
            net.claim_paymaster_relayer_reward(
                reward.reward_id,
                relayer_label="refill-relayer",
            )
        self.assertEqual(net.paymasters[paymaster.paymaster_id].balance, 5)
        expired_note = net.mint(fee_asset.asset_id, "sponsor-view-key", 1)
        expired_authorization = net.authorize_paymaster_refill(
            paymaster.paymaster_id,
            spent_note_id=expired_note.note_id,
            sponsor_label="sponsor-view-key",
            relayer_label="slow-relayer",
            max_refill_amount=1,
            expires_in_blocks=1,
        )
        with self.assertRaisesRegex(ValueError, "not expired"):
            net.report_paymaster_refill_failure(
                expired_authorization.authorization_id,
                reporter_label="sponsor-view-key",
                evidence="too early",
            )
        net.produce_block()
        net.produce_block()
        failure = net.report_paymaster_refill_failure(
            expired_authorization.authorization_id,
            reporter_label="sponsor-view-key",
            evidence="relayer missed refill window",
        )
        public_failure = failure.public_record()
        self.assertEqual(public_failure["reason_code"], "expired")
        self.assertEqual(public_failure["status"], "open")
        self.assertEqual(
            public_failure["challenge_deadline_height"],
            failure.reported_at_height
            + devnet.PAYMASTER_REFILL_FAILURE_CHALLENGE_BLOCKS,
        )
        self.assertNotIn("sponsor-view-key", json.dumps(public_failure))
        self.assertNotIn("relayer missed refill window", json.dumps(public_failure))
        self.assertEqual(
            net.paymaster_refill_authorizations[
                expired_authorization.authorization_id
            ].status,
            "failed",
        )
        challenge = net.challenge_paymaster_refill_failure(
            failure.receipt_id,
            relayer_label="slow-relayer",
            evidence="relayer submitted private proof",
        )
        public_challenge = challenge.public_record()
        self.assertEqual(public_challenge["receipt_id"], failure.receipt_id)
        self.assertNotIn("slow-relayer", json.dumps(public_challenge))
        self.assertNotIn("relayer submitted private proof", json.dumps(public_challenge))
        challenged_failure = net.paymaster_refill_failures[failure.receipt_id]
        self.assertEqual(challenged_failure.status, "challenged")
        self.assertEqual(challenged_failure.challenge_id, challenge.challenge_id)
        with self.assertRaisesRegex(ValueError, "not open"):
            net.publish_paymaster_relayer_slashing_hook(
                failure.receipt_id,
                reporter_label="sponsor-view-key",
            )

        slash_note = net.mint(fee_asset.asset_id, "sponsor-view-key", 1)
        relayer_bond_note = net.mint(fee_asset.asset_id, "slash-relayer", 5)
        bond = net.bond_paymaster_refill_relayer(
            relayer_bond_note.note_id,
            relayer_label="slash-relayer",
            amount=3,
        )
        public_bond = bond.public_record()
        self.assertEqual(public_bond["amount"], 3)
        self.assertEqual(public_bond["active_amount"], 3)
        self.assertNotIn("slash-relayer", json.dumps(public_bond))
        self.assertEqual(note_amounts(net.wallet_notes("slash-relayer"), fee_asset.asset_id), [2])
        slash_authorization = net.authorize_paymaster_refill(
            paymaster.paymaster_id,
            spent_note_id=slash_note.note_id,
            sponsor_label="sponsor-view-key",
            relayer_label="slash-relayer",
            max_refill_amount=1,
            expires_in_blocks=1,
        )
        net.produce_block()
        net.produce_block()
        slash_failure = net.report_paymaster_refill_failure(
            slash_authorization.authorization_id,
            reporter_label="sponsor-view-key",
            evidence="relayer stayed offline",
        )
        with self.assertRaisesRegex(ValueError, "challenge window is still open"):
            net.publish_paymaster_relayer_slashing_hook(
                slash_failure.receipt_id,
                reporter_label="sponsor-view-key",
            )
        for _ in range(devnet.PAYMASTER_REFILL_FAILURE_CHALLENGE_BLOCKS + 1):
            net.produce_block()
        hook = net.publish_paymaster_relayer_slashing_hook(
            slash_failure.receipt_id,
            reporter_label="sponsor-view-key",
            penalty_units=2,
        )
        public_hook = hook.public_record()
        self.assertEqual(public_hook["receipt_id"], slash_failure.receipt_id)
        self.assertEqual(public_hook["penalty_units"], 2)
        self.assertNotIn("sponsor-view-key", json.dumps(public_hook))
        slashable_failure = net.paymaster_refill_failures[slash_failure.receipt_id]
        self.assertEqual(slashable_failure.status, "slashable")
        self.assertEqual(slashable_failure.slashing_hook_id, hook.hook_id)
        settlement = net.settle_paymaster_relayer_slashing_hook(
            hook.hook_id,
            reporter_label="sponsor-view-key",
        )
        public_settlement = settlement.public_record()
        self.assertEqual(public_settlement["hook_id"], hook.hook_id)
        self.assertEqual(public_settlement["status"], "settled")
        self.assertEqual(public_settlement["slashed_amount"], 2)
        self.assertEqual(public_settlement["remaining_penalty_units"], 0)
        self.assertNotIn("sponsor-view-key", json.dumps(public_settlement))
        updated_bond = net.paymaster_relayer_bonds[bond.bond_id]
        self.assertEqual(updated_bond.active_amount, 1)
        self.assertEqual(updated_bond.slashed_amount, 2)
        self.assertEqual(updated_bond.slash_count, 1)
        with self.assertRaisesRegex(ValueError, "already settled"):
            net.settle_paymaster_relayer_slashing_hook(
                hook.hook_id,
                reporter_label="sponsor-view-key",
            )
        candidates = net.paymaster_refill_relayer_candidates(paymaster.paymaster_id)
        self.assertEqual(candidates["candidate_count"], 2)
        slash_candidate = next(
            row
            for row in candidates["candidates"]
            if row["relayer_commitment"]
            == devnet.paymaster_relayer_commitment("slash-relayer")
        )
        self.assertEqual(slash_candidate["selectable_bond_amount"], 1)
        self.assertEqual(
            candidates["candidates"][0]["relayer_commitment"],
            devnet.paymaster_relayer_commitment("refill-relayer"),
        )
        self.assertEqual(candidates["candidates"][0]["reward_units"], 1)
        self.assertEqual(
            candidates["candidates"][0]["performance_score_bps"],
            10_250,
        )
        unbond = net.request_paymaster_relayer_unbond(
            bond.bond_id,
            relayer_label="slash-relayer",
            amount=1,
        )
        public_unbond = unbond.public_record()
        self.assertEqual(public_unbond["status"], "pending")
        self.assertEqual(
            public_unbond["available_at_height"],
            unbond.requested_at_height + devnet.PAYMASTER_RELAYER_UNBOND_DELAY_BLOCKS,
        )
        self.assertNotIn("slash-relayer", json.dumps(public_unbond))
        with self.assertRaisesRegex(ValueError, "not available"):
            net.claim_paymaster_relayer_unbond(
                unbond.request_id,
                relayer_label="slash-relayer",
            )
        self.assertEqual(
            net.paymaster_refill_relayer_candidates(paymaster.paymaster_id)[
                "candidate_count"
            ],
            1,
        )
        for _ in range(devnet.PAYMASTER_RELAYER_UNBOND_DELAY_BLOCKS):
            net.produce_block()
        claimed_unbond = net.claim_paymaster_relayer_unbond(
            unbond.request_id,
            relayer_label="slash-relayer",
        )
        self.assertEqual(claimed_unbond.status, "claimed")
        self.assertEqual(claimed_unbond.claimed_amount, 1)
        self.assertTrue(claimed_unbond.claim_note_commitment)
        self.assertEqual(
            note_amounts(net.wallet_notes("slash-relayer"), fee_asset.asset_id),
            [1, 2],
        )
        exited_bond = net.paymaster_relayer_bonds[bond.bond_id]
        self.assertEqual(exited_bond.active_amount, 0)
        self.assertEqual(exited_bond.slashed_amount, 2)
        self.assertEqual(exited_bond.withdrawn_amount, 1)
        self.assertEqual(exited_bond.status, "depleted")
        reputation = net.paymaster_refill_reputation()
        fast = next(
            row
            for row in reputation["relayers"]
            if row["relayer_commitment"] == devnet.paymaster_relayer_commitment("refill-relayer")
        )
        slow = next(
            row
            for row in reputation["relayers"]
            if row["relayer_commitment"] == devnet.paymaster_relayer_commitment("slow-relayer")
        )
        slash = next(
            row
            for row in reputation["relayers"]
            if row["relayer_commitment"] == devnet.paymaster_relayer_commitment("slash-relayer")
        )
        self.assertEqual(fast["used_count"], 1)
        self.assertEqual(fast["success_bps"], 10_000)
        self.assertEqual(fast["reward_units"], 1)
        self.assertEqual(fast["claimed_reward_units"], 1)
        self.assertEqual(fast["claimable_reward_units"], 0)
        self.assertEqual(fast["bonded_amount"], 2)
        self.assertEqual(fast["selectable_bond_amount"], 2)
        self.assertEqual(slow["failed_count"], 1)
        self.assertEqual(slow["challenged_count"], 1)
        self.assertEqual(slow["success_bps"], 0)
        self.assertEqual(slash["failed_count"], 1)
        self.assertEqual(slash["slashable_count"], 1)
        self.assertEqual(slash["penalty_units"], 2)
        self.assertEqual(slash["bonded_amount"], 3)
        self.assertEqual(slash["active_bond_amount"], 0)
        self.assertEqual(slash["pending_unbond_amount"], 0)
        self.assertEqual(slash["selectable_bond_amount"], 0)
        self.assertEqual(slash["settled_slashed_amount"], 2)
        self.assertEqual(slash["withdrawn_bond_amount"], 1)
        self.assertEqual(slash["unsettled_penalty_units"], 0)

        close = net.close_paymaster(
            paymaster.paymaster_id,
            sponsor_label="sponsor-view-key",
            reason="retire sponsor budget",
        )
        self.assertEqual(close.action, "close")
        self.assertEqual(close.new_status, "closed")
        self.assertEqual(close.refund_amount, 5)
        self.assertTrue(close.refund_note_commitment)
        self.assertNotIn("retire sponsor budget", json.dumps(close.public_record()))
        self.assertEqual(net.paymasters[paymaster.paymaster_id].balance, 0)
        self.assertEqual(net.paymasters[paymaster.paymaster_id].status, "closed")
        self.assertIn(5, note_amounts(net.wallet_notes("sponsor-view-key"), fee_asset.asset_id))
        with self.assertRaisesRegex(ValueError, "paymaster is closed"):
            net.update_paymaster_policy(
                paymaster.paymaster_id,
                sponsor_label="sponsor-view-key",
                per_call_cap=2,
            )

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.paymaster_root(), net.paymaster_root())
        self.assertEqual(
            round_trip.paymaster_governance_root(),
            net.paymaster_governance_root(),
        )
        self.assertEqual(len(round_trip.paymaster_governance_actions), 4)
        self.assertEqual(len(round_trip.paymaster_refill_authorizations), 3)
        self.assertEqual(len(round_trip.paymaster_refill_failures), 2)
        self.assertEqual(len(round_trip.paymaster_refill_challenges), 1)
        self.assertEqual(len(round_trip.paymaster_relayer_slashing_hooks), 1)
        self.assertEqual(len(round_trip.paymaster_relayer_bonds), 2)
        self.assertEqual(len(round_trip.paymaster_relayer_slash_settlements), 1)
        self.assertEqual(len(round_trip.paymaster_relayer_unbond_requests), 1)
        self.assertEqual(len(round_trip.paymaster_relayer_reward_receipts), 1)
        self.assertEqual(
            round_trip.paymaster_refill_authorization_root(),
            net.paymaster_refill_authorization_root(),
        )
        self.assertEqual(
            round_trip.paymaster_refill_failure_root(),
            net.paymaster_refill_failure_root(),
        )
        self.assertEqual(
            round_trip.paymaster_refill_challenge_root(),
            net.paymaster_refill_challenge_root(),
        )
        self.assertEqual(
            round_trip.paymaster_relayer_slashing_root(),
            net.paymaster_relayer_slashing_root(),
        )
        self.assertEqual(
            round_trip.paymaster_relayer_bond_root(),
            net.paymaster_relayer_bond_root(),
        )
        self.assertEqual(
            round_trip.paymaster_relayer_slash_settlement_root(),
            net.paymaster_relayer_slash_settlement_root(),
        )
        self.assertEqual(
            round_trip.paymaster_relayer_unbond_root(),
            net.paymaster_relayer_unbond_root(),
        )
        self.assertEqual(
            round_trip.paymaster_relayer_reward_root(),
            net.paymaster_relayer_reward_root(),
        )
        tampered = net.state_record()
        tampered["paymaster_relayer_reward_receipts"][0]["claim_note_commitment"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "invalid paymaster relayer reward claim proof"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_paymaster_relayer_reward_policy_caps_budget(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        refill_one = net.mint(fee_asset.asset_id, "sponsor-view-key", 2)
        refill_two = net.mint(fee_asset.asset_id, "sponsor-view-key", 2)
        refill_three = net.mint(fee_asset.asset_id, "sponsor-view-key", 2)
        relayer_bond_note = net.mint(fee_asset.asset_id, "reward-relayer", 3)
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        paymaster = net.create_paymaster(
            contract.contract_id,
            fee_asset.asset_id,
            sponsor_label="sponsor-view-key",
            replenish_threshold=0,
            replenish_target=2,
            relayer_reward_units=2,
            relayer_reward_budget=2,
        )
        public_paymaster = paymaster.public_record()
        self.assertEqual(public_paymaster["relayer_reward_units"], 2)
        self.assertEqual(public_paymaster["relayer_reward_budget"], 2)
        self.assertNotIn("sponsor-view-key", json.dumps(public_paymaster))

        net.bond_paymaster_refill_relayer(
            relayer_bond_note.note_id,
            relayer_label="reward-relayer",
            amount=2,
        )
        plan = net.paymaster_refill_plan(paymaster.paymaster_id)
        self.assertTrue(plan["needs_refill"])
        self.assertEqual(plan["next_relayer_reward_units"], 2)
        self.assertEqual(plan["relayer_reward_budget_remaining"], 2)
        candidates = net.paymaster_refill_relayer_candidates(paymaster.paymaster_id)
        self.assertEqual(candidates["next_relayer_reward_units"], 2)
        self.assertEqual(candidates["relayer_reward_budget_remaining"], 2)

        first_authorization = net.route_paymaster_refill_authorization(
            paymaster.paymaster_id,
            spent_note_id=refill_one.note_id,
            sponsor_label="sponsor-view-key",
            max_refill_amount=2,
        )
        net.submit_paymaster_refill(
            paymaster.paymaster_id,
            spent_note_id=refill_one.note_id,
            authorization_id=first_authorization.authorization_id,
            relayer_label="reward-relayer",
        )
        first_reward = next(iter(net.paymaster_relayer_reward_receipts.values()))
        self.assertEqual(first_reward.reward_units, 2)
        self.assertEqual(first_reward.budget_units_before, 0)
        self.assertEqual(first_reward.budget_units_after, 2)
        self.assertEqual(first_reward.reward_budget, 2)
        self.assertEqual(first_reward.budget_proof_root, first_reward.expected_budget_proof_root())
        net.produce_block()
        claimed_first = net.claim_paymaster_relayer_reward(
            first_reward.reward_id,
            relayer_label="reward-relayer",
        )
        self.assertEqual(claimed_first.claimed_amount, 2)
        self.assertEqual(claimed_first.claim_proof_root, claimed_first.expected_claim_proof_root())
        self.assertEqual(
            note_amounts(net.wallet_notes("reward-relayer"), fee_asset.asset_id),
            [1, 2],
        )
        exhausted_plan = net.paymaster_refill_plan(paymaster.paymaster_id)
        self.assertEqual(exhausted_plan["relayer_reward_budget_remaining"], 0)
        self.assertEqual(exhausted_plan["next_relayer_reward_units"], 0)

        exhausted_authorization = net.authorize_paymaster_refill(
            paymaster.paymaster_id,
            spent_note_id=refill_two.note_id,
            sponsor_label="sponsor-view-key",
            relayer_label="reward-relayer",
            max_refill_amount=2,
        )
        with self.assertRaisesRegex(ValueError, "reward budget exceeded"):
            net.submit_paymaster_refill(
                paymaster.paymaster_id,
                spent_note_id=refill_two.note_id,
                authorization_id=exhausted_authorization.authorization_id,
                relayer_label="reward-relayer",
            )
        self.assertEqual(len(net.pending), 0)
        self.assertEqual(len(net.paymaster_relayer_reward_receipts), 1)

        policy = net.update_paymaster_policy(
            paymaster.paymaster_id,
            sponsor_label="sponsor-view-key",
            reason="top up relayer rewards",
            relayer_reward_units=1,
            relayer_reward_budget=3,
        )
        self.assertEqual(policy.relayer_reward_units, 1)
        self.assertEqual(policy.relayer_reward_budget, 3)
        self.assertNotIn("top up relayer rewards", json.dumps(policy.public_record()))
        updated_plan = net.paymaster_refill_plan(paymaster.paymaster_id)
        self.assertEqual(updated_plan["relayer_reward_budget_remaining"], 1)
        self.assertEqual(updated_plan["next_relayer_reward_units"], 1)

        second_authorization = net.route_paymaster_refill_authorization(
            paymaster.paymaster_id,
            spent_note_id=refill_three.note_id,
            sponsor_label="sponsor-view-key",
            max_refill_amount=2,
        )
        net.submit_paymaster_refill(
            paymaster.paymaster_id,
            spent_note_id=refill_three.note_id,
            authorization_id=second_authorization.authorization_id,
            relayer_label="reward-relayer",
        )
        second_reward = next(
            receipt
            for receipt in net.paymaster_relayer_reward_receipts.values()
            if receipt.authorization_id == second_authorization.authorization_id
        )
        self.assertEqual(second_reward.reward_units, 1)
        self.assertEqual(second_reward.budget_units_before, 2)
        self.assertEqual(second_reward.budget_units_after, 3)
        self.assertEqual(second_reward.reward_budget, 3)
        net.produce_block()
        claimed_second = net.claim_paymaster_relayer_reward(
            second_reward.reward_id,
            relayer_label="reward-relayer",
        )
        self.assertEqual(claimed_second.claim_proof_root, claimed_second.expected_claim_proof_root())
        self.assertEqual(
            note_amounts(net.wallet_notes("reward-relayer"), fee_asset.asset_id),
            [1, 1, 2],
        )
        final_plan = net.paymaster_refill_plan(paymaster.paymaster_id)
        self.assertEqual(final_plan["relayer_reward_earned_units"], 3)
        self.assertEqual(final_plan["relayer_reward_budget_remaining"], 0)
        self.assertEqual(final_plan["next_relayer_reward_units"], 0)
        tampered_proof = net.state_record()
        tampered_proof["paymaster_relayer_reward_receipts"][0]["budget_proof_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "invalid paymaster relayer reward budget proof"):
            devnet.NebulaL2Devnet.from_state_record(tampered_proof)
        tampered_sequence = net.state_record()
        overlapping = devnet.PaymasterRelayerRewardReceipt.from_record(
            tampered_sequence["paymaster_relayer_reward_receipts"][1],
        )
        overlapping = replace(
            overlapping,
            reward_id="",
            budget_units_before=0,
            budget_units_after=1,
            auth_public_key="",
            auth_transcript_hash="",
            auth_signature="",
        )
        overlapping = replace(overlapping, reward_id=overlapping.expected_reward_id())
        overlapping = replace(
            overlapping,
            budget_proof_root=overlapping.expected_budget_proof_root(),
            claim_proof_root=overlapping.expected_claim_proof_root(),
        )
        overlapping_auth = devnet.sign_authorization(
            "reward-relayer",
            "paymaster_relayer_reward_receipt",
            overlapping.unsigned_record(),
        )
        overlapping = replace(
            overlapping,
            auth_scheme=overlapping_auth["auth_scheme"],
            auth_public_key=overlapping_auth["auth_public_key"],
            auth_transcript_hash=overlapping_auth["auth_transcript_hash"],
            auth_signature=overlapping_auth["auth_signature"],
        )
        tampered_sequence["paymaster_relayer_reward_receipts"][1] = overlapping.state_record()
        with self.assertRaisesRegex(ValueError, "budget sequence mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered_sequence)

    def test_paymaster_relayer_reward_batch_claim_uses_bundle_proof(self) -> None:
        net = devnet.NebulaL2Devnet()
        fee_asset = net.create_asset("DFEE", "devnet-fee-issuer")
        sponsor_note_a = net.mint(fee_asset.asset_id, "sponsor-view-key", 2)
        sponsor_note_b = net.mint(fee_asset.asset_id, "sponsor-view-key", 2)
        relayer_bond_note = net.mint(fee_asset.asset_id, "batch-relayer", 2)
        contract = net.deploy_contract("counter", owner_label="alice-view-key", fuel_limit=100)
        paymaster_a = net.create_paymaster(
            contract.contract_id,
            fee_asset.asset_id,
            sponsor_label="sponsor-view-key",
            replenish_threshold=0,
            replenish_target=2,
        )
        paymaster_b = net.create_paymaster(
            contract.contract_id,
            fee_asset.asset_id,
            sponsor_label="sponsor-view-key",
            replenish_threshold=0,
            replenish_target=2,
        )
        net.bond_paymaster_refill_relayer(
            relayer_bond_note.note_id,
            relayer_label="batch-relayer",
            amount=2,
        )

        auth_a = net.route_paymaster_refill_authorization(
            paymaster_a.paymaster_id,
            spent_note_id=sponsor_note_a.note_id,
            sponsor_label="sponsor-view-key",
            max_refill_amount=2,
        )
        auth_b = net.route_paymaster_refill_authorization(
            paymaster_b.paymaster_id,
            spent_note_id=sponsor_note_b.note_id,
            sponsor_label="sponsor-view-key",
            max_refill_amount=2,
        )
        net.submit_paymaster_refill(
            paymaster_a.paymaster_id,
            spent_note_id=sponsor_note_a.note_id,
            authorization_id=auth_a.authorization_id,
            relayer_label="batch-relayer",
        )
        net.submit_paymaster_refill(
            paymaster_b.paymaster_id,
            spent_note_id=sponsor_note_b.note_id,
            authorization_id=auth_b.authorization_id,
            relayer_label="batch-relayer",
        )
        reward_ids = tuple(
            receipt.reward_id
            for receipt in sorted(
                net.paymaster_relayer_reward_receipts.values(),
                key=lambda receipt: receipt.authorization_id,
            )
        )
        self.assertEqual(len(reward_ids), 2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            net.claim_paymaster_relayer_reward_batch(
                (reward_ids[0], reward_ids[0]),
                relayer_label="batch-relayer",
            )
        net.produce_block()

        expired_quote = net.paymaster_relayer_reward_claim_quote(
            reward_ids,
            relayer_label="batch-relayer",
            expires_in_blocks=1,
        )
        with self.assertRaisesRegex(ValueError, "still valid"):
            net.report_paymaster_relayer_reward_claim_quote_invalidation(
                expired_quote,
                reporter_label="quote-watchtower",
            )
        net.produce_block()
        net.produce_block()
        expired_monitor = net.paymaster_relayer_reward_claim_settlement_monitor(
            relayer_commitment=devnet.paymaster_relayer_commitment("batch-relayer"),
            quote_records=(expired_quote,),
        )
        self.assertEqual(expired_monitor["claimable_reward_count"], 2)
        self.assertEqual(expired_monitor["quote_observations"][0]["reason_code"], "expired")
        expired_report = net.report_paymaster_relayer_reward_claim_quote_invalidation(
            expired_quote,
            reporter_label="quote-watchtower",
        )
        expired_public = expired_report.public_record()
        self.assertEqual(expired_public["reason_code"], "expired")
        self.assertEqual(expired_public["quote_root"], expired_quote["quote_root"])
        self.assertNotIn("batch-relayer", json.dumps(expired_public))
        self.assertNotIn("quote-watchtower", json.dumps(expired_public))
        with self.assertRaisesRegex(ValueError, "already reported"):
            net.report_paymaster_relayer_reward_claim_quote_invalidation(
                expired_quote,
                reporter_label="quote-watchtower",
            )

        deadline_quote = net.paymaster_relayer_reward_claim_quote(
            reward_ids,
            relayer_label="batch-relayer",
            expires_in_blocks=4,
            inclusion_deadline_blocks=1,
        )
        self.assertEqual(deadline_quote["inclusion_deadline_height"], len(net.blocks) + 1)
        net.produce_block()
        net.produce_block()
        deadline_monitor = net.paymaster_relayer_reward_claim_settlement_monitor(
            relayer_commitment=devnet.paymaster_relayer_commitment("batch-relayer"),
            quote_records=(deadline_quote,),
        )
        self.assertEqual(
            deadline_monitor["quote_observations"][0]["reason_code"],
            "inclusion_deadline_missed",
        )
        self.assertTrue(deadline_monitor["quote_observations"][0]["requote_allowed"])
        deadline_report = net.report_paymaster_relayer_reward_claim_quote_invalidation(
            deadline_quote,
            reporter_label="deadline-watchtower",
        )
        deadline_public = deadline_report.public_record()
        self.assertEqual(deadline_public["reason_code"], "inclusion_deadline_missed")
        self.assertEqual(
            deadline_public["inclusion_deadline_height"],
            deadline_quote["inclusion_deadline_height"],
        )
        self.assertNotIn("deadline-watchtower", json.dumps(deadline_public))

        quote = net.paymaster_relayer_reward_claim_quote(
            reward_ids,
            relayer_label="batch-relayer",
            expires_in_blocks=2,
            inclusion_deadline_blocks=2,
        )
        self.assertEqual(quote["claim_count"], 2)
        self.assertEqual(
            quote["max_bundle_size"],
            devnet.PAYMASTER_RELAYER_REWARD_CLAIM_BUNDLE_MAX_ITEMS,
        )
        self.assertEqual(quote["expires_at_height"], len(net.blocks) + 2)
        self.assertEqual(quote["inclusion_deadline_height"], len(net.blocks) + 2)
        self.assertEqual(quote["requote_penalty_count"], 2)
        self.assertGreater(quote["requote_backoff_score"], 0)
        self.assertEqual(quote["requote_backoff_blocks"], 2)
        self.assertEqual(quote["requote_after_height"], len(net.blocks) + 2)
        self.assertFalse(quote["requote_allowed"])
        self.assertEqual(quote["estimated_fee_units"], 1)
        self.assertGreater(
            quote["estimated_proof_bytes"],
            devnet.DEVNET_PRIVACY_PROOF_BYTES,
        )
        self.assertEqual(len(net.paymaster_relayer_reward_claim_bundles), 0)
        with self.assertRaisesRegex(ValueError, "expiry must be positive"):
            net.paymaster_relayer_reward_claim_quote(
                reward_ids,
                relayer_label="batch-relayer",
                expires_in_blocks=0,
            )
        with self.assertRaisesRegex(ValueError, "inclusion deadline exceeds expiry"):
            net.paymaster_relayer_reward_claim_quote(
                reward_ids,
                relayer_label="batch-relayer",
                expires_in_blocks=1,
                inclusion_deadline_blocks=2,
            )
        with self.assertRaisesRegex(ValueError, "exceeds max size"):
            net.paymaster_relayer_reward_claim_quote(
                tuple(
                    f"missing-{index}"
                    for index in range(
                        devnet.PAYMASTER_RELAYER_REWARD_CLAIM_BUNDLE_MAX_ITEMS + 1
                    )
                ),
                relayer_label="batch-relayer",
            )

        bundle = net.claim_paymaster_relayer_reward_batch(
            reward_ids,
            relayer_label="batch-relayer",
            expires_in_blocks=2,
            inclusion_deadline_blocks=2,
        )
        public_bundle = bundle.public_record()
        self.assertEqual(public_bundle["claim_count"], 2)
        self.assertEqual(public_bundle["total_claimed_amount"], 2)
        self.assertEqual(public_bundle["quote_root"], quote["quote_root"])
        self.assertEqual(public_bundle["expires_at_height"], quote["expires_at_height"])
        self.assertEqual(
            public_bundle["inclusion_deadline_height"],
            quote["inclusion_deadline_height"],
        )
        self.assertEqual(public_bundle["requote_after_height"], quote["requote_after_height"])
        self.assertEqual(public_bundle["requote_backoff_blocks"], quote["requote_backoff_blocks"])
        self.assertEqual(public_bundle["requote_backoff_score"], quote["requote_backoff_score"])
        self.assertEqual(public_bundle["estimated_fee_units"], quote["estimated_fee_units"])
        self.assertEqual(public_bundle["estimated_proof_bytes"], quote["estimated_proof_bytes"])
        self.assertEqual(public_bundle["estimated_da_bytes"], quote["estimated_da_bytes"])
        self.assertEqual(public_bundle["bundle_proof_root"], bundle.expected_bundle_proof_root())
        self.assertNotIn("batch-relayer", json.dumps(public_bundle))
        settlement_monitor = net.paymaster_relayer_reward_claim_settlement_monitor(
            relayer_commitment=devnet.paymaster_relayer_commitment("batch-relayer"),
            quote_records=(quote,),
        )
        self.assertEqual(settlement_monitor["claimable_reward_count"], 0)
        self.assertEqual(settlement_monitor["claimed_reward_count"], 2)
        self.assertEqual(settlement_monitor["settled_bundle_count"], 1)
        self.assertEqual(settlement_monitor["quote_invalidation_report_count"], 2)
        self.assertEqual(settlement_monitor["quote_observations"][0]["reason_code"], "settled")
        settled_report = net.report_paymaster_relayer_reward_claim_quote_invalidation(
            quote,
            reporter_label="settlement-watchtower",
        )
        settled_public = settled_report.public_record()
        self.assertEqual(settled_public["reason_code"], "settled")
        self.assertEqual(settled_public["settled_bundle_id"], bundle.bundle_id)
        self.assertNotIn("settlement-watchtower", json.dumps(settled_public))
        self.assertEqual(
            note_amounts(net.wallet_notes("batch-relayer"), fee_asset.asset_id),
            [1, 1],
        )
        self.assertEqual(net.paymasters[paymaster_a.paymaster_id].balance, 1)
        self.assertEqual(net.paymasters[paymaster_b.paymaster_id].balance, 1)
        for reward_id in reward_ids:
            receipt = net.paymaster_relayer_reward_receipts[reward_id]
            self.assertEqual(receipt.status, "claimed")
            self.assertEqual(receipt.claim_bundle_id, bundle.bundle_id)
            self.assertEqual(receipt.claim_proof_root, bundle.bundle_proof_root)
        snapshot = net.public_snapshot()
        self.assertEqual(snapshot["paymaster_relayer_reward_claim_bundle_count"], 1)
        self.assertEqual(
            snapshot["paymaster_relayer_reward_claim_bundle_root"],
            net.paymaster_relayer_reward_claim_bundle_root(),
        )
        self.assertEqual(snapshot["paymaster_relayer_reward_quote_invalidation_count"], 3)
        self.assertEqual(
            snapshot["paymaster_relayer_reward_quote_invalidation_root"],
            net.paymaster_relayer_reward_quote_invalidation_root(),
        )
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.paymaster_relayer_reward_claim_bundle_root(),
            net.paymaster_relayer_reward_claim_bundle_root(),
        )
        self.assertEqual(
            round_trip.paymaster_relayer_reward_quote_invalidation_root(),
            net.paymaster_relayer_reward_quote_invalidation_root(),
        )
        with self.assertRaisesRegex(ValueError, "not claimable"):
            net.claim_paymaster_relayer_reward_batch(
                reward_ids,
                relayer_label="batch-relayer",
            )
        tampered = net.state_record()
        tampered["paymaster_relayer_reward_claim_bundles"][0]["bundle_proof_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "invalid paymaster relayer reward claim bundle proof"):
            devnet.NebulaL2Devnet.from_state_record(tampered)
        tampered_report = net.state_record()
        tampered_report["paymaster_relayer_reward_quote_invalidations"][0][
            "observed_reward_statuses"
        ][0]["status"] = "claimed"
        with self.assertRaisesRegex(ValueError, "status root mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered_report)

    def test_contract_native_asset_deposit_and_withdrawal_flow(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("DVAULT", "vault-issuer")
        alice_note = net.mint(asset.asset_id, "alice-view-key", 50)
        contract = net.deploy_contract("counter", owner_label="owner-view-key", fuel_limit=100)

        deposit = net.submit_contract_deposit(
            contract.contract_id,
            spent_note_id=alice_note.note_id,
            amount=30,
            network_fee=2,
        )
        deposit_public = deposit.public_record()
        self.assertEqual(deposit_public["kind"], "contract_deposit")
        self.assertNotIn("spent_note_id", deposit_public)
        self.assertNotIn("alice-view-key", json.dumps(deposit_public))
        self.assertIn("proof_root", deposit_public["proof_bundle"])

        deposit_block = net.produce_block()
        updated = net.contracts[contract.contract_id]
        self.assertEqual(updated.asset_balances, {asset.asset_id: 30})
        self.assertEqual(net.fees_collected[asset.asset_id], 2)
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), asset.asset_id), [18])
        self.assertEqual(deposit_block.header.contract_root, net.contract_root())
        self.assertEqual(deposit_block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(deposit_block.header.execution_profile.observed_fee_units, 2)

        deposit_event = next(iter(net.contract_events.values())).public_record()
        self.assertEqual(deposit_event["event_name"], "contract.deposited")
        self.assertEqual(deposit_event["public_data"]["asset_id"], asset.asset_id)
        self.assertEqual(deposit_event["public_data"]["amount"], 30)
        self.assertEqual(deposit_event["public_data"]["network_fee"], 2)
        self.assertEqual(deposit_event["public_data"]["new_asset_balance"], 30)
        self.assertEqual(
            deposit_event["public_data"]["caller_commitment"],
            devnet.domain_hash("CONTRACT-CALLER", "alice-view-key"),
        )
        self.assertNotIn("alice-view-key", json.dumps(deposit_event))

        with self.assertRaisesRegex(ValueError, "only the contract owner"):
            net.submit_contract_withdraw(
                contract.contract_id,
                asset.asset_id,
                amount=1,
                recipient_view_key="bob-view-key",
                signer_label="alice-view-key",
            )
        with self.assertRaisesRegex(ValueError, "contract balance"):
            net.submit_contract_withdraw(
                contract.contract_id,
                asset.asset_id,
                amount=31,
                recipient_view_key="bob-view-key",
                signer_label="owner-view-key",
            )

        withdraw = net.submit_contract_withdraw(
            contract.contract_id,
            asset.asset_id,
            amount=12,
            recipient_view_key="bob-view-key",
            network_fee=1,
            signer_label="owner-view-key",
        )
        withdraw_public = withdraw.public_record()
        self.assertEqual(withdraw_public["kind"], "contract_withdraw")
        self.assertNotIn("bob-view-key", json.dumps(withdraw_public))
        self.assertEqual(
            withdraw_public["recipient_commitment"],
            devnet.domain_hash("CONTRACT-WITHDRAW-RECIPIENT", "bob-view-key"),
        )

        withdraw_block = net.produce_block()
        updated = net.contracts[contract.contract_id]
        self.assertEqual(updated.asset_balances, {asset.asset_id: 17})
        self.assertEqual(net.fees_collected[asset.asset_id], 3)
        self.assertEqual(note_amounts(net.wallet_notes("bob-view-key"), asset.asset_id), [12])
        self.assertEqual(withdraw_block.header.execution_profile.privacy_proof_count, 0)
        self.assertEqual(withdraw_block.header.execution_profile.observed_fee_units, 1)
        self.assertEqual(len(net.contract_events), 2)
        withdraw_event = sorted(
            net.contract_events.values(),
            key=lambda item: item.event_index,
        )[-1].public_record()
        self.assertEqual(withdraw_event["event_name"], "contract.withdrawn")
        self.assertEqual(withdraw_event["public_data"]["remaining_asset_balance"], 17)
        self.assertEqual(
            withdraw_event["public_data"]["recipient_commitment"],
            withdraw_public["recipient_commitment"],
        )
        self.assertNotIn("bob-view-key", json.dumps(withdraw_event))

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.contract_root(), net.contract_root())
        self.assertEqual(round_trip.contract_event_root(), net.contract_event_root())
        self.assertEqual(
            round_trip.contracts[contract.contract_id].asset_balances,
            {asset.asset_id: 17},
        )

    def test_vault_contract_allows_committed_beneficiary_withdrawals(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("DVAULT", "vault-issuer")
        deposit_note = net.mint(asset.asset_id, "alice-view-key", 100)
        vault = net.deploy_contract("vault", owner_label="owner-view-key", fuel_limit=300)

        net.submit_contract_deposit(
            vault.contract_id,
            spent_note_id=deposit_note.note_id,
            amount=70,
            network_fee=1,
        )
        net.produce_block()
        self.assertEqual(net.contracts[vault.contract_id].asset_balances, {asset.asset_id: 70})

        bob_commitment = devnet.domain_hash("CONTRACT-CALLER", "bob-view-key")
        grant = net.submit_contract_call(
            vault.contract_id,
            entrypoint="grant",
            args={
                "asset_id": asset.asset_id,
                "beneficiary_commitment": bob_commitment,
                "amount": 30,
            },
            signer_label="owner-view-key",
            fuel_limit=200,
        )
        self.assertEqual(grant.fee, 0)
        grant_block = net.produce_block()
        updated = net.contracts[vault.contract_id]
        allowance_key = net._vault_allowance_key(asset.asset_id, bob_commitment)
        expected_allowance_commitment = net._vault_allowance_commitment(
            asset.asset_id,
            bob_commitment,
            30,
        )
        self.assertEqual(
            updated.storage["allowances"][allowance_key]["amount"],
            30,
        )
        self.assertEqual(
            updated.storage["allowances"][allowance_key]["allowance_commitment"],
            expected_allowance_commitment,
        )
        self.assertEqual(
            updated.storage["allowance_root"],
            net._vault_allowance_root_from_records(updated.storage["allowances"]),
        )
        self.assertEqual(grant_block.header.execution_profile.contract_call_count, 1)
        grant_event = sorted(
            net.contract_events.values(),
            key=lambda item: item.event_index,
        )[-1].public_record()
        self.assertEqual(grant_event["event_name"], "vault.allowance_granted")
        self.assertEqual(grant_event["public_data"]["beneficiary_commitment"], bob_commitment)
        self.assertEqual(
            grant_event["public_data"]["allowance_commitment"],
            expected_allowance_commitment,
        )
        self.assertEqual(
            grant_event["public_data"]["allowance_root"],
            updated.storage["allowance_root"],
        )
        self.assertNotIn("bob-view-key", json.dumps(grant_event))

        with self.assertRaisesRegex(ValueError, "vault allowance"):
            net.submit_contract_withdraw(
                vault.contract_id,
                asset.asset_id,
                amount=31,
                recipient_view_key="bob-view-key",
                signer_label="bob-view-key",
            )
        with self.assertRaisesRegex(ValueError, "must pay the signer"):
            net.submit_contract_withdraw(
                vault.contract_id,
                asset.asset_id,
                amount=1,
                recipient_view_key="carol-view-key",
                signer_label="bob-view-key",
            )

        withdraw = net.submit_contract_withdraw(
            vault.contract_id,
            asset.asset_id,
            amount=20,
            recipient_view_key="bob-view-key",
            network_fee=2,
            signer_label="bob-view-key",
        )
        self.assertNotIn("bob-view-key", json.dumps(withdraw.public_record()))
        withdraw_block = net.produce_block()
        updated = net.contracts[vault.contract_id]
        self.assertEqual(updated.asset_balances, {asset.asset_id: 48})
        expected_remaining_commitment = net._vault_allowance_commitment(
            asset.asset_id,
            bob_commitment,
            8,
        )
        self.assertEqual(
            updated.storage["allowances"][allowance_key]["amount"],
            8,
        )
        self.assertEqual(
            updated.storage["allowances"][allowance_key]["allowance_commitment"],
            expected_remaining_commitment,
        )
        self.assertEqual(
            updated.storage["allowance_root"],
            net._vault_allowance_root_from_records(updated.storage["allowances"]),
        )
        self.assertEqual(note_amounts(net.wallet_notes("bob-view-key"), asset.asset_id), [20])
        self.assertEqual(withdraw_block.header.execution_profile.observed_fee_units, 2)
        withdraw_event = sorted(
            net.contract_events.values(),
            key=lambda item: item.event_index,
        )[-1].public_record()
        self.assertEqual(withdraw_event["event_name"], "contract.withdrawn")
        self.assertEqual(
            withdraw_event["public_data"]["allowance_spender_commitment"],
            bob_commitment,
        )
        self.assertEqual(
            withdraw_event["public_data"]["remaining_allowance_commitment"],
            expected_remaining_commitment,
        )
        self.assertEqual(
            withdraw_event["public_data"]["allowance_root"],
            updated.storage["allowance_root"],
        )
        self.assertNotIn("bob-view-key", json.dumps(withdraw_event))
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.contracts[vault.contract_id].storage["allowance_root"],
            updated.storage["allowance_root"],
        )

        tampered = net.state_record()
        vault_state = next(
            item
            for item in tampered["contracts"]
            if item["contract_id"] == vault.contract_id
        )
        vault_state["storage"]["allowances"][allowance_key]["allowance_commitment"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "vault allowance root mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_private_lending_borrow_and_repay_flow(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        market = net.create_lending_market(
            wxmr.asset_id,
            dusd.asset_id,
            collateral_factor_bps=5_000,
        )
        collateral = net.mint(wxmr.asset_id, "alice-view-key", 1_200)

        with self.assertRaisesRegex(ValueError, "exceeds collateral factor"):
            net.submit_lending_borrow(
                market.market_id,
                collateral.note_id,
                collateral_amount=1_000,
                borrow_amount=700,
                owner_view_key="alice-view-key",
                borrow_fee=5,
            )

        borrow = net.submit_lending_borrow(
            market.market_id,
            collateral.note_id,
            collateral_amount=1_000,
            borrow_amount=500,
            owner_view_key="alice-view-key",
            borrow_fee=5,
        )
        public_borrow = borrow.public_record()
        self.assertNotIn("spent_collateral_note_id", public_borrow)
        self.assertNotIn("collateral_amount", public_borrow)
        self.assertNotIn("borrow_amount", public_borrow)
        self.assertIn("proof_root", public_borrow["proof_bundle"])
        borrow_block = net.produce_block()

        position = net.lending_positions[borrow.position_id]
        self.assertEqual(position.status, "active")
        self.assertEqual(position.collateral_amount, 1_000)
        self.assertEqual(position.debt_amount, 500)
        self.assertEqual(net.lending_markets[market.market_id].total_collateral, 1_000)
        self.assertEqual(net.lending_markets[market.market_id].total_debt, 500)
        self.assertEqual(net.fees_collected[wxmr.asset_id], 5)
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), wxmr.asset_id), [195])
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), dusd.asset_id), [500])
        self.assertEqual(borrow_block.header.execution_profile.privacy_proof_count, 1)
        self.assertNotEqual(borrow_block.header.contract_root, devnet.merkle_root("CONTRACT", []))

        debt_note_id = next(
            note["note_id"]
            for note in net.wallet_notes("alice-view-key")
            if note["asset_id"] == dusd.asset_id
        )
        repay = net.submit_lending_repay(
            borrow.position_id,
            debt_note_id,
            repay_fee=0,
        )
        public_repay = repay.public_record()
        self.assertNotIn("spent_debt_note_id", public_repay)
        self.assertIn("proof_root", public_repay["proof_bundle"])
        repay_block = net.produce_block()

        self.assertEqual(net.lending_positions[borrow.position_id].status, "repaid")
        self.assertEqual(net.lending_markets[market.market_id].total_collateral, 0)
        self.assertEqual(net.lending_markets[market.market_id].total_debt, 0)
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), wxmr.asset_id), [195, 1000])
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), dusd.asset_id), [])
        self.assertEqual(repay_block.header.execution_profile.privacy_proof_count, 1)
        self.assertNotEqual(borrow_block.header.contract_root, repay_block.header.contract_root)

    def test_oracle_price_feed_signs_and_drives_lending_risk(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        feed = net.publish_oracle_price(
            wxmr.asset_id,
            dusd.asset_id,
            price_numerator=2,
            price_denominator=1,
            publisher_labels=("oracle-a", "oracle-b"),
        )
        self.assertEqual(feed.public_record()["attestation_count"], 2)
        self.assertEqual(net.public_snapshot()["oracle_price_count"], 1)
        market = net.create_lending_market(
            wxmr.asset_id,
            dusd.asset_id,
            collateral_factor_bps=5_000,
            oracle_feed_id=feed.feed_id,
        )
        collateral = net.mint(wxmr.asset_id, "alice-view-key", 1_200)

        with self.assertRaisesRegex(ValueError, "exceeds collateral factor"):
            net.submit_lending_borrow(
                market.market_id,
                collateral.note_id,
                collateral_amount=1_000,
                borrow_amount=1_100,
                owner_view_key="alice-view-key",
                borrow_fee=5,
            )

        borrow = net.submit_lending_borrow(
            market.market_id,
            collateral.note_id,
            collateral_amount=1_000,
            borrow_amount=900,
            owner_view_key="alice-view-key",
            borrow_fee=5,
        )
        block = net.produce_block()
        self.assertEqual(net.lending_positions[borrow.position_id].debt_amount, 900)
        self.assertEqual(net.lending_markets[market.market_id].total_debt, 900)
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), dusd.asset_id), [900])
        self.assertEqual(len(block.header.contract_root), 64)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.oracle_prices[feed.feed_id].round_id, 1)
        tampered_state = net.state_record()
        tampered_state["oracle_prices"][0]["attestations"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid oracle price attestation"):
            devnet.NebulaL2Devnet.from_state_record(tampered_state)

    def test_oracle_backed_lending_liquidation_flow(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        feed = net.publish_oracle_price(
            wxmr.asset_id,
            dusd.asset_id,
            price_numerator=2,
            publisher_labels=("oracle-a", "oracle-b"),
        )
        market = net.create_lending_market(
            wxmr.asset_id,
            dusd.asset_id,
            collateral_factor_bps=5_000,
            liquidation_threshold_bps=7_500,
            oracle_feed_id=feed.feed_id,
        )
        collateral = net.mint(wxmr.asset_id, "alice-view-key", 1_200)
        borrow = net.submit_lending_borrow(
            market.market_id,
            collateral.note_id,
            collateral_amount=1_000,
            borrow_amount=900,
            owner_view_key="alice-view-key",
            borrow_fee=5,
        )
        net.produce_block()
        liquidation_debt = net.mint(dusd.asset_id, "liquidator-view-key", 905)

        with self.assertRaisesRegex(ValueError, "not liquidatable"):
            net.submit_lending_liquidation(
                borrow.position_id,
                liquidation_debt.note_id,
                liquidator_view_key="liquidator-view-key",
                liquidation_fee=5,
            )

        net.publish_oracle_price(
            wxmr.asset_id,
            dusd.asset_id,
            price_numerator=1,
            publisher_labels=("oracle-a", "oracle-b"),
        )
        liquidation = net.submit_lending_liquidation(
            borrow.position_id,
            liquidation_debt.note_id,
            liquidator_view_key="liquidator-view-key",
            liquidation_fee=5,
        )
        public_liquidation = liquidation.public_record()
        self.assertEqual(public_liquidation["kind"], "lending_liquidation")
        self.assertNotIn("spent_debt_note_id", public_liquidation)
        self.assertNotIn("liquidator-view-key", json.dumps(public_liquidation))
        self.assertIn("proof_root", public_liquidation["proof_bundle"])

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(len(round_trip.pending), 1)
        liquidation_block = round_trip.produce_block()

        self.assertEqual(round_trip.lending_positions[borrow.position_id].status, "liquidated")
        self.assertEqual(round_trip.lending_markets[market.market_id].total_collateral, 0)
        self.assertEqual(round_trip.lending_markets[market.market_id].total_debt, 0)
        self.assertEqual(round_trip.fees_collected[dusd.asset_id], 5)
        self.assertEqual(
            note_amounts(round_trip.wallet_notes("liquidator-view-key"), wxmr.asset_id),
            [1_000],
        )
        self.assertEqual(
            note_amounts(round_trip.wallet_notes("liquidator-view-key"), dusd.asset_id),
            [],
        )
        self.assertEqual(liquidation_block.header.execution_profile.privacy_proof_count, 1)

    def test_demo_network_preserves_private_transfer_balances(self) -> None:
        net = devnet.build_demo_network()

        self.assertEqual(net.public_snapshot()["height"], 2)
        self.assertEqual(net.wallet_notes("alice-view-key")[0]["amount"], 974_980)
        self.assertEqual(net.wallet_notes("bob-view-key")[0]["amount"], 19_990)
        self.assertEqual(net.wallet_notes("carol-view-key")[0]["amount"], 5_000)
        self.assertEqual(len(net.anchor_commitment()), 64)

    def test_state_round_trip_preserves_anchor_and_wallet_views(self) -> None:
        net = devnet.build_demo_network()

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"
            devnet.save_state(state_path, net)
            restored = devnet.load_state(state_path)

        self.assertEqual(restored.anchor_commitment(), net.anchor_commitment())
        self.assertEqual(
            restored.wallet_notes("alice-view-key"),
            net.wallet_notes("alice-view-key"),
        )
        self.assertEqual(
            restored.public_snapshot()["spent_nullifier_count"],
            net.public_snapshot()["spent_nullifier_count"],
        )

    def test_cli_persistent_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            policy = run_json("crypto-policy")
            self.assertEqual(policy["crypto_policy_root"], devnet.crypto_policy_root())
            self.assertEqual(policy["crypto_suite"]["account_signature"], "ML-DSA-65")
            self.assertEqual(policy["crypto_suite"]["key_establishment"], "ML-KEM-768")
            self.assertIn("test_vectors", policy)

            account = run_json("account", "--label", "alice-view-key")
            self.assertEqual(account["auth_scheme"], devnet.ACCOUNT_SIGNATURE_SCHEME)
            self.assertEqual(account["crypto_policy_root"], devnet.crypto_policy_root())
            self.assertTrue(account["spend_public_key"])

            initialized = run_json(
                "init",
                "--state",
                str(state_path),
                "--epoch-size",
                "3",
            )
            self.assertEqual(initialized["snapshot"]["height"], 0)

            asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            minted = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                asset["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "1000",
            )
            transfer = run_json(
                "transfer",
                "--state",
                str(state_path),
                "--spent-note-id",
                minted["note_id"],
                "--to",
                "bob-view-key",
                "--amount",
                "250",
                "--fee",
                "5",
            )
            self.assertEqual(transfer["fee"], 5)
            self.assertEqual(transfer["auth_scheme"], devnet.ACCOUNT_SIGNATURE_SCHEME)
            self.assertTrue(transfer["auth_signature"])
            self.assertIn("proof_root", transfer["proof_bundle"])
            self.assertNotIn("private_witness_hash", transfer["proof_bundle"])
            tx_public_hash = devnet.domain_hash("TX-PUBLIC", transfer)
            mempool_tx_public_hash = devnet.domain_hash("MEMPOOL-TX-PUBLIC", transfer)

            mempool = run_json("mempool", "--state", str(state_path))
            self.assertEqual(len(mempool["admissions"]), 1)
            self.assertEqual(len(mempool["mempool_admission_root"]), 64)
            self.assertEqual(mempool["admissions"][0]["mempool_sequence"], 0)
            self.assertEqual(len(mempool["admissions"][0]["committee_key_id"]), 64)
            self.assertTrue(mempool["admissions"][0]["auth_signature"])
            self.assertNotIn("bob-view-key", json.dumps(mempool))
            pending_status = run_json(
                "mempool-status",
                "--state",
                str(state_path),
                "--admission-id",
                mempool["admissions"][0]["admission_id"],
            )
            self.assertEqual(pending_status["status"], "pending")
            self.assertEqual(
                pending_status["admission"]["admission_id"],
                mempool["admissions"][0]["admission_id"],
            )
            self.assertEqual(
                pending_status["mempool_admission_root"],
                mempool["mempool_admission_root"],
            )
            self.assertNotIn("bob-view-key", json.dumps(pending_status))
            pending_tx_status = run_json(
                "tx-status",
                "--state",
                str(state_path),
                "--tx-hash",
                tx_public_hash,
            )
            self.assertEqual(pending_tx_status["status"], "pending")
            self.assertEqual(pending_tx_status["tx_public_hash"], tx_public_hash)
            self.assertEqual(
                pending_tx_status["mempool_tx_public_hash"],
                mempool_tx_public_hash,
            )
            self.assertEqual(
                pending_tx_status["mempool_admission"]["admission_id"],
                mempool["admissions"][0]["admission_id"],
            )
            self.assertNotIn("alice-view-key", json.dumps(pending_tx_status))
            self.assertNotIn("bob-view-key", json.dumps(pending_tx_status))
            pending_snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(pending_snapshot["pending_mempool_admission_count"], 1)
            self.assertEqual(
                pending_snapshot["mempool_admission_root"],
                mempool["mempool_admission_root"],
            )
            quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "private-transfer",
                "--fee-asset-id",
                asset["asset_id"],
            )
            self.assertEqual(quote["pending_tx_count"], 1)
            self.assertEqual(quote["projected_tx_count"], 2)
            self.assertEqual(quote["operation"], "private-transfer")
            self.assertGreaterEqual(quote["recommended_fee_units"], quote["minimum_fee_units"])
            self.assertEqual(len(quote["quote_hash"]), 64)
            self.assertEqual(len(quote["projected_profile"]["local_fee_market_root"]), 64)
            self.assertGreaterEqual(quote["projected_profile"]["local_fee_lane_count"], 2)
            self.assertIn(
                ("operation", "private-transfer"),
                {
                    (lane["lane_type"], lane["lane_key"])
                    for lane in quote["candidate_local_fee_markets"]
                },
            )
            self.assertNotIn("bob-view-key", json.dumps(quote))
            pending_fee_markets = run_json(
                "fee-markets",
                "--state",
                str(state_path),
                "--pending",
            )
            self.assertEqual(pending_fee_markets["scope"], "pending")
            self.assertEqual(pending_fee_markets["tx_count"], 1)
            self.assertEqual(len(pending_fee_markets["local_fee_market_root"]), 64)
            self.assertIn(
                ("operation", "private_transfer"),
                {
                    (lane["lane_type"], lane["lane_key"])
                    for lane in pending_fee_markets["lanes"]
                },
            )
            self.assertNotIn("alice-view-key", json.dumps(pending_fee_markets))
            self.assertNotIn("bob-view-key", json.dumps(pending_fee_markets))
            pending_profile = run_json("profile", "--state", str(state_path))
            self.assertEqual(pending_profile["confirmed_block_count"], 0)
            self.assertEqual(pending_profile["pending_tx_count"], 1)
            self.assertEqual(pending_profile["pending"]["tx_count"], 1)
            self.assertEqual(len(pending_profile["profile_root"]), 64)
            self.assertEqual(len(pending_profile["fee_curve_root"]), 64)
            self.assertIn(
                "private-transfer",
                {row["operation"] for row in pending_profile["fee_curve"]},
            )
            self.assertNotIn("alice-view-key", json.dumps(pending_profile))
            self.assertNotIn("bob-view-key", json.dumps(pending_profile))
            contract_deposit_quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "contract-deposit",
                "--output-count",
                "1",
                "--fee-asset-id",
                asset["asset_id"],
            )
            self.assertEqual(contract_deposit_quote["operation"], "contract-deposit")
            self.assertEqual(contract_deposit_quote["fee_mode"], "private-note")
            self.assertEqual(
                contract_deposit_quote["candidate_profile"]["privacy_proof_count"],
                1,
            )
            contract_withdraw_quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "contract-withdraw",
                "--fee-asset-id",
                asset["asset_id"],
            )
            self.assertEqual(contract_withdraw_quote["operation"], "contract-withdraw")
            self.assertEqual(contract_withdraw_quote["fee_mode"], "contract-balance")
            self.assertEqual(contract_withdraw_quote["output_count"], 1)
            self.assertEqual(
                contract_withdraw_quote["candidate_profile"]["privacy_proof_count"],
                0,
            )

            block_header = run_json("block", "--state", str(state_path))
            self.assertEqual(block_header["height"], 0)
            self.assertEqual(block_header["mempool_admission_root"], mempool["mempool_admission_root"])
            self.assertEqual(block_header["mempool_admission_count"], 1)
            self.assertEqual(block_header["execution_profile"]["tx_count"], 1)
            self.assertEqual(block_header["execution_profile"]["observed_fee_units"], 5)
            self.assertEqual(block_header["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(len(block_header["execution_profile"]["local_fee_market_root"]), 64)
            self.assertGreaterEqual(block_header["execution_profile"]["local_fee_lane_count"], 2)
            cleared_mempool = run_json("mempool", "--state", str(state_path))
            self.assertEqual(cleared_mempool["admissions"], [])
            self.assertEqual(len(cleared_mempool["mempool_admission_root"]), 64)
            block_fee_markets = run_json(
                "fee-markets",
                "--state",
                str(state_path),
                "--block-height",
                "0",
            )
            self.assertEqual(block_fee_markets["scope"], "block")
            self.assertEqual(block_fee_markets["block_hash"], block_header["block_hash"])
            self.assertEqual(
                block_fee_markets["local_fee_market_root"],
                block_header["execution_profile"]["local_fee_market_root"],
            )
            self.assertIn(
                ("operation", "private_transfer"),
                {
                    (lane["lane_type"], lane["lane_key"])
                    for lane in block_fee_markets["lanes"]
                },
            )
            self.assertNotIn("alice-view-key", json.dumps(block_fee_markets))
            self.assertNotIn("bob-view-key", json.dumps(block_fee_markets))
            confirmed_profile = run_json("profile", "--state", str(state_path))
            self.assertEqual(confirmed_profile["confirmed_block_count"], 1)
            self.assertEqual(confirmed_profile["confirmed"]["tx_count"], 1)
            self.assertEqual(confirmed_profile["confirmed"]["observed_fee_units"], 5)
            self.assertEqual(confirmed_profile["pending"]["tx_count"], 0)
            self.assertEqual(
                confirmed_profile["confirmed"]["batched_da_bytes"],
                block_header["execution_profile"]["batched_da_bytes"],
            )
            confirmed_only_profile = run_json(
                "profile",
                "--state",
                str(state_path),
                "--exclude-pending",
            )
            self.assertEqual(confirmed_only_profile["pending_tx_count"], 0)
            self.assertEqual(confirmed_only_profile["pending"]["tx_count"], 0)
            benchmark = run_json(
                "benchmark",
                "--state",
                str(state_path),
                "--scenario",
                "cli-private-transfer-mix",
                "--benchmarker",
                "perf-cli",
            )
            self.assertEqual(benchmark["scenario"], "cli-private-transfer-mix")
            self.assertEqual(benchmark["benchmarker_label"], "perf-cli")
            self.assertEqual(benchmark["profile_root"], confirmed_profile["profile_root"])
            self.assertEqual(benchmark["fee_curve_root"], confirmed_profile["fee_curve_root"])
            self.assertEqual(benchmark["confirmed_summary"]["tx_count"], 1)
            self.assertEqual(benchmark["pending_summary"]["tx_count"], 0)
            self.assertEqual(benchmark["measured_at_height"], 0)
            self.assertTrue(benchmark["auth_signature"])
            self.assertEqual(len(benchmark["benchmark_root"]), 64)
            self.assertNotIn("alice-view-key", json.dumps(benchmark))
            self.assertNotIn("bob-view-key", json.dumps(benchmark))
            benchmarks = run_json("benchmarks", "--state", str(state_path))
            self.assertEqual(benchmarks["performance_benchmark_count"], 1)
            self.assertEqual(
                benchmarks["benchmarks"][0]["benchmark_id"],
                benchmark["benchmark_id"],
            )
            self.assertEqual(len(benchmarks["performance_benchmark_root"]), 64)
            benchmark_snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(benchmark_snapshot["performance_benchmark_count"], 1)
            self.assertEqual(
                benchmark_snapshot["performance_benchmark_root"],
                benchmarks["performance_benchmark_root"],
            )
            measured_cli_da_bytes = (
                benchmark["confirmed_summary"]["da_encoded_bytes"]
                or benchmark["confirmed_summary"]["batched_da_bytes"]
            ) + 64
            calibration = run_json(
                "calibrate",
                "--state",
                str(state_path),
                "--benchmark-id",
                benchmark["benchmark_id"],
                "--calibrator",
                "perf-cli-calibrator",
                "--measured-proof-bytes",
                str(benchmark["confirmed_summary"]["estimated_proof_bytes"] + 128),
                "--measured-auth-bytes",
                str(benchmark["confirmed_summary"]["estimated_authorization_bytes"] + 128),
                "--measured-da-bytes",
                str(measured_cli_da_bytes),
                "--measured-prover-ms",
                "9",
                "--measured-signer-ms",
                "4",
                "--measured-total-latency-ms",
                str(devnet.TARGET_BLOCK_MS + 25),
            )
            self.assertEqual(calibration["source_benchmark_id"], benchmark["benchmark_id"])
            self.assertEqual(calibration["calibrator_label"], "perf-cli-calibrator")
            self.assertEqual(calibration["measured_da_encoded_bytes"], measured_cli_da_bytes)
            self.assertGreater(calibration["proof_size_multiplier_bps"], 10_000)
            self.assertGreater(calibration["authorization_size_multiplier_bps"], 10_000)
            self.assertGreater(calibration["da_bandwidth_multiplier_bps"], 10_000)
            self.assertEqual(calibration["target_latency_delta_ms"], 25)
            self.assertTrue(calibration["auth_signature"])
            self.assertEqual(len(calibration["calibration_root"]), 64)
            calibrations = run_json("calibrations", "--state", str(state_path))
            self.assertEqual(calibrations["performance_calibration_count"], 1)
            self.assertEqual(
                calibrations["latest_performance_calibration_id"],
                calibration["calibration_id"],
            )
            self.assertEqual(
                calibrations["calibrations"][0]["calibration_id"],
                calibration["calibration_id"],
            )
            calibrated_profile = run_json("profile", "--state", str(state_path))
            self.assertEqual(calibrated_profile["performance_calibration_count"], 1)
            self.assertEqual(
                calibrated_profile["latest_performance_calibration_id"],
                calibration["calibration_id"],
            )
            calibration_snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(calibration_snapshot["performance_calibration_count"], 1)
            self.assertEqual(
                calibration_snapshot["performance_calibration_root"],
                calibrations["performance_calibration_root"],
            )
            included_status = run_json(
                "mempool-status",
                "--state",
                str(state_path),
                "--admission-id",
                mempool["admissions"][0]["admission_id"],
            )
            self.assertEqual(included_status["status"], "included")
            self.assertEqual(included_status["block_height"], block_header["height"])
            self.assertEqual(
                included_status["mempool_admission_root"],
                mempool["mempool_admission_root"],
            )
            self.assertEqual(included_status["settlement"]["status"], "soft_final")
            self.assertNotIn("bob-view-key", json.dumps(included_status))
            included_tx_status = run_json(
                "tx-status",
                "--state",
                str(state_path),
                "--tx-hash",
                mempool_tx_public_hash,
            )
            self.assertEqual(included_tx_status["status"], "soft_final")
            self.assertEqual(included_tx_status["inclusion_status"], "included")
            self.assertEqual(included_tx_status["block_height"], block_header["height"])
            self.assertEqual(included_tx_status["tx_index"], 0)
            self.assertEqual(included_tx_status["settlement"]["status"], "soft_final")
            self.assertEqual(
                included_tx_status["privacy_proof_item"]["tx_kind"],
                "private_transfer",
            )
            self.assertNotIn("alice-view-key", json.dumps(included_tx_status))
            self.assertNotIn("bob-view-key", json.dumps(included_tx_status))
            da = run_json("da", "--state", str(state_path), "--block-height", "0")
            self.assertEqual(da["da_root"], block_header["da_root"])
            self.assertEqual(da["attestation_count"], 1)
            self.assertGreaterEqual(da["shard_count"], 2)
            sample = run_json(
                "da-sample",
                "--state",
                str(state_path),
                "--block-height",
                "0",
                "--shard-index",
                "0",
            )
            self.assertTrue(sample["verified"])
            self.assertEqual(sample["da_root"], block_header["da_root"])
            validity = run_json(
                "validity",
                "--state",
                str(state_path),
                "--block-height",
                "0",
            )
            self.assertEqual(validity["validity_certificate_count"], 1)
            self.assertEqual(validity["filtered_certificate_count"], 1)
            self.assertEqual(validity["certificates"][0]["block_hash"], block_header["block_hash"])
            self.assertEqual(validity["certificates"][0]["state_root"], block_header["state_root"])
            self.assertEqual(validity["certificates"][0]["da_root"], block_header["da_root"])
            self.assertEqual(len(validity["certificates"][0]["certificate_root"]), 64)
            self.assertEqual(len(validity["validity_root"]), 64)
            self.assertNotIn("alice-view-key", json.dumps(validity))
            self.assertNotIn("bob-view-key", json.dumps(validity))
            proofs = run_json(
                "proofs",
                "--state",
                str(state_path),
                "--block-height",
                "0",
            )
            self.assertEqual(proofs["privacy_proof_aggregate_count"], 1)
            self.assertEqual(proofs["filtered_aggregate_count"], 1)
            self.assertEqual(proofs["aggregates"][0]["block_hash"], block_header["block_hash"])
            self.assertEqual(proofs["aggregates"][0]["tx_root"], block_header["tx_root"])
            self.assertEqual(proofs["aggregates"][0]["privacy_proof_count"], 1)
            self.assertEqual(proofs["aggregates"][0]["proof_items"][0]["tx_kind"], "private_transfer")
            self.assertEqual(len(proofs["aggregates"][0]["aggregate_root"]), 64)
            self.assertEqual(len(proofs["privacy_proof_aggregate_root"]), 64)
            self.assertNotIn("private_witness_hash", json.dumps(proofs))
            self.assertNotIn("alice-view-key", json.dumps(proofs))
            self.assertNotIn("bob-view-key", json.dumps(proofs))
            audit = run_json(
                "audit-block",
                "--state",
                str(state_path),
                "--block-height",
                "0",
                "--watchtower",
                "watchtower-cli",
                "--sample-shard",
                "0",
                "--sample-shard",
                "1",
            )
            self.assertEqual(audit["block_hash"], block_header["block_hash"])
            self.assertEqual(audit["da_root"], block_header["da_root"])
            self.assertEqual(audit["sampled_shard_indices"], [0, 1])
            self.assertEqual(audit["sampled_shard_count"], 2)
            self.assertEqual(audit["audit_status"], "available")
            self.assertTrue(audit["auth_signature"])
            self.assertNotIn("alice-view-key", json.dumps(audit))
            self.assertNotIn("bob-view-key", json.dumps(audit))
            audits = run_json(
                "block-audits",
                "--state",
                str(state_path),
                "--block-height",
                "0",
            )
            self.assertEqual(audits["block_audit_report_count"], 1)
            self.assertEqual(audits["filtered_report_count"], 1)
            self.assertEqual(audits["reports"][0]["audit_id"], audit["audit_id"])
            self.assertEqual(len(audits["block_audit_report_root"]), 64)
            challenge = run_json(
                "challenge-block",
                "--state",
                str(state_path),
                "--block-height",
                "0",
                "--type",
                "bridge-root-mismatch",
                "--observed-root",
                devnet.domain_hash("CLI-BRIDGE-ROOT", "conflict"),
                "--reporter",
                "watchtower-cli",
            )
            self.assertEqual(challenge["status"], "external_dispute")
            self.assertEqual(challenge["slashed_amount"], 0)
            self.assertEqual(challenge["expected_root"], block_header["bridge_root"])
            self.assertTrue(challenge["auth_signature"])
            challenges = run_json(
                "block-challenges",
                "--state",
                str(state_path),
                "--block-height",
                "0",
            )
            self.assertEqual(challenges["block_challenge_report_count"], 1)
            self.assertEqual(challenges["filtered_report_count"], 1)
            self.assertEqual(challenges["reports"][0]["challenge_id"], challenge["challenge_id"])
            self.assertEqual(len(challenges["block_challenge_report_root"]), 64)

            alice = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            bob = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            self.assertEqual(alice[0]["amount"], 745)
            self.assertEqual(bob[0]["amount"], 250)
            history = run_json("wallet-history", "--state", str(state_path), "--owner", "bob-view-key")
            self.assertEqual(history["current_totals"], {asset["asset_id"]: 250})
            self.assertEqual(history["received_totals"], {asset["asset_id"]: 250})
            self.assertEqual(history["spent_totals"], {})
            self.assertEqual(history["unindexed_current_note_count"], 0)
            self.assertEqual(len(history["history_root"]), 64)
            self.assertNotIn("alice-view-key", json.dumps(history))
            self.assertNotIn("bob-view-key", json.dumps(history))
            disclosure = run_json(
                "disclose",
                "--state",
                str(state_path),
                "--owner",
                "bob-view-key",
                "--audience",
                "merchant-auditor",
                "--asset-id",
                asset["asset_id"],
            )
            self.assertEqual(disclosure["disclosed_view_key"], "bob-view-key")
            self.assertEqual(disclosure["audience_label"], "merchant-auditor")
            self.assertEqual(disclosure["asset_totals"], {asset["asset_id"]: 250})
            self.assertEqual(len(disclosure["note_commitment_root"]), 64)
            self.assertNotIn("alice-view-key", json.dumps(disclosure))
            self.assertTrue(devnet.load_state(state_path).verify_view_key_disclosure(disclosure))

            snapshot = run_json("snapshot", "--state", str(state_path))
            anchor = run_json("anchor", "--state", str(state_path))
            self.assertEqual(snapshot["height"], 1)
            self.assertEqual(snapshot["spent_nullifier_count"], 1)
            self.assertEqual(snapshot["data_availability_record_count"], 1)
            self.assertEqual(snapshot["latest_da_root"], block_header["da_root"])
            self.assertEqual(len(anchor["anchor_commitment"]), 64)

    def test_cli_persistent_mempool_omission_evidence_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path), "--epoch-size", "2")
            asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            minted = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                asset["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "1000",
            )
            run_json(
                "transfer",
                "--state",
                str(state_path),
                "--spent-note-id",
                minted["note_id"],
                "--to",
                "bob-view-key",
                "--amount",
                "250",
                "--fee",
                "5",
            )
            mempool = run_json("mempool", "--state", str(state_path))
            admission = mempool["admissions"][0]
            preconfirmation = mempool["preconfirmations"][0]
            self.assertRelayMetadata(
                admission,
                policy="dandelion",
                raw_path="dandelion-stem-fluff",
            )
            self.assertEqual(mempool["mempool_omission_evidence_count"], 0)
            self.assertEqual(mempool["mempool_preconfirmation_count"], 1)
            self.assertEqual(mempool["mempool_preconfirmation_miss_count"], 0)
            self.assertEqual(preconfirmation["admission_id"], admission["admission_id"])
            self.assertEqual(preconfirmation["target_height"], 0)
            self.assertNotIn("bob-view-key", json.dumps(preconfirmation))
            preconfirmations = run_json("preconfirmations", "--state", str(state_path))
            self.assertEqual(preconfirmations["mempool_preconfirmation_count"], 1)
            self.assertEqual(
                preconfirmations["preconfirmations"][0]["preconfirmation_id"],
                preconfirmation["preconfirmation_id"],
            )
            pending_status = run_json(
                "mempool-status",
                "--state",
                str(state_path),
                "--admission-id",
                admission["admission_id"],
            )
            self.assertEqual(pending_status["status"], "pending")
            self.assertEqual(pending_status["admission"]["admission_id"], admission["admission_id"])
            self.assertEqual(pending_status["preconfirmations"][0]["status"], "preconfirmed")

            for expected_height in range(3):
                block = run_json("block", "--state", str(state_path), "--defer-mempool")
                self.assertEqual(block["height"], expected_height)
                self.assertEqual(block["mempool_admission_count"], 0)
                self.assertEqual(block["execution_profile"]["tx_count"], 0)
                if expected_height == 0:
                    miss = run_json(
                        "preconfirm-miss",
                        "--state",
                        str(state_path),
                        "--preconfirmation-id",
                        preconfirmation["preconfirmation_id"],
                        "--reporter",
                        "watchtower-cli",
                    )
                    self.assertEqual(
                        miss["preconfirmation_id"],
                        preconfirmation["preconfirmation_id"],
                    )
                    self.assertEqual(miss["status"], "slashed")
                    self.assertEqual(miss["slashed_amount"], 1)
                    self.assertEqual(miss["validator_stake_after"], 999)
                    self.assertNotIn("bob-view-key", json.dumps(miss))

            evidence = run_json(
                "mempool-expire",
                "--state",
                str(state_path),
                "--admission-id",
                admission["admission_id"],
                "--reporter",
                "watchtower-cli",
            )
            self.assertEqual(evidence["admission_id"], admission["admission_id"])
            self.assertEqual(evidence["tx_public_hash"], admission["tx_public_hash"])
            self.assertEqual(evidence["encrypted_payload_hash"], admission["encrypted_payload_hash"])
            self.assertEqual(evidence["reporter_label"], "watchtower-cli")
            self.assertEqual(evidence["missed_block_count"], 1)
            self.assertEqual(evidence["penalty_units"], 1)
            self.assertEqual(evidence["status"], "slashed")
            self.assertEqual(evidence["slashed_amount"], 1)
            self.assertEqual(evidence["validator_stake_after"], 998)
            self.assertTrue(evidence["auth_signature"])
            self.assertNotIn("alice-view-key", json.dumps(evidence))
            self.assertNotIn("bob-view-key", json.dumps(evidence))
            omitted_status = run_json(
                "mempool-status",
                "--state",
                str(state_path),
                "--admission-id",
                admission["admission_id"],
            )
            self.assertEqual(omitted_status["status"], "omitted")
            self.assertEqual(omitted_status["evidence_status"], "slashed")
            self.assertEqual(omitted_status["evidence"]["evidence_id"], evidence["evidence_id"])
            self.assertEqual(omitted_status["forced_inclusion_count"], 0)
            self.assertNotIn("bob-view-key", json.dumps(omitted_status))

            mempool = run_json("mempool", "--state", str(state_path))
            self.assertEqual(mempool["admissions"], [])
            self.assertEqual(mempool["mempool_omission_evidence_count"], 1)
            self.assertEqual(mempool["mempool_preconfirmation_miss_count"], 1)
            self.assertEqual(mempool["mempool_forced_inclusion_count"], 0)
            evidence_list = run_json("mempool-evidence", "--state", str(state_path))
            self.assertEqual(len(evidence_list["evidence"]), 1)
            self.assertEqual(evidence_list["evidence"][0]["evidence_id"], evidence["evidence_id"])
            self.assertEqual(
                evidence_list["mempool_omission_evidence_root"],
                mempool["mempool_omission_evidence_root"],
            )
            self.assertEqual(evidence_list["mempool_forced_inclusion_count"], 0)

            forced = run_json(
                "mempool-force-include",
                "--state",
                str(state_path),
                "--evidence-id",
                evidence["evidence_id"],
                "--sequencer",
                "devnet-proposer",
            )
            self.assertEqual(forced["evidence_id"], evidence["evidence_id"])
            self.assertEqual(forced["admission_id"], admission["admission_id"])
            self.assertEqual(forced["tx_public_hash"], admission["tx_public_hash"])
            self.assertEqual(forced["old_encrypted_payload_hash"], admission["encrypted_payload_hash"])
            self.assertRelayMetadata(
                forced,
                policy="forced-inclusion",
                prefix="new_relay_path",
            )
            self.assertNotEqual(forced["new_admission_id"], admission["admission_id"])
            self.assertTrue(forced["auth_signature"])
            self.assertNotIn("alice-view-key", json.dumps(forced))
            self.assertNotIn("bob-view-key", json.dumps(forced))

            requeued_status = run_json(
                "mempool-status",
                "--state",
                str(state_path),
                "--admission-id",
                admission["admission_id"],
            )
            self.assertEqual(requeued_status["status"], "omitted")
            self.assertEqual(requeued_status["forced_inclusion_count"], 1)
            self.assertEqual(
                requeued_status["forced_inclusions"][0]["forced_inclusion_id"],
                forced["forced_inclusion_id"],
            )
            mempool = run_json("mempool", "--state", str(state_path))
            self.assertEqual(mempool["mempool_forced_inclusion_count"], 1)
            self.assertEqual(mempool["admissions"][0]["admission_id"], forced["new_admission_id"])
            self.assertRelayMetadata(
                mempool["admissions"][0],
                policy="forced-inclusion",
            )
            self.assertNotIn("bob-view-key", json.dumps(mempool["forced_inclusions"]))

            forced_block = run_json("block", "--state", str(state_path))
            self.assertEqual(forced_block["mempool_admission_count"], 1)
            forced_status = run_json(
                "mempool-status",
                "--state",
                str(state_path),
                "--admission-id",
                forced["new_admission_id"],
            )
            self.assertEqual(forced_status["status"], "included")
            self.assertRelayMetadata(
                forced_status["admission"],
                policy="forced-inclusion",
            )
            bob_wallet = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            self.assertEqual(note_amounts(bob_wallet, asset["asset_id"]), [250])

            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(snapshot["pending_mempool_admission_count"], 0)
            self.assertEqual(snapshot["mempool_omission_evidence_count"], 1)
            self.assertEqual(snapshot["mempool_forced_inclusion_count"], 1)
            self.assertEqual(
                snapshot["mempool_omission_evidence_root"],
                mempool["mempool_omission_evidence_root"],
            )
            validators = run_json("validators", "--state", str(state_path))
            proposer = next(
                item for item in validators if item["label"] == "devnet-proposer"
            )
            self.assertEqual(proposer["stake"], 998)
            self.assertEqual(proposer["slashed_stake"], 2)
            self.assertEqual(proposer["omission_count"], 1)
            self.assertEqual(proposer["preconfirmation_miss_count"], 1)
            self.assertEqual(proposer["status"], "active")

    def test_cli_persistent_native_token_mint_burn_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DGR",
                "--issuer-policy",
                "issuer:treasury-key",
                "--supply-policy",
                "fixed",
                "--max-supply",
                "1000",
            )
            self.assertEqual(asset["supply_policy"], "fixed")
            self.assertEqual(asset["max_supply"], 1000)
            mint = run_json(
                "token-mint",
                "--state",
                str(state_path),
                "--asset-id",
                asset["asset_id"],
                "--to",
                "alice-view-key",
                "--amount",
                "1000",
            )
            self.assertEqual(mint["kind"], "asset_mint")
            self.assertNotIn("alice-view-key", json.dumps(mint))
            self.assertEqual(mint["amount"], 1000)
            self.assertTrue(mint["auth_signature"])
            overflow = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "token-mint",
                    "--state",
                    str(state_path),
                    "--asset-id",
                    asset["asset_id"],
                    "--to",
                    "bob-view-key",
                    "--amount",
                    "1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(overflow.returncode, 0)
            self.assertIn("max supply", overflow.stderr)

            mint_block = run_json("block", "--state", str(state_path))
            self.assertIn("asset_root", mint_block)
            self.assertEqual(mint_block["execution_profile"]["privacy_proof_count"], 0)
            alice = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            snapshot = run_json("snapshot", "--state", str(state_path))
            supply = next(
                item for item in snapshot["asset_supplies"] if item["asset_id"] == asset["asset_id"]
            )
            self.assertEqual(note_amounts(alice, asset["asset_id"]), [1000])
            self.assertEqual(supply["minted_amount"], 1000)
            self.assertEqual(supply["burned_amount"], 0)
            self.assertEqual(supply["circulating_amount"], 1000)

            burn = run_json(
                "token-burn",
                "--state",
                str(state_path),
                "--spent-note-id",
                alice[0]["note_id"],
                "--amount",
                "250",
            )
            self.assertEqual(burn["kind"], "asset_burn")
            self.assertNotIn("spent_note_id", burn)
            self.assertNotIn("alice-view-key", json.dumps(burn))
            self.assertIn("proof_root", burn["proof_bundle"])

            burn_block = run_json("block", "--state", str(state_path))
            alice = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            snapshot = run_json("snapshot", "--state", str(state_path))
            supply = next(
                item for item in snapshot["asset_supplies"] if item["asset_id"] == asset["asset_id"]
            )
            self.assertEqual(note_amounts(alice, asset["asset_id"]), [750])
            self.assertEqual(supply["minted_amount"], 1000)
            self.assertEqual(supply["burned_amount"], 250)
            self.assertEqual(supply["circulating_amount"], 750)
            self.assertEqual(burn_block["execution_profile"]["privacy_proof_count"], 1)

    def test_cli_persistent_batch_transfer_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            first = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                asset["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "1000",
            )
            second = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                asset["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "500",
            )
            batch = run_json(
                "batch-transfer",
                "--state",
                str(state_path),
                "--spent-note-id",
                first["note_id"],
                "--spent-note-id",
                second["note_id"],
                "--to",
                "bob-view-key",
                "--amount",
                "200",
                "--to",
                "carol-view-key",
                "--amount",
                "300",
                "--fee",
                "5",
            )
            self.assertEqual(batch["input_count"], 2)
            self.assertEqual(len(batch["nullifiers"]), 2)
            self.assertNotIn("spent_note_ids", batch)
            self.assertIn("proof_root", batch["proof_bundle"])

            block = run_json("block", "--state", str(state_path))
            self.assertEqual(block["execution_profile"]["tx_count"], 1)
            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(block["execution_profile"]["authorization_count"], 1)
            self.assertEqual(block["execution_profile"]["observed_fee_units"], 5)

            alice = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            bob = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            carol = run_json("wallet", "--state", str(state_path), "--owner", "carol-view-key")
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(note_amounts(alice, asset["asset_id"]), [995])
            self.assertEqual(note_amounts(bob, asset["asset_id"]), [200])
            self.assertEqual(note_amounts(carol, asset["asset_id"]), [300])
            self.assertEqual(snapshot["spent_nullifier_count"], 2)

    def test_cli_persistent_validator_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            validator = run_json(
                "validator-add",
                "--state",
                str(state_path),
                "--label",
                "validator-two",
                "--stake",
                "2500",
            )
            self.assertEqual(validator["stake"], 2500)

            validators = run_json("validators", "--state", str(state_path))
            self.assertEqual(len(validators), 2)

            block = run_json(
                "block",
                "--state",
                str(state_path),
                "--proposer",
                "validator-two",
            )
            self.assertEqual(block["proposer_id"], validator["validator_id"])
            self.assertEqual(block["validator_vote_count"], 2)
            self.assertEqual(block["validator_stake_weight"], 3500)
            self.assertTrue(block["soft_finality"])

            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(snapshot["validator_count"], 2)

    def test_cli_persistent_account_rotation_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            account = run_json(
                "account-register",
                "--state",
                str(state_path),
                "--label",
                "cli-alice-v1",
            )
            session = run_json(
                "session-open",
                "--state",
                str(state_path),
                "--account-id",
                account["account_id"],
                "--signer",
                "cli-alice-v1",
                "--relay-path",
                "i2p-fluff",
                "--expires-in-blocks",
                "5",
            )
            self.assertEqual(session["account_id"], account["account_id"])
            self.assertEqual(session["status"], "active")
            self.assertRelayMetadata(session, policy="i2p", raw_path="i2p-fluff")
            self.assertNotIn("cli-alice-v1", json.dumps(session))
            session_status = run_json(
                "session-status",
                "--state",
                str(state_path),
                "--session-id",
                session["session_id"],
            )
            self.assertEqual(session_status["status"], "active")
            self.assertEqual(session_status["session"]["session_id"], session["session_id"])
            self.assertRelayMetadata(
                session_status["session"],
                policy="i2p",
                raw_path="i2p-fluff",
            )
            sessions = run_json("sessions", "--state", str(state_path))
            self.assertEqual(sessions["wallet_session_count"], 1)
            self.assertEqual(sessions["sessions"][0]["session_id"], session["session_id"])
            self.assertRelayMetadata(
                sessions["sessions"][0],
                policy="i2p",
                raw_path="i2p-fluff",
            )
            self.assertNotIn("cli-alice-v1", json.dumps(sessions))

            rotation = run_json(
                "account-rotate",
                "--state",
                str(state_path),
                "--account-id",
                account["account_id"],
                "--new-label",
                "cli-alice-v2",
                "--recovery-label",
                "cli-alice-v1",
            )
            self.assertEqual(rotation["recovery_scheme"], devnet.RECOVERY_SIGNATURE_SCHEME)
            self.assertNotIn("new_label", rotation)

            block = run_json("block", "--state", str(state_path))
            accounts = run_json("accounts", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(block["execution_profile"]["tx_count"], 1)
            self.assertEqual(block["account_root"], snapshot["account_root"])
            self.assertEqual(accounts[0]["rotation_nonce"], 1)
            self.assertEqual(snapshot["account_count"], 1)
            self.assertEqual(snapshot["wallet_session_count"], 1)
            revoked = run_json(
                "session-status",
                "--state",
                str(state_path),
                "--session-id",
                session["session_id"],
            )
            self.assertEqual(revoked["status"], "revoked")

    def test_cli_persistent_contract_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            fee_asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DFEE",
                "--issuer-policy",
                "devnet-fee-issuer",
            )
            fee_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "bob-view-key",
                "--amount",
                "10",
            )
            contract = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "counter",
                "--owner",
                "alice-view-key",
                "--fuel-limit",
                "100",
            )
            call = run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--entrypoint",
                "increment",
                "--args-json",
                '{"amount": 11}',
                "--signer",
                "bob-view-key",
                "--fuel-limit",
                "20",
                "--fee-asset-id",
                fee_asset["asset_id"],
                "--fee-note-id",
                fee_note["note_id"],
                "--max-fee",
                "1",
            )
            self.assertEqual(call["entrypoint"], "increment")
            self.assertEqual(call["fuel_used"], 12)
            self.assertEqual(call["fee_asset_id"], fee_asset["asset_id"])
            self.assertEqual(call["fee"], 1)
            self.assertTrue(call["fee_nullifier"])
            self.assertIn("proof_root", call["proof_bundle"])
            self.assertNotIn("fee_note_id", call)
            self.assertTrue(call["auth_signature"])

            block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            contract_events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            contract_receipts = run_json(
                "contract-execution-receipts",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(contracts[0]["storage"]["count"], 11)
            self.assertEqual(contracts[0]["storage"]["last_caller"], "bob-view-key")
            self.assertEqual(snapshot["contract_count"], 1)
            self.assertEqual(snapshot["contract_event_count"], 1)
            self.assertEqual(snapshot["contract_execution_receipt_count"], 1)
            self.assertEqual(
                contract_events["contract_event_root"],
                snapshot["contract_event_root"],
            )
            self.assertEqual(
                contract_receipts["contract_execution_receipt_root"],
                snapshot["contract_execution_receipt_root"],
            )
            self.assertEqual(contract_events["filtered_event_count"], 1)
            self.assertEqual(contract_receipts["filtered_receipt_count"], 1)
            self.assertEqual(
                contract_events["events"][0]["event_name"],
                "counter.incremented",
            )
            self.assertEqual(
                contract_events["events"][0]["previous_event_root"],
                devnet.merkle_root("CONTRACT-EVENT", []),
            )
            self.assertEqual(len(contract_events["events"][0]["event_chain_root"]), 64)
            self.assertEqual(contract_events["events"][0]["public_data"]["amount"], 11)
            self.assertEqual(contract_events["events"][0]["public_data"]["new_count"], 11)
            self.assertEqual(
                contract_receipts["receipts"][0]["event_id"],
                contract_events["events"][0]["event_id"],
            )
            self.assertEqual(contract_receipts["receipts"][0]["entrypoint"], "increment")
            self.assertEqual(contract_receipts["receipts"][0]["tx_index"], 0)
            self.assertEqual(contract_receipts["receipts"][0]["fuel_used"], 12)
            self.assertEqual(
                contract_receipts["receipts"][0]["args_commitment"],
                call["args_commitment"],
            )
            self.assertNotIn("args", contract_receipts["receipts"][0])
            self.assertNotIn("bob-view-key", json.dumps(contract_events))
            self.assertNotIn("bob-view-key", json.dumps(contract_receipts))
            self.assertEqual(len(block["contract_root"]), 64)
            self.assertEqual(block["execution_profile"]["execution_fuel"], 12)
            self.assertEqual(block["execution_profile"]["observed_fee_units"], 1)
            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)
            bob = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            self.assertEqual(note_amounts(bob, fee_asset["asset_id"]), [9])

            contract_deposit = run_json(
                "contract-deposit",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--spent-note-id",
                bob[0]["note_id"],
                "--amount",
                "5",
                "--network-fee",
                "1",
            )
            self.assertEqual(contract_deposit["kind"], "contract_deposit")
            self.assertNotIn("spent_note_id", contract_deposit)
            self.assertNotIn("bob-view-key", json.dumps(contract_deposit))
            self.assertIn("proof_root", contract_deposit["proof_bundle"])

            deposit_block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            contract_events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            bob = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            self.assertEqual(contracts[0]["asset_balances"][fee_asset["asset_id"]], 5)
            self.assertEqual(note_amounts(bob, fee_asset["asset_id"]), [3])
            self.assertEqual(deposit_block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(deposit_block["execution_profile"]["observed_fee_units"], 1)
            self.assertEqual(contract_events["contract_event_count"], 2)
            self.assertEqual(
                contract_events["events"][-1]["event_name"],
                "contract.deposited",
            )

            contract_withdraw = run_json(
                "contract-withdraw",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--asset-id",
                fee_asset["asset_id"],
                "--amount",
                "4",
                "--to",
                "carol-view-key",
                "--network-fee",
                "1",
                "--signer",
                "alice-view-key",
            )
            self.assertEqual(contract_withdraw["kind"], "contract_withdraw")
            self.assertNotIn("carol-view-key", json.dumps(contract_withdraw))
            self.assertTrue(contract_withdraw["recipient_commitment"])

            withdraw_block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            contract_events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            carol = run_json("wallet", "--state", str(state_path), "--owner", "carol-view-key")
            self.assertEqual(contracts[0]["asset_balances"].get(fee_asset["asset_id"], 0), 0)
            self.assertEqual(note_amounts(carol, fee_asset["asset_id"]), [4])
            self.assertEqual(withdraw_block["execution_profile"]["privacy_proof_count"], 0)
            self.assertEqual(withdraw_block["execution_profile"]["observed_fee_units"], 1)
            self.assertEqual(contract_events["contract_event_count"], 3)
            self.assertEqual(
                contract_events["events"][-1]["event_name"],
                "contract.withdrawn",
            )
            self.assertNotIn("carol-view-key", json.dumps(contract_events))

            upgrade = run_json(
                "contract-upgrade-propose",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--version",
                "2",
                "--fuel-limit",
                "150",
                "--proposer",
                "alice-view-key",
                "--timelock-blocks",
                "2",
            )
            self.assertEqual(upgrade["status"], "pending")
            self.assertEqual(upgrade["proposed_version"], 2)
            self.assertEqual(upgrade["proposed_fuel_limit"], 150)
            self.assertTrue(upgrade["auth_signature"])

            upgrades = run_json(
                "contract-upgrades",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            self.assertEqual(upgrades["contract_upgrade_count"], 1)
            self.assertEqual(upgrades["filtered_upgrade_count"], 1)
            self.assertEqual(upgrades["proposals"][0]["proposal_id"], upgrade["proposal_id"])

            early_execute = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "contract-upgrade-execute",
                    "--state",
                    str(state_path),
                    "--proposal-id",
                    upgrade["proposal_id"],
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(early_execute.returncode, 0)
            self.assertIn("timelock", early_execute.stderr)

            run_json("block", "--state", str(state_path))
            run_json("block", "--state", str(state_path))
            executed_upgrade = run_json(
                "contract-upgrade-execute",
                "--state",
                str(state_path),
                "--proposal-id",
                upgrade["proposal_id"],
                "--executor",
                "upgrade-keeper",
            )
            self.assertEqual(executed_upgrade["status"], "executed")
            self.assertEqual(executed_upgrade["executed_at_height"], upgrade["executable_at_height"])
            contracts = run_json("contracts", "--state", str(state_path))
            counter_state = next(
                item for item in contracts if item["contract_id"] == contract["contract_id"]
            )
            self.assertEqual(counter_state["version"], 2)
            self.assertEqual(counter_state["fuel_limit"], 150)
            self.assertEqual(counter_state["code_hash"], upgrade["proposed_code_hash"])
            contract_events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            self.assertEqual(
                contract_events["events"][-1]["event_name"],
                "contract.upgraded",
            )
            self.assertEqual(
                contract_events["events"][-1]["public_data"]["new_fuel_limit"],
                150,
            )
            self.assertNotIn("upgrade-keeper", json.dumps(contract_events))
            executed_upgrades = run_json(
                "contract-upgrades",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(snapshot["contract_upgrade_count"], 1)
            self.assertEqual(
                snapshot["contract_upgrade_root"],
                executed_upgrades["contract_upgrade_root"],
            )

            governor = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "governor",
                "--owner",
                "dao-owner-key",
                "--fuel-limit",
                "300",
            )
            description_hash = devnet.domain_hash("CLI-DAO-DESCRIPTION", "list DUSD market")
            action_hash = devnet.domain_hash("CLI-DAO-ACTION", "add-market-risk-v1")
            run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                governor["contract_id"],
                "--entrypoint",
                "propose",
                "--args-json",
                json.dumps({
                    "description_hash": description_hash,
                    "action_hash": action_hash,
                    "voting_period_blocks": 1,
                    "quorum": 1,
                }),
                "--signer",
                "alice-voter-key",
                "--fuel-limit",
                "100",
            )
            run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            governor_state = next(
                item for item in contracts if item["contract_id"] == governor["contract_id"]
            )
            proposal_id = next(iter(governor_state["storage"]["proposals"]))
            proposal = governor_state["storage"]["proposals"][proposal_id]
            self.assertEqual(proposal["description_hash"], description_hash)
            self.assertEqual(
                proposal["proposer_commitment"],
                devnet.domain_hash("CONTRACT-CALLER", "alice-voter-key"),
            )
            self.assertNotIn("alice-voter-key", json.dumps(governor_state))

            run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                governor["contract_id"],
                "--entrypoint",
                "vote",
                "--args-json",
                json.dumps({
                    "proposal_id": proposal_id,
                    "support": True,
                    "weight": 1,
                }),
                "--signer",
                "bob-voter-key",
                "--fuel-limit",
                "80",
            )
            run_json("block", "--state", str(state_path))
            run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                governor["contract_id"],
                "--entrypoint",
                "execute",
                "--args-json",
                json.dumps({"proposal_id": proposal_id}),
                "--signer",
                "keeper-key",
                "--fuel-limit",
                "80",
            )
            run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            governor_state = next(
                item for item in contracts if item["contract_id"] == governor["contract_id"]
            )
            proposal = governor_state["storage"]["proposals"][proposal_id]
            self.assertEqual(proposal["status"], "executed")
            self.assertEqual(proposal["outcome"], "passed")
            self.assertEqual(proposal["yes_weight"], 1)
            self.assertNotIn("bob-voter-key", json.dumps(governor_state))
            governor_events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                governor["contract_id"],
            )
            self.assertEqual(
                [event["event_name"] for event in governor_events["events"][-3:]],
                ["governor.proposed", "governor.voted", "governor.executed"],
            )
            self.assertNotIn("alice-voter-key", json.dumps(governor_events))
            self.assertNotIn("bob-voter-key", json.dumps(governor_events))
            self.assertNotIn("keeper-key", json.dumps(governor_events))

            vault = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "vault",
                "--owner",
                "alice-view-key",
                "--fuel-limit",
                "300",
            )
            vault_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "20",
            )
            run_json(
                "contract-deposit",
                "--state",
                str(state_path),
                "--contract-id",
                vault["contract_id"],
                "--spent-note-id",
                vault_note["note_id"],
                "--amount",
                "15",
                "--network-fee",
                "1",
            )
            run_json("block", "--state", str(state_path))
            bob_commitment = devnet.domain_hash("CONTRACT-CALLER", "bob-vault-key")
            grant = run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                vault["contract_id"],
                "--entrypoint",
                "grant",
                "--args-json",
                json.dumps({
                    "asset_id": fee_asset["asset_id"],
                    "beneficiary_commitment": bob_commitment,
                    "amount": 8,
                }),
                "--signer",
                "alice-view-key",
                "--fuel-limit",
                "200",
            )
            self.assertEqual(grant["entrypoint"], "grant")
            run_json("block", "--state", str(state_path))
            vault_withdraw = run_json(
                "contract-withdraw",
                "--state",
                str(state_path),
                "--contract-id",
                vault["contract_id"],
                "--asset-id",
                fee_asset["asset_id"],
                "--amount",
                "6",
                "--to",
                "bob-vault-key",
                "--network-fee",
                "1",
                "--signer",
                "bob-vault-key",
            )
            self.assertNotIn("bob-vault-key", json.dumps(vault_withdraw))
            run_json("block", "--state", str(state_path))
            vaults = run_json("contracts", "--state", str(state_path))
            vault_state = next(item for item in vaults if item["contract_id"] == vault["contract_id"])
            allowance_key = devnet.domain_hash(
                "VAULT-ALLOWANCE",
                fee_asset["asset_id"],
                bob_commitment,
            )
            expected_allowance_commitment = devnet.domain_hash(
                "VAULT-ALLOWANCE-COMMITMENT",
                {
                    "asset_id": fee_asset["asset_id"],
                    "beneficiary_commitment": bob_commitment,
                    "amount": 1,
                },
            )
            self.assertEqual(
                vault_state["storage"]["allowances"][allowance_key]["amount"],
                1,
            )
            self.assertEqual(
                vault_state["storage"]["allowances"][allowance_key]["allowance_commitment"],
                expected_allowance_commitment,
            )
            self.assertEqual(len(vault_state["storage"]["allowance_root"]), 64)
            self.assertEqual(vault_state["asset_balances"][fee_asset["asset_id"]], 8)
            bob_vault = run_json("wallet", "--state", str(state_path), "--owner", "bob-vault-key")
            self.assertEqual(note_amounts(bob_vault, fee_asset["asset_id"]), [6])

    def test_cli_persistent_private_contract_storage_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            contract = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "counter",
                "--owner",
                "alice-view-key",
                "--fuel-limit",
                "100",
                "--private-storage",
            )
            self.assertTrue(contract["private_storage"])
            self.assertNotIn("storage", contract)
            self.assertEqual(len(contract["storage_root"]), 64)

            call = run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--entrypoint",
                "increment",
                "--args-json",
                '{"amount": 9}',
                "--private-args",
                "--signer",
                "bob-view-key",
                "--fuel-limit",
                "20",
            )
            self.assertTrue(call["private_args"])
            self.assertNotIn("args", call)
            self.assertIn("proof_root", call["proof_bundle"])
            block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            public_contract = next(
                item for item in contracts if item["contract_id"] == contract["contract_id"]
            )
            snapshot_contract = next(
                item
                for item in snapshot["contracts"]
                if item["contract_id"] == contract["contract_id"]
            )
            self.assertNotIn("storage", public_contract)
            self.assertNotIn("storage", snapshot_contract)
            self.assertEqual(public_contract["storage_root"], snapshot_contract["storage_root"])
            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(events["events"][0]["public_data"]["args_commitment"], call["args_commitment"])
            self.assertTrue(events["events"][0]["public_data"]["private_args"])
            public_dump = json.dumps({
                "block": block,
                "contracts": contracts,
                "snapshot": snapshot,
                "events": events,
            })
            self.assertNotIn('"storage"', public_dump)
            self.assertNotIn('"args":', public_dump)
            self.assertNotIn('"amount": 9', public_dump)
            self.assertNotIn("bob-view-key", public_dump)

            disclosure = run_json(
                "contract-disclose",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--owner",
                "alice-view-key",
                "--audience",
                "defi-indexer",
                "--path",
                "count",
            )
            self.assertEqual(disclosure["disclosed_owner_label"], "alice-view-key")
            self.assertEqual(disclosure["audience_label"], "defi-indexer")
            self.assertEqual(disclosure["openings"][0]["path"], "count")
            self.assertEqual(disclosure["openings"][0]["value"], 9)
            self.assertEqual(disclosure["storage_root"], public_contract["storage_root"])
            self.assertNotIn("bob-view-key", json.dumps(disclosure))
            self.assertTrue(
                devnet.load_state(state_path).verify_contract_storage_disclosure(disclosure)
            )

            with state_path.open("r", encoding="utf-8") as handle:
                state = json.load(handle)
            persisted_contract = next(
                item
                for item in state["contracts"]
                if item["contract_id"] == contract["contract_id"]
            )
            self.assertEqual(persisted_contract["storage"]["count"], 9)

    def test_cli_persistent_contract_call_batch_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            fee_asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DFEE",
                "--issuer-policy",
                "devnet-fee-issuer",
            )
            fee_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "bob-view-key",
                "--amount",
                "10",
            )
            contract = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "counter",
                "--owner",
                "alice-view-key",
                "--fuel-limit",
                "100",
                "--private-storage",
            )
            calls = [
                {
                    "contract_id": contract["contract_id"],
                    "entrypoint": "increment",
                    "args": {"amount": 3},
                    "fuel_limit": 20,
                    "private_args": True,
                },
                {
                    "contract_id": contract["contract_id"],
                    "entrypoint": "increment",
                    "args": {"amount": 4},
                    "fuel_limit": 20,
                    "private_args": True,
                },
            ]
            quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "contract-call-batch",
                "--input-count",
                "2",
                "--contract-id",
                contract["contract_id"],
                "--contract-fuel",
                "22",
                "--fee-asset-id",
                fee_asset["asset_id"],
                "--private-args",
            )
            self.assertEqual(quote["candidate_profile"]["contract_call_count"], 2)
            self.assertEqual(quote["candidate_profile"]["authorization_count"], 1)
            self.assertEqual(quote["minimum_fee_units"], 1)

            batch = run_json(
                "contract-call-batch",
                "--state",
                str(state_path),
                "--calls-json",
                json.dumps(calls),
                "--signer",
                "bob-view-key",
                "--fee-asset-id",
                fee_asset["asset_id"],
                "--fee-note-id",
                fee_note["note_id"],
                "--max-fee",
                "1",
            )
            self.assertEqual(batch["kind"], "contract_call_batch")
            self.assertEqual(batch["call_count"], 2)
            self.assertEqual(batch["fee"], 1)
            self.assertNotIn("fee_note_id", batch)
            self.assertTrue(all("args" not in call for call in batch["calls"]))
            self.assertIn("proof_root", batch["proof_bundle"])

            block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            receipts = run_json(
                "contract-execution-receipts",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            wallet = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            self.assertEqual(block["execution_profile"]["contract_call_count"], 2)
            self.assertEqual(block["execution_profile"]["authorization_count"], 1)
            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(block["execution_profile"]["observed_fee_units"], 1)
            self.assertEqual(note_amounts(wallet, fee_asset["asset_id"]), [9])
            self.assertEqual(events["filtered_event_count"], 2)
            self.assertEqual(receipts["filtered_receipt_count"], 2)
            receipt_rows = sorted(receipts["receipts"], key=lambda item: item["call_index"])
            self.assertEqual(
                [receipt["call_index"] for receipt in receipt_rows],
                [0, 1],
            )
            self.assertEqual(
                [receipt["tx_index"] for receipt in receipt_rows],
                [0, 0],
            )
            self.assertEqual(
                [receipt["args_commitment"] for receipt in receipt_rows],
                [call["args_commitment"] for call in batch["calls"]],
            )
            self.assertNotIn("storage", contracts[0])
            public_dump = json.dumps({
                "batch": batch,
                "block": block,
                "contracts": contracts,
                "events": events,
                "receipts": receipts,
            })
            self.assertNotIn('"args":', public_dump)
            self.assertNotIn('"amount": 3', public_dump)
            self.assertNotIn('"amount": 4', public_dump)
            self.assertNotIn("bob-view-key", public_dump)

    def test_cli_persistent_paymaster_sponsored_contract_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            fee_asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DFEE",
                "--issuer-policy",
                "devnet-fee-issuer",
            )
            sponsor_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "sponsor-view-key",
                "--amount",
                "5",
            )
            contract = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "counter",
                "--owner",
                "alice-view-key",
                "--fuel-limit",
                "100",
            )
            paymaster = run_json(
                "paymaster-create",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--fee-asset-id",
                fee_asset["asset_id"],
                "--sponsor",
                "sponsor-view-key",
                "--per-call-cap",
                "1",
                "--per-caller-cap",
                "2",
                "--allowed-caller",
                "bob-view-key",
                "--allowed-caller",
                "carol-view-key",
            )
            bob_commitment = devnet.paymaster_caller_commitment("bob-view-key")
            carol_commitment = devnet.paymaster_caller_commitment("carol-view-key")
            self.assertEqual(paymaster["balance"], 0)
            self.assertEqual(paymaster["per_call_cap"], 1)
            self.assertEqual(paymaster["per_caller_cap"], 2)
            self.assertEqual(
                paymaster["relayer_reward_units"],
                devnet.PAYMASTER_RELAYER_REFILL_REWARD_UNITS,
            )
            self.assertEqual(paymaster["relayer_reward_budget"], 0)
            self.assertIn(bob_commitment, paymaster["allowed_caller_commitments"])
            self.assertIn(carol_commitment, paymaster["allowed_caller_commitments"])
            self.assertNotIn("sponsor-view-key", json.dumps(paymaster))
            self.assertNotIn("bob-view-key", json.dumps(paymaster))
            self.assertNotIn("carol-view-key", json.dumps(paymaster))
            deposit = run_json(
                "paymaster-deposit",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--spent-note-id",
                sponsor_note["note_id"],
                "--amount",
                "3",
            )
            self.assertEqual(deposit["kind"], "paymaster_deposit")
            self.assertNotIn("spent_note_id", deposit)
            self.assertIn("proof_root", deposit["proof_bundle"])
            deposit_block = run_json("block", "--state", str(state_path))
            self.assertEqual(deposit_block["execution_profile"]["privacy_proof_count"], 1)

            paymasters = run_json("paymasters", "--state", str(state_path))
            self.assertEqual(paymasters["paymasters"][0]["balance"], 3)
            sponsor = run_json("wallet", "--state", str(state_path), "--owner", "sponsor-view-key")
            self.assertEqual(note_amounts(sponsor, fee_asset["asset_id"]), [2])

            call = run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--entrypoint",
                "increment",
                "--args-json",
                '{"amount": 6}',
                "--signer",
                "bob-view-key",
                "--fuel-limit",
                "20",
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--max-fee",
                "1",
            )
            self.assertEqual(call["paymaster_id"], paymaster["paymaster_id"])
            self.assertEqual(call["fee_asset_id"], fee_asset["asset_id"])
            self.assertEqual(call["fee"], 1)
            self.assertFalse(call["fee_nullifier"])
            self.assertIsNone(call["proof_bundle"])
            call_block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            paymasters = run_json("paymasters", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(contracts[0]["storage"]["count"], 6)
            self.assertEqual(contracts[0]["storage"]["last_caller"], "bob-view-key")
            self.assertEqual(paymasters["paymasters"][0]["balance"], 2)
            self.assertEqual(paymasters["paymasters"][0]["spent_amount"], 1)
            self.assertEqual(
                paymasters["paymasters"][0]["spent_by_caller"][bob_commitment],
                1,
            )
            self.assertEqual(snapshot["paymaster_count"], 1)
            self.assertEqual(call_block["execution_profile"]["observed_fee_units"], 1)
            self.assertEqual(call_block["execution_profile"]["privacy_proof_count"], 0)

            quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "contract-call",
                "--contract-id",
                contract["contract_id"],
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--fee-mode",
                "paymaster",
                "--contract-fuel",
                "11",
                "--private-args",
            )
            self.assertTrue(quote["private_args"])
            self.assertEqual(quote["candidate_profile"]["privacy_proof_count"], 1)
            self.assertEqual(quote["minimum_fee_units"], 1)

            private_call = run_json(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--entrypoint",
                "increment",
                "--args-json",
                '{"amount": 5}',
                "--private-args",
                "--signer",
                "carol-view-key",
                "--fuel-limit",
                "20",
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--max-fee",
                "1",
            )
            self.assertTrue(private_call["private_args"])
            self.assertNotIn("args", private_call)
            self.assertIn("args_commitment", private_call)
            self.assertIn("proof_root", private_call["proof_bundle"])

            private_call_block = run_json("block", "--state", str(state_path))
            contracts = run_json("contracts", "--state", str(state_path))
            paymasters = run_json("paymasters", "--state", str(state_path))
            contract_events = run_json(
                "contract-events",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
            )
            self.assertEqual(contracts[0]["storage"]["count"], 11)
            self.assertEqual(paymasters["paymasters"][0]["balance"], 1)
            self.assertEqual(paymasters["paymasters"][0]["spent_amount"], 2)
            self.assertEqual(
                paymasters["paymasters"][0]["spent_by_caller"][bob_commitment],
                1,
            )
            self.assertEqual(
                paymasters["paymasters"][0]["spent_by_caller"][carol_commitment],
                1,
            )
            self.assertEqual(private_call_block["execution_profile"]["observed_fee_units"], 1)
            self.assertEqual(private_call_block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(
                contract_events["events"][-1]["public_data"]["args_commitment"],
                private_call["args_commitment"],
            )
            self.assertTrue(contract_events["events"][-1]["public_data"]["private_args"])
            self.assertNotIn("amount", contract_events["events"][-1]["public_data"])
            self.assertNotIn("new_count", contract_events["events"][-1]["public_data"])
            self.assertNotIn('"args":', json.dumps(private_call_block))

            event_disclosure = run_json(
                "contract-event-disclose",
                "--state",
                str(state_path),
                "--event-id",
                contract_events["events"][-1]["event_id"],
                "--signer",
                "carol-view-key",
                "--audience",
                "defi-indexer",
            )
            self.assertEqual(event_disclosure["audience_label"], "defi-indexer")
            self.assertEqual(
                event_disclosure["event_id"],
                contract_events["events"][-1]["event_id"],
            )
            self.assertEqual(event_disclosure["opening"]["args"], {"amount": 5})
            self.assertEqual(
                event_disclosure["args_commitment"],
                private_call["args_commitment"],
            )
            self.assertTrue(
                devnet.load_state(state_path).verify_contract_event_disclosure(
                    event_disclosure
                )
            )

    def test_cli_persistent_paymaster_governance_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            def run_raw(*args: str):
                return subprocess.run(
                    [sys.executable, str(script), *args],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            run_json("init", "--state", str(state_path))
            fee_asset = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DFEE",
                "--issuer-policy",
                "devnet-fee-issuer",
            )
            sponsor_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "sponsor-view-key",
                "--amount",
                "1",
            )
            refill_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "sponsor-view-key",
                "--amount",
                "5",
            )
            expired_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "sponsor-view-key",
                "--amount",
                "1",
            )
            slash_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "sponsor-view-key",
                "--amount",
                "1",
            )
            slash_bond_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "slash-relayer",
                "--amount",
                "3",
            )
            refill_bond_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                fee_asset["asset_id"],
                "--owner",
                "refill-relayer",
                "--amount",
                "2",
            )
            contract = run_json(
                "contract-deploy",
                "--state",
                str(state_path),
                "--template",
                "counter",
                "--owner",
                "alice-view-key",
                "--fuel-limit",
                "100",
            )
            paymaster = run_json(
                "paymaster-create",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--fee-asset-id",
                fee_asset["asset_id"],
                "--sponsor",
                "sponsor-view-key",
                "--replenish-threshold",
                "1",
                "--replenish-target",
                "4",
            )
            self.assertEqual(paymaster["replenish_threshold"], 1)
            self.assertEqual(paymaster["replenish_target"], 4)
            run_json(
                "paymaster-deposit",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--spent-note-id",
                sponsor_note["note_id"],
                "--amount",
                "1",
            )
            run_json("block", "--state", str(state_path))

            pause = run_json(
                "paymaster-pause",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--sponsor",
                "sponsor-view-key",
                "--reason",
                "contract incident",
            )
            self.assertEqual(pause["action"], "pause")
            self.assertEqual(pause["new_status"], "paused")
            self.assertNotIn("sponsor-view-key", json.dumps(pause))
            self.assertNotIn("contract incident", json.dumps(pause))

            failed_call = run_raw(
                "contract-call",
                "--state",
                str(state_path),
                "--contract-id",
                contract["contract_id"],
                "--entrypoint",
                "increment",
                "--args-json",
                '{"amount": 1}',
                "--signer",
                "bob-view-key",
                "--fuel-limit",
                "20",
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--max-fee",
                "1",
            )
            self.assertNotEqual(failed_call.returncode, 0)
            self.assertIn("paymaster is not active", failed_call.stderr)

            resume = run_json(
                "paymaster-resume",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--sponsor",
                "sponsor-view-key",
                "--reason",
                "review complete",
            )
            self.assertEqual(resume["new_status"], "active")
            carol_commitment = devnet.paymaster_caller_commitment("carol-view-key")
            policy = run_json(
                "paymaster-policy",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--sponsor",
                "sponsor-view-key",
                "--per-call-cap",
                "1",
                "--per-caller-cap",
                "1",
                "--allowed-caller",
                "carol-view-key",
                "--replenish-threshold",
                "2",
                "--replenish-target",
                "6",
                "--relayer-reward-units",
                "1",
                "--relayer-reward-budget",
                "2",
            )
            self.assertEqual(policy["action"], "update_policy")
            self.assertIn(carol_commitment, policy["allowed_caller_commitments"])
            self.assertEqual(policy["relayer_reward_units"], 1)
            self.assertEqual(policy["relayer_reward_budget"], 2)
            self.assertNotIn("carol-view-key", json.dumps(policy))
            refill_plan = run_json(
                "paymaster-refill-plan",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
            )
            self.assertTrue(refill_plan["needs_refill"])
            self.assertEqual(refill_plan["refill_amount"], 5)
            self.assertEqual(refill_plan["next_relayer_reward_units"], 1)
            self.assertEqual(refill_plan["relayer_reward_budget_remaining"], 2)
            refill_bond = run_json(
                "paymaster-relayer-bond",
                "--state",
                str(state_path),
                "--spent-note-id",
                refill_bond_note["note_id"],
                "--relayer",
                "refill-relayer",
                "--amount",
                "2",
            )
            self.assertEqual(refill_bond["active_amount"], 2)
            self.assertNotIn("refill-relayer", json.dumps(refill_bond))
            routed_candidates = run_json(
                "paymaster-relayer-select",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
            )
            self.assertEqual(routed_candidates["candidate_count"], 1)
            self.assertEqual(routed_candidates["next_relayer_reward_units"], 1)
            self.assertEqual(routed_candidates["relayer_reward_budget_remaining"], 2)
            self.assertEqual(
                routed_candidates["candidates"][0]["relayer_commitment"],
                devnet.paymaster_relayer_commitment("refill-relayer"),
            )
            authorization = run_json(
                "paymaster-refill-route-authorize",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--spent-note-id",
                refill_note["note_id"],
                "--sponsor",
                "sponsor-view-key",
                "--max-amount",
                "5",
                "--expires-in-blocks",
                "5",
            )
            self.assertEqual(authorization["status"], "open")
            self.assertEqual(authorization["max_refill_amount"], 5)
            self.assertNotIn("sponsor-view-key", json.dumps(authorization))
            self.assertNotIn("refill-relayer", json.dumps(authorization))
            refill = run_json(
                "paymaster-refill",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--spent-note-id",
                refill_note["note_id"],
                "--authorization-id",
                authorization["authorization_id"],
                "--relayer",
                "refill-relayer",
            )
            self.assertEqual(refill["amount"], 5)
            self.assertEqual(
                refill["refill_authorization_id"],
                authorization["authorization_id"],
            )
            self.assertEqual(
                refill["refill_relayer_commitment"],
                devnet.paymaster_relayer_commitment("refill-relayer"),
            )
            refill_rewards = run_json(
                "paymaster-relayer-bonds",
                "--state",
                str(state_path),
                "--relayer-commitment",
                devnet.paymaster_relayer_commitment("refill-relayer"),
            )
            self.assertEqual(refill_rewards["filtered_reward_count"], 1)
            self.assertEqual(
                refill_rewards["reward_receipts"][0]["authorization_id"],
                authorization["authorization_id"],
            )
            self.assertEqual(refill_rewards["reward_receipts"][0]["budget_units_before"], 0)
            self.assertEqual(refill_rewards["reward_receipts"][0]["budget_units_after"], 1)
            self.assertEqual(refill_rewards["reward_receipts"][0]["reward_budget"], 2)
            self.assertTrue(refill_rewards["reward_receipts"][0]["budget_proof_root"])
            run_json("block", "--state", str(state_path))
            claim_quote = run_json(
                "paymaster-relayer-reward-claim-quote",
                "--state",
                str(state_path),
                "--reward-id",
                refill_rewards["reward_receipts"][0]["reward_id"],
                "--relayer",
                "refill-relayer",
                "--expires-in-blocks",
                "2",
                "--inclusion-deadline-blocks",
                "2",
            )
            self.assertEqual(claim_quote["claim_count"], 1)
            self.assertEqual(claim_quote["total_claimed_amount"], 1)
            self.assertEqual(
                claim_quote["max_bundle_size"],
                devnet.PAYMASTER_RELAYER_REWARD_CLAIM_BUNDLE_MAX_ITEMS,
            )
            self.assertEqual(
                claim_quote["expires_at_height"],
                claim_quote["claimed_at_height"] + 2,
            )
            self.assertEqual(
                claim_quote["inclusion_deadline_height"],
                claim_quote["claimed_at_height"] + 2,
            )
            self.assertEqual(claim_quote["requote_backoff_score"], 0)
            self.assertEqual(claim_quote["requote_after_height"], claim_quote["claimed_at_height"])
            self.assertTrue(claim_quote["requote_allowed"])
            self.assertTrue(claim_quote["quote_root"])
            self.assertNotIn("refill-relayer", json.dumps(claim_quote))
            pre_claim_monitor = run_json(
                "paymaster-relayer-reward-settlement-monitor",
                "--state",
                str(state_path),
                "--relayer-commitment",
                devnet.paymaster_relayer_commitment("refill-relayer"),
                "--quote-json",
                json.dumps(claim_quote),
            )
            self.assertEqual(pre_claim_monitor["claimable_reward_count"], 1)
            self.assertEqual(pre_claim_monitor["settled_bundle_count"], 0)
            self.assertEqual(pre_claim_monitor["quote_invalidation_report_count"], 0)
            self.assertEqual(
                pre_claim_monitor["quote_observations"][0]["reason_code"],
                "open",
            )
            self.assertEqual(
                pre_claim_monitor["quote_observations"][0]["blocks_until_inclusion_deadline"],
                2,
            )
            claimed_bundle = run_json(
                "paymaster-relayer-reward-claim-batch",
                "--state",
                str(state_path),
                "--reward-id",
                refill_rewards["reward_receipts"][0]["reward_id"],
                "--relayer",
                "refill-relayer",
                "--expires-in-blocks",
                "2",
                "--inclusion-deadline-blocks",
                "2",
            )
            self.assertEqual(claimed_bundle["claim_count"], 1)
            self.assertEqual(claimed_bundle["total_claimed_amount"], 1)
            self.assertEqual(claimed_bundle["quote_root"], claim_quote["quote_root"])
            self.assertEqual(
                claimed_bundle["expires_at_height"],
                claim_quote["expires_at_height"],
            )
            self.assertEqual(
                claimed_bundle["inclusion_deadline_height"],
                claim_quote["inclusion_deadline_height"],
            )
            self.assertEqual(
                claimed_bundle["requote_backoff_score"],
                claim_quote["requote_backoff_score"],
            )
            self.assertEqual(
                claimed_bundle["estimated_fee_units"],
                claim_quote["estimated_fee_units"],
            )
            self.assertEqual(
                claimed_bundle["estimated_proof_bytes"],
                claim_quote["estimated_proof_bytes"],
            )
            self.assertEqual(
                claimed_bundle["estimated_da_bytes"],
                claim_quote["estimated_da_bytes"],
            )
            self.assertTrue(claimed_bundle["bundle_proof_root"])
            self.assertNotIn("refill-relayer", json.dumps(claimed_bundle))
            quote_invalidation = run_json(
                "paymaster-relayer-reward-quote-invalidate",
                "--state",
                str(state_path),
                "--quote-json",
                json.dumps(claim_quote),
                "--reporter",
                "quote-watchtower",
            )
            self.assertEqual(quote_invalidation["reason_code"], "settled")
            self.assertEqual(quote_invalidation["settled_bundle_id"], claimed_bundle["bundle_id"])
            self.assertNotIn("quote-watchtower", json.dumps(quote_invalidation))
            self.assertNotIn("refill-relayer", json.dumps(quote_invalidation))
            post_claim_monitor = run_json(
                "paymaster-relayer-reward-settlement-monitor",
                "--state",
                str(state_path),
                "--relayer-commitment",
                devnet.paymaster_relayer_commitment("refill-relayer"),
                "--quote-json",
                json.dumps(claim_quote),
            )
            self.assertEqual(post_claim_monitor["claimable_reward_count"], 0)
            self.assertEqual(post_claim_monitor["claimed_reward_count"], 1)
            self.assertEqual(post_claim_monitor["settled_bundle_count"], 1)
            self.assertEqual(post_claim_monitor["quote_invalidation_report_count"], 1)
            self.assertEqual(
                post_claim_monitor["quote_observations"][0]["reason_code"],
                "settled",
            )
            claimed_rewards = run_json(
                "paymaster-relayer-bonds",
                "--state",
                str(state_path),
                "--relayer-commitment",
                devnet.paymaster_relayer_commitment("refill-relayer"),
            )
            self.assertEqual(claimed_rewards["filtered_reward_claim_bundle_count"], 1)
            self.assertEqual(claimed_rewards["filtered_quote_invalidation_count"], 1)
            self.assertEqual(
                claimed_rewards["reward_receipts"][0]["claim_bundle_id"],
                claimed_bundle["bundle_id"],
            )
            self.assertEqual(
                claimed_rewards["reward_receipts"][0]["claim_proof_root"],
                claimed_bundle["bundle_proof_root"],
            )
            duplicate_reward_claim = run_raw(
                "paymaster-relayer-reward-claim",
                "--state",
                str(state_path),
                "--reward-id",
                refill_rewards["reward_receipts"][0]["reward_id"],
                "--relayer",
                "refill-relayer",
            )
            self.assertNotEqual(duplicate_reward_claim.returncode, 0)
            self.assertIn("not claimable", duplicate_reward_claim.stderr)
            refill_wallet = run_json(
                "wallet",
                "--state",
                str(state_path),
                "--owner",
                "refill-relayer",
            )
            self.assertEqual(note_amounts(refill_wallet, fee_asset["asset_id"]), [1])
            expired_authorization = run_json(
                "paymaster-refill-authorize",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--spent-note-id",
                expired_note["note_id"],
                "--sponsor",
                "sponsor-view-key",
                "--relayer",
                "slow-relayer",
                "--max-amount",
                "1",
                "--expires-in-blocks",
                "1",
            )
            early_failure = run_raw(
                "paymaster-refill-failure",
                "--state",
                str(state_path),
                "--authorization-id",
                expired_authorization["authorization_id"],
                "--reporter",
                "sponsor-view-key",
                "--evidence",
                "too early",
            )
            self.assertNotEqual(early_failure.returncode, 0)
            self.assertIn("not expired", early_failure.stderr)
            run_json("block", "--state", str(state_path))
            run_json("block", "--state", str(state_path))
            failure = run_json(
                "paymaster-refill-failure",
                "--state",
                str(state_path),
                "--authorization-id",
                expired_authorization["authorization_id"],
                "--reporter",
                "sponsor-view-key",
                "--evidence",
                "relayer missed refill window",
            )
            self.assertEqual(failure["reason_code"], "expired")
            self.assertNotIn("sponsor-view-key", json.dumps(failure))
            self.assertNotIn("relayer missed refill window", json.dumps(failure))
            challenge = run_json(
                "paymaster-refill-challenge",
                "--state",
                str(state_path),
                "--receipt-id",
                failure["receipt_id"],
                "--relayer",
                "slow-relayer",
                "--evidence",
                "relayer has private delivery proof",
            )
            self.assertEqual(challenge["receipt_id"], failure["receipt_id"])
            self.assertNotIn("slow-relayer", json.dumps(challenge))
            self.assertNotIn("private delivery proof", json.dumps(challenge))
            challenged_slash = run_raw(
                "paymaster-refill-slash",
                "--state",
                str(state_path),
                "--receipt-id",
                failure["receipt_id"],
                "--reporter",
                "sponsor-view-key",
            )
            self.assertNotEqual(challenged_slash.returncode, 0)
            self.assertIn("not open", challenged_slash.stderr)
            bond = run_json(
                "paymaster-relayer-bond",
                "--state",
                str(state_path),
                "--spent-note-id",
                slash_bond_note["note_id"],
                "--relayer",
                "slash-relayer",
                "--amount",
                "3",
            )
            self.assertEqual(bond["active_amount"], 3)
            self.assertNotIn("slash-relayer", json.dumps(bond))
            slash_authorization = run_json(
                "paymaster-refill-authorize",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--spent-note-id",
                slash_note["note_id"],
                "--sponsor",
                "sponsor-view-key",
                "--relayer",
                "slash-relayer",
                "--max-amount",
                "1",
                "--expires-in-blocks",
                "1",
            )
            run_json("block", "--state", str(state_path))
            run_json("block", "--state", str(state_path))
            slash_failure = run_json(
                "paymaster-refill-failure",
                "--state",
                str(state_path),
                "--authorization-id",
                slash_authorization["authorization_id"],
                "--reporter",
                "sponsor-view-key",
                "--evidence",
                "relayer stayed offline",
            )
            early_slash = run_raw(
                "paymaster-refill-slash",
                "--state",
                str(state_path),
                "--receipt-id",
                slash_failure["receipt_id"],
                "--reporter",
                "sponsor-view-key",
            )
            self.assertNotEqual(early_slash.returncode, 0)
            self.assertIn("challenge window is still open", early_slash.stderr)
            for _ in range(devnet.PAYMASTER_REFILL_FAILURE_CHALLENGE_BLOCKS + 1):
                run_json("block", "--state", str(state_path))
            slash_hook = run_json(
                "paymaster-refill-slash",
                "--state",
                str(state_path),
                "--receipt-id",
                slash_failure["receipt_id"],
                "--reporter",
                "sponsor-view-key",
                "--penalty-units",
                "2",
            )
            self.assertEqual(slash_hook["receipt_id"], slash_failure["receipt_id"])
            self.assertEqual(slash_hook["penalty_units"], 2)
            self.assertNotIn("sponsor-view-key", json.dumps(slash_hook))
            settlement = run_json(
                "paymaster-refill-slash-settle",
                "--state",
                str(state_path),
                "--hook-id",
                slash_hook["hook_id"],
                "--reporter",
                "sponsor-view-key",
            )
            self.assertEqual(settlement["hook_id"], slash_hook["hook_id"])
            self.assertEqual(settlement["status"], "settled")
            self.assertEqual(settlement["slashed_amount"], 2)
            self.assertEqual(settlement["remaining_penalty_units"], 0)
            self.assertNotIn("sponsor-view-key", json.dumps(settlement))
            duplicate_settlement = run_raw(
                "paymaster-refill-slash-settle",
                "--state",
                str(state_path),
                "--hook-id",
                slash_hook["hook_id"],
                "--reporter",
                "sponsor-view-key",
            )
            self.assertNotEqual(duplicate_settlement.returncode, 0)
            self.assertIn("already settled", duplicate_settlement.stderr)
            candidates = run_json(
                "paymaster-relayer-select",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
            )
            self.assertEqual(candidates["candidate_count"], 2)
            self.assertEqual(
                candidates["candidates"][0]["relayer_commitment"],
                devnet.paymaster_relayer_commitment("refill-relayer"),
            )
            self.assertEqual(candidates["candidates"][0]["reward_units"], 1)
            slash_candidate = next(
                row
                for row in candidates["candidates"]
                if row["relayer_commitment"]
                == devnet.paymaster_relayer_commitment("slash-relayer")
            )
            self.assertEqual(slash_candidate["selectable_bond_amount"], 1)
            unbond = run_json(
                "paymaster-relayer-unbond",
                "--state",
                str(state_path),
                "--bond-id",
                bond["bond_id"],
                "--relayer",
                "slash-relayer",
                "--amount",
                "1",
            )
            self.assertEqual(unbond["status"], "pending")
            self.assertNotIn("slash-relayer", json.dumps(unbond))
            self.assertEqual(
                unbond["available_at_height"],
                unbond["requested_at_height"]
                + devnet.PAYMASTER_RELAYER_UNBOND_DELAY_BLOCKS,
            )
            pending_candidates = run_json(
                "paymaster-relayer-select",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
            )
            self.assertEqual(pending_candidates["candidate_count"], 1)
            self.assertEqual(
                pending_candidates["candidates"][0]["relayer_commitment"],
                devnet.paymaster_relayer_commitment("refill-relayer"),
            )
            early_claim = run_raw(
                "paymaster-relayer-unbond-claim",
                "--state",
                str(state_path),
                "--request-id",
                unbond["request_id"],
                "--relayer",
                "slash-relayer",
            )
            self.assertNotEqual(early_claim.returncode, 0)
            self.assertIn("not available", early_claim.stderr)
            for _ in range(devnet.PAYMASTER_RELAYER_UNBOND_DELAY_BLOCKS):
                run_json("block", "--state", str(state_path))
            claimed_unbond = run_json(
                "paymaster-relayer-unbond-claim",
                "--state",
                str(state_path),
                "--request-id",
                unbond["request_id"],
                "--relayer",
                "slash-relayer",
            )
            self.assertEqual(claimed_unbond["status"], "claimed")
            self.assertEqual(claimed_unbond["claimed_amount"], 1)
            self.assertTrue(claimed_unbond["claim_note_commitment"])
            slash_wallet = run_json(
                "wallet",
                "--state",
                str(state_path),
                "--owner",
                "slash-relayer",
            )
            self.assertEqual(note_amounts(slash_wallet, fee_asset["asset_id"]), [1])
            reputation = run_json("paymaster-refill-reputation", "--state", str(state_path))
            self.assertEqual(reputation["paymaster_refill_failure_count"], 2)
            self.assertEqual(reputation["paymaster_relayer_bond_count"], 2)
            self.assertEqual(reputation["paymaster_relayer_slash_settlement_count"], 1)
            self.assertEqual(reputation["paymaster_relayer_unbond_request_count"], 1)
            self.assertEqual(reputation["paymaster_relayer_reward_count"], 1)
            self.assertEqual(reputation["relayer_count"], 3)
            fast = next(
                row
                for row in reputation["relayers"]
                if row["relayer_commitment"]
                == devnet.paymaster_relayer_commitment("refill-relayer")
            )
            slow = next(
                row
                for row in reputation["relayers"]
                if row["relayer_commitment"]
                == devnet.paymaster_relayer_commitment("slow-relayer")
            )
            slash = next(
                row
                for row in reputation["relayers"]
                if row["relayer_commitment"]
                == devnet.paymaster_relayer_commitment("slash-relayer")
            )
            self.assertEqual(fast["reward_units"], 1)
            self.assertEqual(fast["claimed_reward_units"], 1)
            self.assertEqual(fast["claimable_reward_units"], 0)
            self.assertEqual(fast["selectable_bond_amount"], 2)
            self.assertEqual(slow["challenged_count"], 1)
            self.assertEqual(slash["slashable_count"], 1)
            self.assertEqual(slash["penalty_units"], 2)
            self.assertEqual(slash["bonded_amount"], 3)
            self.assertEqual(slash["active_bond_amount"], 0)
            self.assertEqual(slash["pending_unbond_amount"], 0)
            self.assertEqual(slash["selectable_bond_amount"], 0)
            self.assertEqual(slash["settled_slashed_amount"], 2)
            self.assertEqual(slash["withdrawn_bond_amount"], 1)
            self.assertEqual(slash["unsettled_penalty_units"], 0)
            close = run_json(
                "paymaster-close",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
                "--sponsor",
                "sponsor-view-key",
                "--reason",
                "retire budget",
            )
            self.assertEqual(close["action"], "close")
            self.assertEqual(close["new_status"], "closed")
            self.assertEqual(close["refund_amount"], 5)
            self.assertTrue(close["refund_note_commitment"])
            self.assertNotIn("retire budget", json.dumps(close))

            paymasters = run_json("paymasters", "--state", str(state_path))
            self.assertEqual(paymasters["paymaster_governance_action_count"], 4)
            self.assertEqual(len(paymasters["governance_actions"]), 4)
            self.assertEqual(paymasters["paymaster_refill_authorization_count"], 3)
            self.assertEqual(len(paymasters["refill_authorizations"]), 3)
            statuses = {
                item["authorization_id"]: item["status"]
                for item in paymasters["refill_authorizations"]
            }
            self.assertEqual(statuses[authorization["authorization_id"]], "used")
            self.assertEqual(statuses[expired_authorization["authorization_id"]], "failed")
            self.assertEqual(statuses[slash_authorization["authorization_id"]], "failed")
            self.assertEqual(paymasters["paymaster_refill_failure_count"], 2)
            self.assertEqual(len(paymasters["refill_failures"]), 2)
            self.assertEqual(paymasters["paymaster_refill_challenge_count"], 1)
            self.assertEqual(len(paymasters["refill_challenges"]), 1)
            self.assertEqual(paymasters["paymaster_relayer_slashing_hook_count"], 1)
            self.assertEqual(len(paymasters["relayer_slashing_hooks"]), 1)
            self.assertEqual(paymasters["paymaster_relayer_bond_count"], 2)
            self.assertEqual(len(paymasters["relayer_bonds"]), 2)
            slash_public_bond = next(
                item
                for item in paymasters["relayer_bonds"]
                if item["relayer_commitment"]
                == devnet.paymaster_relayer_commitment("slash-relayer")
            )
            self.assertEqual(slash_public_bond["active_amount"], 0)
            self.assertEqual(slash_public_bond["withdrawn_amount"], 1)
            self.assertEqual(paymasters["paymaster_relayer_slash_settlement_count"], 1)
            self.assertEqual(len(paymasters["relayer_slash_settlements"]), 1)
            self.assertEqual(paymasters["paymaster_relayer_unbond_request_count"], 1)
            self.assertEqual(len(paymasters["relayer_unbond_requests"]), 1)
            self.assertEqual(paymasters["paymaster_relayer_reward_count"], 1)
            self.assertEqual(len(paymasters["relayer_reward_receipts"]), 1)
            self.assertEqual(paymasters["paymasters"][0]["status"], "closed")
            self.assertEqual(paymasters["paymasters"][0]["balance"], 0)
            self.assertEqual(paymasters["paymasters"][0]["per_caller_cap"], 1)
            self.assertEqual(
                paymasters["paymasters"][0]["allowed_caller_commitments"],
                [carol_commitment],
            )
            sponsor_wallet = run_json(
                "wallet",
                "--state",
                str(state_path),
                "--owner",
                "sponsor-view-key",
            )
            self.assertEqual(note_amounts(sponsor_wallet, fee_asset["asset_id"]), [1, 1, 5])
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(snapshot["paymaster_governance_action_count"], 4)
            self.assertEqual(len(snapshot["paymaster_governance_root"]), 64)
            self.assertEqual(snapshot["paymaster_refill_authorization_count"], 3)
            self.assertEqual(len(snapshot["paymaster_refill_authorization_root"]), 64)
            self.assertEqual(snapshot["paymaster_refill_failure_count"], 2)
            self.assertEqual(len(snapshot["paymaster_refill_failure_root"]), 64)
            self.assertEqual(snapshot["paymaster_refill_challenge_count"], 1)
            self.assertEqual(len(snapshot["paymaster_refill_challenge_root"]), 64)
            self.assertEqual(snapshot["paymaster_relayer_slashing_hook_count"], 1)
            self.assertEqual(len(snapshot["paymaster_relayer_slashing_root"]), 64)
            self.assertEqual(snapshot["paymaster_relayer_bond_count"], 2)
            self.assertEqual(len(snapshot["paymaster_relayer_bond_root"]), 64)
            self.assertEqual(snapshot["paymaster_relayer_slash_settlement_count"], 1)
            self.assertEqual(
                len(snapshot["paymaster_relayer_slash_settlement_root"]),
                64,
            )
            self.assertEqual(snapshot["paymaster_relayer_unbond_request_count"], 1)
            self.assertEqual(len(snapshot["paymaster_relayer_unbond_root"]), 64)
            self.assertEqual(snapshot["paymaster_relayer_reward_count"], 1)
            self.assertEqual(len(snapshot["paymaster_relayer_reward_root"]), 64)
            authorizations = run_json(
                "paymaster-refill-authorizations",
                "--state",
                str(state_path),
                "--paymaster-id",
                paymaster["paymaster_id"],
            )
            self.assertEqual(authorizations["filtered_authorization_count"], 3)
            relayer_bonds = run_json(
                "paymaster-relayer-bonds",
                "--state",
                str(state_path),
                "--relayer-commitment",
                devnet.paymaster_relayer_commitment("slash-relayer"),
            )
            self.assertEqual(relayer_bonds["filtered_bond_count"], 1)
            self.assertEqual(relayer_bonds["filtered_settlement_count"], 1)
            self.assertEqual(relayer_bonds["filtered_unbond_request_count"], 1)
            self.assertEqual(relayer_bonds["bonds"][0]["slashed_amount"], 2)
            self.assertEqual(relayer_bonds["bonds"][0]["withdrawn_amount"], 1)

    def test_cli_persistent_lending_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            wxmr = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            dusd = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSD",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            collateral = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "1200",
            )
            oracle = run_json(
                "oracle-publish",
                "--state",
                str(state_path),
                "--base-asset-id",
                wxmr["asset_id"],
                "--quote-asset-id",
                dusd["asset_id"],
                "--price-numerator",
                "2",
                "--price-denominator",
                "1",
                "--publisher",
                "oracle-a",
                "--publisher",
                "oracle-b",
            )
            self.assertEqual(oracle["attestation_count"], 2)
            market = run_json(
                "lending-market",
                "--state",
                str(state_path),
                "--collateral-asset-id",
                wxmr["asset_id"],
                "--debt-asset-id",
                dusd["asset_id"],
                "--collateral-factor-bps",
                "5000",
                "--oracle-feed-id",
                oracle["feed_id"],
            )
            self.assertEqual(market["oracle_feed_id"], oracle["feed_id"])
            borrow = run_json(
                "borrow",
                "--state",
                str(state_path),
                "--market-id",
                market["market_id"],
                "--collateral-note-id",
                collateral["note_id"],
                "--collateral-amount",
                "1000",
                "--borrow-amount",
                "900",
                "--owner",
                "alice-view-key",
                "--borrow-fee",
                "5",
            )
            self.assertEqual(borrow["kind"], "lending_borrow")
            self.assertNotIn("spent_collateral_note_id", borrow)
            self.assertNotIn("borrow_amount", borrow)
            self.assertIn("proof_root", borrow["proof_bundle"])
            borrow_block = run_json("block", "--state", str(state_path))
            lending = run_json("lending", "--state", str(state_path))
            alice = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            self.assertEqual(lending["markets"][0]["total_collateral"], 1000)
            self.assertEqual(lending["markets"][0]["total_debt"], 900)
            self.assertEqual(lending["positions"][0]["status"], "active")
            self.assertEqual(note_amounts(alice, wxmr["asset_id"]), [195])
            self.assertEqual(note_amounts(alice, dusd["asset_id"]), [900])
            self.assertEqual(borrow_block["execution_profile"]["privacy_proof_count"], 1)
            oracles = run_json("oracles", "--state", str(state_path))
            self.assertEqual(len(oracles["prices"]), 1)
            self.assertEqual(oracles["prices"][0]["feed_id"], oracle["feed_id"])

            debt_note_id = next(
                note["note_id"] for note in alice if note["asset_id"] == dusd["asset_id"]
            )
            repay = run_json(
                "repay",
                "--state",
                str(state_path),
                "--position-id",
                borrow["position_id"],
                "--debt-note-id",
                debt_note_id,
            )
            self.assertEqual(repay["kind"], "lending_repay")
            self.assertNotIn("spent_debt_note_id", repay)
            self.assertIn("proof_root", repay["proof_bundle"])
            repay_block = run_json("block", "--state", str(state_path))
            lending = run_json("lending", "--state", str(state_path))
            alice = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(lending["markets"][0]["total_collateral"], 0)
            self.assertEqual(lending["markets"][0]["total_debt"], 0)
            self.assertEqual(lending["positions"][0]["status"], "repaid")
            self.assertEqual(note_amounts(alice, wxmr["asset_id"]), [195, 1000])
            self.assertEqual(note_amounts(alice, dusd["asset_id"]), [])
            self.assertEqual(snapshot["lending_market_count"], 1)
            self.assertEqual(snapshot["lending_position_count"], 1)
            self.assertEqual(snapshot["oracle_price_count"], 1)
            self.assertEqual(repay_block["execution_profile"]["privacy_proof_count"], 1)

    def test_cli_persistent_lending_liquidation_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            wxmr = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            dusd = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSD",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            collateral = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "1200",
            )
            oracle = run_json(
                "oracle-publish",
                "--state",
                str(state_path),
                "--base-asset-id",
                wxmr["asset_id"],
                "--quote-asset-id",
                dusd["asset_id"],
                "--price-numerator",
                "2",
                "--publisher",
                "oracle-a",
                "--publisher",
                "oracle-b",
            )
            market = run_json(
                "lending-market",
                "--state",
                str(state_path),
                "--collateral-asset-id",
                wxmr["asset_id"],
                "--debt-asset-id",
                dusd["asset_id"],
                "--collateral-factor-bps",
                "5000",
                "--liquidation-threshold-bps",
                "7500",
                "--oracle-feed-id",
                oracle["feed_id"],
            )
            borrow = run_json(
                "borrow",
                "--state",
                str(state_path),
                "--market-id",
                market["market_id"],
                "--collateral-note-id",
                collateral["note_id"],
                "--collateral-amount",
                "1000",
                "--borrow-amount",
                "900",
                "--owner",
                "alice-view-key",
                "--borrow-fee",
                "5",
            )
            run_json("block", "--state", str(state_path))
            run_json(
                "oracle-publish",
                "--state",
                str(state_path),
                "--base-asset-id",
                wxmr["asset_id"],
                "--quote-asset-id",
                dusd["asset_id"],
                "--price-numerator",
                "1",
                "--publisher",
                "oracle-a",
                "--publisher",
                "oracle-b",
            )
            liquidation_debt = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "liquidator-view-key",
                "--amount",
                "900",
            )
            liquidation = run_json(
                "liquidate",
                "--state",
                str(state_path),
                "--position-id",
                borrow["position_id"],
                "--debt-note-id",
                liquidation_debt["note_id"],
                "--liquidator",
                "liquidator-view-key",
            )
            self.assertEqual(liquidation["kind"], "lending_liquidation")
            self.assertNotIn("spent_debt_note_id", liquidation)
            self.assertNotIn("liquidator-view-key", json.dumps(liquidation))
            self.assertIn("proof_root", liquidation["proof_bundle"])

            liquidation_block = run_json("block", "--state", str(state_path))
            lending = run_json("lending", "--state", str(state_path))
            liquidator = run_json(
                "wallet",
                "--state",
                str(state_path),
                "--owner",
                "liquidator-view-key",
            )
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(lending["markets"][0]["total_collateral"], 0)
            self.assertEqual(lending["markets"][0]["total_debt"], 0)
            self.assertEqual(lending["positions"][0]["status"], "liquidated")
            self.assertEqual(note_amounts(liquidator, wxmr["asset_id"]), [1000])
            self.assertEqual(note_amounts(liquidator, dusd["asset_id"]), [])
            self.assertEqual(snapshot["oracle_price_count"], 1)
            self.assertEqual(liquidation_block["execution_profile"]["privacy_proof_count"], 1)

    def test_amm_liquidity_and_swap_update_contract_state(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        xmr_note = net.mint(wxmr.asset_id, "lp-view-key", 10_000)
        usd_note = net.mint(dusd.asset_id, "lp-view-key", 20_000)
        pool = net.create_amm_pool(wxmr.asset_id, dusd.asset_id, fee_bps=30)

        liquidity = net.submit_amm_liquidity_add(
            pool.pool_id,
            xmr_note.note_id,
            usd_note.note_id,
            amount_a=5_000,
            amount_b=10_000,
            owner_view_key="lp-view-key",
            network_fee=5,
        )
        self.assertEqual(liquidity.lp_minted, 7071)
        self.assertIsNotNone(liquidity.privacy_proof)
        net.produce_block()

        pool = net.pools[pool.pool_id]
        self.assertEqual(pool.reserve_a, 5_000)
        self.assertEqual(pool.reserve_b, 10_000)
        self.assertEqual(pool.total_lp, 7071)
        self.assertEqual(note_amounts(net.wallet_notes("lp-view-key"), pool.lp_asset_id), [7071])
        self.assertEqual(note_amounts(net.wallet_notes("lp-view-key"), wxmr.asset_id), [4995])
        self.assertEqual(note_amounts(net.wallet_notes("lp-view-key"), dusd.asset_id), [10000])

        trader_note = net.mint(wxmr.asset_id, "trader-view-key", 1_500)
        swap = net.submit_amm_swap(
            pool.pool_id,
            trader_note.note_id,
            amount_in=1_000,
            min_amount_out=1_600,
            recipient_view_key="trader-view-key",
            network_fee=2,
        )
        self.assertEqual(swap.amount_out, 1662)
        self.assertIsNotNone(swap.privacy_proof)
        net.produce_block()

        pool = net.pools[pool.pool_id]
        self.assertEqual(pool.reserve_a, 6_000)
        self.assertEqual(pool.reserve_b, 8_338)
        self.assertEqual(note_amounts(net.wallet_notes("trader-view-key"), wxmr.asset_id), [498])
        self.assertEqual(note_amounts(net.wallet_notes("trader-view-key"), dusd.asset_id), [1662])
        self.assertEqual(net.fees_collected[wxmr.asset_id], 7)

        batch_note_one = net.mint(wxmr.asset_id, "trader-view-key", 800)
        batch_note_two = net.mint(wxmr.asset_id, "trader-view-key", 700)
        batch = net.submit_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(batch_note_one.note_id, batch_note_two.note_id),
            amount_ins=(600, 400),
            min_total_amount_out=1_100,
            recipient_view_key="trader-view-key",
            network_fee=3,
        )
        self.assertEqual(batch.total_amount_in, 1_000)
        self.assertEqual(batch.total_amount_out, 1188)
        self.assertEqual(batch.public_record()["input_count"], 2)
        self.assertNotIn("spent_note_ids", batch.public_record())
        self.assertIsNotNone(batch.privacy_proof)
        block = net.produce_block()

        pool = net.pools[pool.pool_id]
        self.assertEqual(pool.reserve_a, 7_000)
        self.assertEqual(pool.reserve_b, 7_150)
        self.assertEqual(note_amounts(net.wallet_notes("trader-view-key"), wxmr.asset_id), [197, 300, 498])
        self.assertEqual(note_amounts(net.wallet_notes("trader-view-key"), dusd.asset_id), [1188, 1662])
        self.assertEqual(net.fees_collected[wxmr.asset_id], 10)
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)

    def test_stable_asset_pool_swaps_near_parity_with_private_notes(self) -> None:
        net = devnet.NebulaL2Devnet()
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        dusc = net.create_asset("DUSC", "devnet-stable-issuer")
        dusd_note = net.mint(dusd.asset_id, "stable-lp-view-key", 20_000)
        dusc_note = net.mint(dusc.asset_id, "stable-lp-view-key", 20_000)
        pool = net.create_amm_pool(
            dusd.asset_id,
            dusc.asset_id,
            fee_bps=5,
            curve="stable",
        )
        self.assertEqual(pool.curve, "stable")

        liquidity = net.submit_amm_liquidity_add(
            pool.pool_id,
            dusd_note.note_id,
            dusc_note.note_id,
            amount_a=10_000,
            amount_b=10_000,
            owner_view_key="stable-lp-view-key",
            network_fee=5,
        )
        self.assertEqual(liquidity.lp_minted, 20_000)
        net.produce_block()
        pool = net.pools[pool.pool_id]
        self.assertEqual(pool.reserve_a, 10_000)
        self.assertEqual(pool.reserve_b, 10_000)
        self.assertEqual(pool.total_lp, 20_000)

        trader_note = net.mint(dusd.asset_id, "stable-trader-view-key", 1_500)
        swap = net.submit_amm_swap(
            pool.pool_id,
            trader_note.note_id,
            amount_in=1_000,
            min_amount_out=995,
            recipient_view_key="stable-trader-view-key",
            network_fee=2,
        )
        self.assertEqual(swap.amount_out, 999)
        net.produce_block()
        pool = net.pools[pool.pool_id]
        self.assertEqual(pool.reserve_a, 11_000)
        self.assertEqual(pool.reserve_b, 9_001)
        self.assertEqual(note_amounts(net.wallet_notes("stable-trader-view-key"), dusd.asset_id), [498])
        self.assertEqual(note_amounts(net.wallet_notes("stable-trader-view-key"), dusc.asset_id), [999])

        first_note = net.mint(dusd.asset_id, "stable-trader-view-key", 800)
        second_note = net.mint(dusd.asset_id, "stable-trader-view-key", 700)
        batch = net.submit_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(first_note.note_id, second_note.note_id),
            amount_ins=(600, 400),
            min_total_amount_out=995,
            recipient_view_key="stable-trader-view-key",
            network_fee=3,
        )
        self.assertEqual(batch.total_amount_out, 999)
        batch_block = net.produce_block()
        pool = net.pools[pool.pool_id]
        self.assertEqual(pool.reserve_a, 12_000)
        self.assertEqual(pool.reserve_b, 8_002)
        self.assertEqual(batch_block.header.execution_profile.privacy_proof_count, 1)

        sealed_one = net.mint(dusd.asset_id, "stable-one-view-key", 600)
        sealed_two = net.mint(dusd.asset_id, "stable-two-view-key", 600)
        sealed = net.submit_sealed_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(sealed_one.note_id, sealed_two.note_id),
            amount_ins=(500, 500),
            min_amount_outs=(490, 490),
            recipient_view_keys=("stable-one-view-key", "stable-two-view-key"),
            network_fees=(1, 1),
            solver_label="stable-solver",
        )
        self.assertEqual(sealed.total_amount_out, 999)
        sealed_block = net.produce_block()
        receipt = next(iter(net.sealed_swap_settlement_receipts.values()))
        self.assertEqual(receipt.block_height, sealed_block.header.height)
        self.assertEqual(receipt.pool_curve, "stable")
        self.assertEqual(receipt.total_amount_out, 999)
        self.assertEqual(receipt.pool_after_reserve_out, 7_003)
        self.assertNotIn("stable-one-view-key", json.dumps(receipt.public_record()))
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.pools[pool.pool_id].curve, "stable")
        self.assertEqual(
            round_trip.sealed_swap_settlement_receipt_root(),
            net.sealed_swap_settlement_receipt_root(),
        )

    def test_private_route_swap_hops_multiple_pools_for_one_fee(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        dusc = net.create_asset("DUSC", "devnet-stable-issuer")
        wxmr_liquidity = net.mint(wxmr.asset_id, "lp-one-view-key", 10_000)
        dusd_liquidity = net.mint(dusd.asset_id, "lp-one-view-key", 20_000)
        pool_one = net.create_amm_pool(wxmr.asset_id, dusd.asset_id, fee_bps=30)
        net.submit_amm_liquidity_add(
            pool_one.pool_id,
            wxmr_liquidity.note_id,
            dusd_liquidity.note_id,
            amount_a=5_000,
            amount_b=10_000,
            owner_view_key="lp-one-view-key",
            network_fee=5,
        )
        dusd_stable = net.mint(dusd.asset_id, "lp-two-view-key", 20_000)
        dusc_stable = net.mint(dusc.asset_id, "lp-two-view-key", 20_000)
        pool_two = net.create_amm_pool(
            dusd.asset_id,
            dusc.asset_id,
            fee_bps=5,
            curve="stable",
        )
        net.submit_amm_liquidity_add(
            pool_two.pool_id,
            dusd_stable.note_id,
            dusc_stable.note_id,
            amount_a=10_000,
            amount_b=10_000,
            owner_view_key="lp-two-view-key",
            network_fee=5,
        )
        net.produce_block()

        trader_note = net.mint(wxmr.asset_id, "route-trader-view-key", 1_500)
        route = net.submit_amm_route_swap(
            pool_ids=(pool_one.pool_id, pool_two.pool_id),
            note_in_id=trader_note.note_id,
            amount_in=1_000,
            min_amount_out=1_600,
            recipient_view_key="route-trader-view-key",
            network_fee=2,
        )
        public_record = route.public_record()
        self.assertEqual(public_record["route_hop_count"], 2)
        self.assertEqual(public_record["asset_path"], [
            wxmr.asset_id,
            dusd.asset_id,
            dusc.asset_id,
        ])
        self.assertEqual(public_record["hop_amounts"], [1662, 1661])
        self.assertEqual(public_record["amount_out"], 1661)
        self.assertEqual(public_record["route_root"], route.route_root())
        self.assertIn("proof_root", public_record["proof_bundle"])
        self.assertNotIn(trader_note.note_id, json.dumps(public_record))
        self.assertNotIn("route-trader-view-key", json.dumps(public_record))

        quote = net.fee_quote(
            operation="route-swap",
            input_count=2,
            output_count=2,
            pool_id=pool_one.pool_id,
        )
        self.assertEqual(quote["operation"], "route-swap")
        self.assertEqual(quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertEqual(quote["candidate_profile"]["authorization_count"], 1)
        self.assertEqual(quote["candidate_profile"]["local_fee_lane_count"], 3)

        tampered = replace(route, hop_amounts=(1662, 1660))
        with self.assertRaisesRegex(ValueError, "invalid privacy proof|hop amount"):
            net._verify_transaction_auth(tampered)

        block = net.produce_block()
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(block.header.execution_profile.authorization_count, 1)
        self.assertEqual(net.pools[pool_one.pool_id].reserve_a, 6_000)
        self.assertEqual(net.pools[pool_one.pool_id].reserve_b, 8_338)
        self.assertEqual(net.pools[pool_two.pool_id].reserve_a, 11_662)
        self.assertEqual(net.pools[pool_two.pool_id].reserve_b, 8_339)
        wallet = net.wallet_notes("route-trader-view-key")
        self.assertEqual(note_amounts(wallet, wxmr.asset_id), [498])
        self.assertEqual(note_amounts(wallet, dusc.asset_id), [1661])
        history = net.wallet_history("route-trader-view-key")
        route_spends = [
            event for event in history["events"]
            if event["event"] == "spent" and event["kind"] == "amm_route_swap"
        ]
        self.assertEqual(len(route_spends), 1)
        self.assertEqual(route_spends[0]["route_hop_count"], 2)
        self.assertEqual(route_spends[0]["fee_units"], 2)

    def test_dark_pool_swap_atomically_matches_private_notes(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        alice_note = net.mint(wxmr.asset_id, "alice-view-key", 1_000)
        bob_note = net.mint(dusd.asset_id, "bob-view-key", 2_500)

        swap = net.submit_dark_pool_swap(
            note_a_id=alice_note.note_id,
            note_b_id=bob_note.note_id,
            amount_a=400,
            amount_b=800,
            recipient_a_view_key="alice-view-key",
            recipient_b_view_key="bob-view-key",
            network_fee_a=2,
            network_fee_b=3,
            match_salt="shared-dark-match",
        )
        public_record = swap.public_record()
        self.assertEqual(public_record["kind"], "dark_pool_swap")
        self.assertEqual(public_record["trade_commitment"], swap.trade_commitment())
        self.assertIn("proof_root", public_record["proof_bundle"])
        self.assertNotIn("spent_note_a_id", public_record)
        self.assertNotIn("amount_a", public_record)
        self.assertNotIn("asset_a_id", public_record)
        self.assertNotIn(alice_note.note_id, json.dumps(public_record))
        self.assertNotIn(bob_note.note_id, json.dumps(public_record))
        self.assertNotIn("alice-view-key", json.dumps(public_record))
        self.assertNotIn("bob-view-key", json.dumps(public_record))

        quote = net.fee_quote(
            operation="dark-swap",
            input_count=2,
            output_count=4,
        )
        self.assertEqual(quote["operation"], "dark-swap")
        self.assertEqual(quote["candidate_profile"]["privacy_proof_count"], 1)
        self.assertEqual(quote["candidate_profile"]["authorization_count"], 2)

        tampered = replace(swap, amount_a=401)
        with self.assertRaisesRegex(
            ValueError,
            "invalid privacy proof|invalid dark pool swap leg A authorization|dark pool leg A output mismatch",
        ):
            net._verify_transaction_auth(tampered)

        block = net.produce_block()
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(block.header.execution_profile.authorization_count, 2)
        self.assertEqual(net.fees_collected[wxmr.asset_id], 2)
        self.assertEqual(net.fees_collected[dusd.asset_id], 3)
        alice_wallet = net.wallet_notes("alice-view-key")
        bob_wallet = net.wallet_notes("bob-view-key")
        self.assertEqual(note_amounts(alice_wallet, wxmr.asset_id), [598])
        self.assertEqual(note_amounts(alice_wallet, dusd.asset_id), [800])
        self.assertEqual(note_amounts(bob_wallet, wxmr.asset_id), [400])
        self.assertEqual(note_amounts(bob_wallet, dusd.asset_id), [1697])

        alice_history = net.wallet_history("alice-view-key")
        alice_spends = [
            event for event in alice_history["events"]
            if event["event"] == "spent" and event["kind"] == "dark_pool_swap"
        ]
        self.assertEqual(len(alice_spends), 1)
        self.assertEqual(alice_spends[0]["side"], "a")
        self.assertEqual(alice_spends[0]["trade_commitment"], swap.trade_commitment())

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            note_amounts(round_trip.wallet_notes("bob-view-key"), wxmr.asset_id),
            [400],
        )

    def test_sealed_amm_batch_swap_settles_multi_user_intents(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        xmr_note = net.mint(wxmr.asset_id, "lp-view-key", 10_000)
        usd_note = net.mint(dusd.asset_id, "lp-view-key", 20_000)
        pool = net.create_amm_pool(wxmr.asset_id, dusd.asset_id, fee_bps=30)
        net.submit_amm_liquidity_add(
            pool.pool_id,
            xmr_note.note_id,
            usd_note.note_id,
            amount_a=5_000,
            amount_b=10_000,
            owner_view_key="lp-view-key",
            network_fee=5,
        )
        net.produce_block()

        first_trader = net.mint(wxmr.asset_id, "trader-one-view-key", 800)
        second_trader = net.mint(wxmr.asset_id, "trader-two-view-key", 700)
        sealed = net.submit_sealed_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(first_trader.note_id, second_trader.note_id),
            amount_ins=(600, 400),
            min_amount_outs=(900, 600),
            recipient_view_keys=("trader-one-view-key", "trader-two-view-key"),
            network_fees=(2, 1),
        )
        public_record = sealed.public_record()
        self.assertEqual(public_record["intent_count"], 2)
        self.assertEqual(public_record["total_amount_in"], 1_000)
        self.assertEqual(public_record["total_amount_out"], 1_662)
        self.assertEqual(public_record["network_fee_total"], 3)
        self.assertNotIn("fills", public_record)
        self.assertNotIn("spent_note_ids", public_record)
        self.assertNotIn("trader-one-view-key", str(public_record))
        self.assertTrue(public_record["intent_root"])
        self.assertIsNotNone(sealed.privacy_proof)

        block = net.produce_block()
        self.assertEqual(len(net.sealed_swap_settlement_receipts), 1)
        receipt = next(iter(net.sealed_swap_settlement_receipts.values()))
        self.assertEqual(receipt.block_height, block.header.height)
        self.assertEqual(receipt.pool_id, pool.pool_id)
        self.assertEqual(receipt.solver_label, "sealed-swap-solver")
        self.assertEqual(receipt.intent_count, 2)
        self.assertEqual(receipt.intent_root, sealed.intent_root())
        self.assertEqual(receipt.total_amount_in, 1_000)
        self.assertEqual(receipt.total_amount_out, 1_662)
        self.assertEqual(receipt.total_surplus_amount, 162)
        self.assertEqual(receipt.clearing_price_numerator, 1_662)
        self.assertEqual(receipt.clearing_price_denominator, 1_000)
        self.assertEqual(
            receipt.clearing_price_commitment_root,
            receipt.expected_clearing_price_commitment_root(),
        )
        self.assertEqual(
            receipt.aggregate_surplus_commitment_root,
            receipt.expected_aggregate_surplus_commitment_root(),
        )
        self.assertEqual(len(receipt.route_commitment), 64)
        self.assertEqual(len(receipt.clearing_price_commitment_root), 64)
        self.assertEqual(len(receipt.aggregate_surplus_commitment_root), 64)
        self.assertTrue(receipt.auth_signature)
        receipt_json = json.dumps(receipt.public_record())
        self.assertNotIn("trader-one-view-key", receipt_json)
        self.assertNotIn("trader-two-view-key", receipt_json)
        self.assertEqual(
            net.public_snapshot()["sealed_swap_settlement_receipt_count"],
            1,
        )
        self.assertEqual(
            net.public_snapshot()["sealed_swap_settlement_receipt_root"],
            net.sealed_swap_settlement_receipt_root(),
        )
        pool_after = net.pools[pool.pool_id]
        self.assertEqual(pool_after.reserve_a, 6_000)
        self.assertEqual(pool_after.reserve_b, 8_338)
        self.assertEqual(note_amounts(net.wallet_notes("trader-one-view-key"), wxmr.asset_id), [198])
        self.assertEqual(note_amounts(net.wallet_notes("trader-one-view-key"), dusd.asset_id), [997])
        self.assertEqual(note_amounts(net.wallet_notes("trader-two-view-key"), wxmr.asset_id), [299])
        self.assertEqual(note_amounts(net.wallet_notes("trader-two-view-key"), dusd.asset_id), [665])
        self.assertEqual(net.fees_collected[wxmr.asset_id], 8)
        self.assertEqual(block.header.execution_profile.tx_count, 1)
        self.assertEqual(block.header.execution_profile.privacy_proof_count, 1)
        self.assertEqual(block.header.execution_profile.authorization_count, 2)
        self.assertGreater(
            block.header.execution_profile.estimated_proof_bytes,
            devnet.DEVNET_PRIVACY_PROOF_BYTES,
        )
        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.sealed_swap_settlement_receipt_root(),
            net.sealed_swap_settlement_receipt_root(),
        )

        tampered_commitment = net.state_record()
        tampered_commitment["sealed_swap_settlement_receipts"][0][
            "clearing_price_commitment_root"
        ] = "00" * 32
        with self.assertRaisesRegex(ValueError, "clearing price commitment mismatch"):
            devnet.NebulaL2Devnet.from_state_record(tampered_commitment)

        tampered = net.state_record()
        tampered["sealed_swap_settlement_receipts"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid sealed swap settlement receipt"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_sealed_swap_commit_reveal_binds_private_orders(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        xmr_note = net.mint(wxmr.asset_id, "lp-view-key", 10_000)
        usd_note = net.mint(dusd.asset_id, "lp-view-key", 20_000)
        pool = net.create_amm_pool(wxmr.asset_id, dusd.asset_id, fee_bps=30)
        net.submit_amm_liquidity_add(
            pool.pool_id,
            xmr_note.note_id,
            usd_note.note_id,
            amount_a=5_000,
            amount_b=10_000,
            owner_view_key="lp-view-key",
            network_fee=5,
        )
        net.produce_block()

        first_trader = net.mint(wxmr.asset_id, "trader-one-view-key", 800)
        second_trader = net.mint(wxmr.asset_id, "trader-two-view-key", 700)
        first_secret = "large-order-secret-one"
        second_secret = "large-order-secret-two"
        first_commitment = net.submit_sealed_swap_order_commitment(
            pool.pool_id,
            note_in_id=first_trader.note_id,
            amount_in=600,
            min_amount_out=900,
            recipient_view_key="trader-one-view-key",
            network_fee=2,
            reveal_secret=first_secret,
        )
        second_commitment = net.submit_sealed_swap_order_commitment(
            pool.pool_id,
            note_in_id=second_trader.note_id,
            amount_in=400,
            min_amount_out=600,
            recipient_view_key="trader-two-view-key",
            network_fee=1,
            reveal_secret=second_secret,
        )
        public_commitments = json.dumps([
            first_commitment.public_record(),
            second_commitment.public_record(),
        ])
        self.assertEqual(first_commitment.min_reveal_height, 2)
        self.assertEqual(
            net.public_snapshot()["sealed_swap_order_commitment_count"],
            2,
        )
        self.assertNotIn(first_trader.note_id, public_commitments)
        self.assertNotIn("trader-one-view-key", public_commitments)
        self.assertNotIn(first_secret, public_commitments)
        self.assertEqual(
            first_commitment.owner_commitment,
            devnet.domain_hash("SEALED-SWAP-COMMITTER", "trader-one-view-key"),
        )

        with self.assertRaisesRegex(ValueError, "not revealable yet"):
            net.submit_sealed_amm_batch_swap(
                pool.pool_id,
                note_in_ids=(first_trader.note_id, second_trader.note_id),
                amount_ins=(600, 400),
                min_amount_outs=(900, 600),
                recipient_view_keys=("trader-one-view-key", "trader-two-view-key"),
                network_fees=(2, 1),
                commitment_ids=(
                    first_commitment.commitment_id,
                    second_commitment.commitment_id,
                ),
                commitment_reveal_secrets=(first_secret, second_secret),
            )

        net.produce_block(include_pending=False)
        lower_bid = net.submit_sealed_swap_solver_bid(
            pool.pool_id,
            commitment_ids=(
                first_commitment.commitment_id,
                second_commitment.commitment_id,
            ),
            asset_in_id=wxmr.asset_id,
            asset_out_id=dusd.asset_id,
            total_amount_in=1_000,
            quoted_amount_out=1_600,
            network_fee_total=3,
            solver_label="solver-low",
        )
        best_bid = net.submit_sealed_swap_solver_bid(
            pool.pool_id,
            commitment_ids=(
                first_commitment.commitment_id,
                second_commitment.commitment_id,
            ),
            asset_in_id=wxmr.asset_id,
            asset_out_id=dusd.asset_id,
            total_amount_in=1_000,
            quoted_amount_out=1_662,
            network_fee_total=3,
            solver_label="solver-best",
        )
        bids_json = json.dumps([
            lower_bid.public_record(),
            best_bid.public_record(),
        ])
        self.assertNotIn("trader-one-view-key", bids_json)
        self.assertNotIn(first_secret, bids_json)
        self.assertEqual(
            net.public_snapshot()["sealed_swap_solver_bid_count"],
            2,
        )
        with self.assertRaisesRegex(ValueError, "better sealed swap solver bid"):
            net.submit_sealed_amm_batch_swap(
                pool.pool_id,
                note_in_ids=(first_trader.note_id, second_trader.note_id),
                amount_ins=(600, 400),
                min_amount_outs=(900, 600),
                recipient_view_keys=("trader-one-view-key", "trader-two-view-key"),
                network_fees=(2, 1),
                commitment_ids=(
                    first_commitment.commitment_id,
                    second_commitment.commitment_id,
                ),
                commitment_reveal_secrets=(first_secret, second_secret),
                solver_bid_id=lower_bid.bid_id,
                solver_label="solver-low",
            )
        sealed = net.submit_sealed_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(first_trader.note_id, second_trader.note_id),
            amount_ins=(600, 400),
            min_amount_outs=(900, 600),
            recipient_view_keys=("trader-one-view-key", "trader-two-view-key"),
            network_fees=(2, 1),
            commitment_ids=(
                first_commitment.commitment_id,
                second_commitment.commitment_id,
            ),
            commitment_reveal_secrets=(first_secret, second_secret),
            solver_bid_id=best_bid.bid_id,
            solver_label="solver-best",
        )
        public_record = sealed.public_record()
        self.assertEqual(public_record["commitment_count"], 2)
        self.assertEqual(public_record["solver_bid_id"], best_bid.bid_id)
        self.assertEqual(
            public_record["commitment_root"],
            devnet.merkle_root(
                "SEALED-SWAP-COMMITMENT-ID",
                [first_commitment.commitment_id, second_commitment.commitment_id],
            ),
        )
        self.assertNotIn(first_secret, json.dumps(public_record))
        self.assertNotIn("trader-one-view-key", json.dumps(public_record))

        with self.assertRaisesRegex(ValueError, "duplicate nullifier|already pending reveal"):
            net.submit_sealed_amm_batch_swap(
                pool.pool_id,
                note_in_ids=(first_trader.note_id, second_trader.note_id),
                amount_ins=(600, 400),
                min_amount_outs=(900, 600),
                recipient_view_keys=("trader-one-view-key", "trader-two-view-key"),
                network_fees=(2, 1),
                commitment_ids=(
                    first_commitment.commitment_id,
                    second_commitment.commitment_id,
                ),
                commitment_reveal_secrets=(first_secret, second_secret),
                solver_bid_id=best_bid.bid_id,
                solver_label="solver-best",
            )

        block = net.produce_block()
        self.assertEqual(block.header.execution_profile.authorization_count, 2)
        revealed = net.sealed_swap_order_commitments[first_commitment.commitment_id]
        self.assertEqual(revealed.status, "revealed")
        self.assertEqual(revealed.revealed_intent_hash, sealed.fills[0].intent.intent_hash())
        self.assertEqual(revealed.revealed_at_height, block.header.height)
        self.assertEqual(
            net.public_snapshot()["sealed_swap_order_commitment_root"],
            net.sealed_swap_order_commitment_root(),
        )
        self.assertEqual(net.sealed_swap_solver_bids[best_bid.bid_id].status, "won")
        self.assertEqual(net.sealed_swap_solver_bids[lower_bid.bid_id].status, "lost")
        receipt = next(iter(net.sealed_swap_settlement_receipts.values()))
        self.assertEqual(receipt.solver_bid_id, best_bid.bid_id)
        self.assertEqual(
            net.public_snapshot()["sealed_swap_solver_bid_root"],
            net.sealed_swap_solver_bid_root(),
        )

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.sealed_swap_order_commitment_root(),
            net.sealed_swap_order_commitment_root(),
        )
        self.assertEqual(
            round_trip.sealed_swap_solver_bid_root(),
            net.sealed_swap_solver_bid_root(),
        )
        tampered_bid = net.state_record()
        tampered_bid["sealed_swap_solver_bids"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid sealed swap solver bid"):
            devnet.NebulaL2Devnet.from_state_record(tampered_bid)
        tampered = net.state_record()
        tampered["sealed_swap_order_commitments"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid sealed swap commitment"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_sealed_swap_expiry_sweeps_commitments_and_solver_bids(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        xmr_note = net.mint(wxmr.asset_id, "lp-view-key", 10_000)
        usd_note = net.mint(dusd.asset_id, "lp-view-key", 20_000)
        pool = net.create_amm_pool(wxmr.asset_id, dusd.asset_id, fee_bps=30)
        net.submit_amm_liquidity_add(
            pool.pool_id,
            xmr_note.note_id,
            usd_note.note_id,
            amount_a=5_000,
            amount_b=10_000,
            owner_view_key="lp-view-key",
            network_fee=5,
        )
        net.produce_block()

        trader_note = net.mint(wxmr.asset_id, "trader-view-key", 800)
        commitment = net.submit_sealed_swap_order_commitment(
            pool.pool_id,
            note_in_id=trader_note.note_id,
            amount_in=600,
            min_amount_out=900,
            recipient_view_key="trader-view-key",
            network_fee=2,
            reveal_secret="short-auction-secret",
            ttl_blocks=1,
            min_reveal_height=len(net.blocks),
        )
        bid = net.submit_sealed_swap_solver_bid(
            pool.pool_id,
            commitment_ids=(commitment.commitment_id,),
            asset_in_id=wxmr.asset_id,
            asset_out_id=dusd.asset_id,
            total_amount_in=600,
            quoted_amount_out=1_000,
            network_fee_total=2,
            solver_label="solver-expiry",
            ttl_blocks=1,
        )
        net.submit_sealed_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(trader_note.note_id,),
            amount_ins=(600,),
            min_amount_outs=(900,),
            recipient_view_keys=("trader-view-key",),
            network_fees=(2,),
            commitment_ids=(commitment.commitment_id,),
            commitment_reveal_secrets=("short-auction-secret",),
            solver_bid_id=bid.bid_id,
            solver_label="solver-expiry",
        )

        net.produce_block(include_pending=False)
        net.produce_block(include_pending=False)
        report = net.expire_sealed_swap_auctions()

        self.assertEqual(report["height"], len(net.blocks))
        self.assertEqual(report["expired_commitment_count"], 1)
        self.assertEqual(report["expired_solver_bid_count"], 1)
        self.assertEqual(
            net.sealed_swap_order_commitments[commitment.commitment_id].status,
            "expired",
        )
        self.assertEqual(net.sealed_swap_solver_bids[bid.bid_id].status, "expired")
        self.assertEqual(
            report["sealed_swap_order_commitment_root"],
            net.sealed_swap_order_commitment_root(),
        )
        self.assertEqual(
            report["sealed_swap_solver_bid_root"],
            net.sealed_swap_solver_bid_root(),
        )

        with self.assertRaisesRegex(ValueError, "sealed swap commitment is not active"):
            net.produce_block()

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.sealed_swap_order_commitments[commitment.commitment_id].status,
            "expired",
        )
        self.assertEqual(
            round_trip.sealed_swap_solver_bids[bid.bid_id].status,
            "expired",
        )

    def test_sealed_amm_batch_swap_rejects_tampered_intent_auth(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.create_asset("WXMR", "devnet-bridge-threshold")
        dusd = net.create_asset("DUSD", "devnet-stable-issuer")
        xmr_note = net.mint(wxmr.asset_id, "lp-view-key", 10_000)
        usd_note = net.mint(dusd.asset_id, "lp-view-key", 20_000)
        pool = net.create_amm_pool(wxmr.asset_id, dusd.asset_id, fee_bps=30)
        net.submit_amm_liquidity_add(
            pool.pool_id,
            xmr_note.note_id,
            usd_note.note_id,
            amount_a=5_000,
            amount_b=10_000,
            owner_view_key="lp-view-key",
            network_fee=5,
        )
        net.produce_block()

        first_trader = net.mint(wxmr.asset_id, "trader-one-view-key", 800)
        second_trader = net.mint(wxmr.asset_id, "trader-two-view-key", 700)
        sealed = net.submit_sealed_amm_batch_swap(
            pool.pool_id,
            note_in_ids=(first_trader.note_id, second_trader.note_id),
            amount_ins=(600, 400),
            min_amount_outs=(900, 600),
            recipient_view_keys=("trader-one-view-key", "trader-two-view-key"),
            network_fees=(2, 1),
        )

        first_fill = sealed.fills[0]
        bad_intent = replace(first_fill.intent, auth_signature="00")
        bad_fill = replace(first_fill, intent=bad_intent)
        bad_tx = replace(sealed, fills=(bad_fill, sealed.fills[1]))
        net.pending[0] = net._attach_privacy_proof(bad_tx)

        with self.assertRaisesRegex(ValueError, "invalid sealed swap intent authorization"):
            net.produce_block()

    def test_bridge_deposit_mint_and_withdrawal_flow(self) -> None:
        net = devnet.NebulaL2Devnet()
        request = net.request_bridge_deposit_address("alice-view-key")
        observation = net.observe_bridge_deposit(
            request.deposit_id,
            monero_txid="monero-tx-001",
            amount=10_000,
            confirmations=12,
            watcher_labels=["bridge-signer-1", "bridge-signer-2"],
        )
        self.assertEqual(observation.status, "observed")
        signer_set = net.active_bridge_signer_set()
        self.assertEqual(observation.signer_set_id, signer_set.signer_set_id)
        self.assertEqual(observation.signer_threshold, signer_set.threshold)
        self.assertEqual(observation.public_record()["signer_count"], 2)
        self.assertEqual(observation.public_record()["signer_threshold"], 2)
        bridge_root_before = net.bridge_root()

        mint = net.submit_bridge_mint(request.deposit_id)
        self.assertEqual(mint.amount, 10_000)
        self.assertEqual(mint.signer_set_id, signer_set.signer_set_id)
        self.assertEqual(mint.signer_threshold, signer_set.threshold)
        self.assertEqual(mint.signer_count, 2)
        mint_block = net.produce_block()
        mint_anchor = net._anchor_commitment_for_block(0)

        bridge_root_after_mint = net.bridge_root()
        self.assertEqual(mint_block.header.bridge_root, bridge_root_after_mint)
        self.assertNotEqual(bridge_root_before, bridge_root_after_mint)
        wxmr_asset_id = net.wrapped_xmr_asset_id
        self.assertIsNotNone(wxmr_asset_id)
        alice_notes = net.wallet_notes("alice-view-key")
        self.assertEqual(note_amounts(alice_notes, wxmr_asset_id), [10_000])

        initial_reserve = net.publish_bridge_reserve_report(
            reserve_amount=10_000,
            reserve_address="devnet-reserve-vault-1",
            reporter_labels=("reserve-auditor-1", "reserve-auditor-2"),
        )
        self.assertEqual(initial_reserve.reserve_asset_id, wxmr_asset_id)
        self.assertEqual(initial_reserve.circulating_amount, 10_000)
        self.assertEqual(initial_reserve.queued_withdrawal_amount, 0)
        self.assertEqual(initial_reserve.submitted_withdrawal_amount, 0)
        self.assertEqual(initial_reserve.outstanding_liability, 10_000)
        self.assertEqual(initial_reserve.reported_reserve_amount, 10_000)
        self.assertEqual(initial_reserve.coverage_bps, 10_000)
        self.assertEqual(initial_reserve.status, "healthy")
        self.assertEqual(initial_reserve.reporter_count, 2)
        self.assertTrue(initial_reserve.attestation_root)
        self.assertNotIn("devnet-reserve-vault-1", json.dumps(initial_reserve.public_record()))

        withdraw = net.submit_bridge_withdraw(
            alice_notes[0]["note_id"],
            monero_address="44AFFq5kSiGBoZ...",
            amount=6_000,
            bridge_fee=25,
        )
        self.assertTrue(withdraw.auth_signature)
        self.assertEqual(withdraw.queue_signer_set_id, signer_set.signer_set_id)
        self.assertEqual(withdraw.queue_signer_threshold, signer_set.threshold)
        self.assertEqual(withdraw.queue_signer_count, signer_set.threshold)
        self.assertIsNotNone(withdraw.privacy_proof)
        withdraw_block = net.produce_block()

        self.assertEqual(len(net.bridge_withdrawals), 1)
        self.assertEqual(withdraw_block.header.bridge_root, net.bridge_root())
        self.assertNotEqual(mint_block.header.bridge_root, withdraw_block.header.bridge_root)
        self.assertEqual(net._anchor_commitment_for_block(0), mint_anchor)
        withdrawal = next(iter(net.bridge_withdrawals.values()))
        self.assertEqual(withdrawal.amount, 6_000)
        self.assertEqual(withdrawal.bridge_fee, 25)
        self.assertEqual(withdrawal.status, "queued")
        self.assertEqual(withdrawal.queue_signer_set_id, signer_set.signer_set_id)
        self.assertEqual(withdrawal.queue_signer_threshold, signer_set.threshold)
        self.assertEqual(withdrawal.queue_signer_count, signer_set.threshold)
        self.assertEqual(withdrawal.requested_at_height, withdraw_block.header.height)
        self.assertEqual(withdrawal.amount_bucket, 6_000)
        self.assertEqual(withdrawal.privacy_delay_blocks, devnet.BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS)
        self.assertEqual(
            withdrawal.release_not_before_height,
            withdraw_block.header.height + devnet.BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS,
        )
        self.assertEqual(withdrawal.release_monero_txid_hash, "")
        self.assertEqual(note_amounts(net.wallet_notes("alice-view-key"), wxmr_asset_id), [3_975])
        self.assertEqual(net.fees_collected[wxmr_asset_id], 25)
        self.assertEqual(net.public_snapshot()["bridge_withdrawal_count"], 1)

        queued_reserve = net.publish_bridge_reserve_report(
            reserve_amount=10_000,
            reserve_address="devnet-reserve-vault-1",
        )
        self.assertEqual(queued_reserve.circulating_amount, 4_000)
        self.assertEqual(queued_reserve.queued_withdrawal_amount, 6_000)
        self.assertEqual(queued_reserve.submitted_withdrawal_amount, 0)
        self.assertEqual(queued_reserve.outstanding_liability, 10_000)
        self.assertEqual(queued_reserve.surplus_amount, 0)
        self.assertEqual(queued_reserve.status, "healthy")

        with self.assertRaisesRegex(ValueError, "release delay"):
            net.release_bridge_withdrawal(
                withdrawal.withdrawal_id,
                monero_txid="monero-withdraw-release-too-early",
            )
        delay_block = net.produce_block()
        self.assertEqual(delay_block.header.execution_profile.tx_count, 0)
        self.assertGreaterEqual(len(net.blocks), withdrawal.release_not_before_height)

        release = net.release_bridge_withdrawal(
            withdrawal.withdrawal_id,
            monero_txid="monero-withdraw-release-001",
            signer_labels=("bridge-signer-1", "bridge-signer-2"),
        )
        self.assertEqual(release.status, "submitted")
        self.assertEqual(release.release_signer_count, 2)
        self.assertEqual(release.release_confirmations, 0)
        self.assertTrue(release.release_signature_root)
        self.assertEqual(
            release.release_monero_txid_hash,
            devnet.domain_hash("MONERO-TXID-HASH", "monero-withdraw-release-001"),
        )
        public_release = release.public_record()
        self.assertNotIn("monero_txid", public_release)
        self.assertEqual(public_release["status"], "submitted")

        with self.assertRaisesRegex(ValueError, "already submitted"):
            net.release_bridge_withdrawal(
                withdrawal.withdrawal_id,
                monero_txid="monero-withdraw-release-002",
            )

        pending_release = net.confirm_bridge_withdrawal(
            withdrawal.withdrawal_id,
            confirmations=4,
            finality_depth=10,
        )
        self.assertEqual(pending_release.status, "submitted")
        self.assertEqual(pending_release.release_confirmations, 4)
        self.assertEqual(pending_release.completed_at_ms, 0)

        completed_release = net.confirm_bridge_withdrawal(
            withdrawal.withdrawal_id,
            confirmations=10,
            finality_depth=10,
        )
        self.assertEqual(completed_release.status, "completed")
        self.assertEqual(completed_release.release_confirmations, 10)
        self.assertGreater(completed_release.completed_at_ms, 0)

        completed_reserve = net.publish_bridge_reserve_report(
            reserve_amount=4_000,
            reserve_address="devnet-reserve-vault-1",
        )
        self.assertEqual(completed_reserve.circulating_amount, 4_000)
        self.assertEqual(completed_reserve.queued_withdrawal_amount, 0)
        self.assertEqual(completed_reserve.submitted_withdrawal_amount, 0)
        self.assertEqual(completed_reserve.completed_withdrawal_amount, 6_000)
        self.assertEqual(completed_reserve.outstanding_liability, 4_000)
        self.assertEqual(completed_reserve.status, "healthy")
        underreserved = net.publish_bridge_reserve_report(
            reserve_amount=3_999,
            reserve_address="devnet-reserve-vault-1",
        )
        self.assertEqual(underreserved.status, "underreserved")
        self.assertEqual(underreserved.surplus_amount, -1)
        self.assertEqual(net.public_snapshot()["bridge_reserve_report_count"], 4)

        with self.assertRaisesRegex(ValueError, "cannot decrease"):
            net.confirm_bridge_withdrawal(withdrawal.withdrawal_id, confirmations=9)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.bridge_withdrawals[withdrawal.withdrawal_id].status,
            "completed",
        )
        self.assertEqual(
            round_trip.bridge_withdrawals[withdrawal.withdrawal_id].release_monero_txid_hash,
            release.release_monero_txid_hash,
        )
        self.assertEqual(
            round_trip.bridge_reserve_report_root(),
            net.bridge_reserve_report_root(),
        )
        tampered_observation = net.state_record()
        tampered_observation["bridge_observations"][0]["attestation_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "bridge deposit attestation root"):
            devnet.NebulaL2Devnet.from_state_record(tampered_observation)

    def test_bridge_withdrawal_challenge_holds_and_release_rate_limit(self) -> None:
        net = devnet.NebulaL2Devnet()
        wxmr = net.ensure_wrapped_xmr_asset()
        alice_note = net.mint(wxmr.asset_id, "alice-view-key", 8_000)
        bob_note = net.mint(wxmr.asset_id, "bob-view-key", 5_000)
        first_tx = net.submit_bridge_withdraw(
            alice_note.note_id,
            monero_address="44AFFq5kSiGBoZfirst",
            amount=7_000,
            bridge_fee=0,
        )
        second_tx = net.submit_bridge_withdraw(
            bob_note.note_id,
            monero_address="84kDevnetSecondWithdraw",
            amount=4_000,
            bridge_fee=0,
        )
        block = net.produce_block()
        first = net.bridge_withdrawals[first_tx.withdrawal_id]
        second = net.bridge_withdrawals[second_tx.withdrawal_id]
        self.assertEqual(first.status, "queued")
        self.assertEqual(second.status, "queued")

        challenge = net.challenge_bridge_withdrawal(
            first.withdrawal_id,
            challenge_type="address-risk",
            evidence="cluster score above policy threshold",
            reporter_label="bridge-watchtower-a",
            hold_blocks=3,
        )
        self.assertEqual(challenge.withdrawal_id, first.withdrawal_id)
        self.assertEqual(challenge.challenge_type, "address-risk")
        self.assertEqual(challenge.amount_bucket, first.amount_bucket)
        self.assertEqual(challenge.reported_at_height, len(net.blocks))
        self.assertEqual(challenge.hold_until_height, len(net.blocks) + 3)
        self.assertTrue(challenge.auth_signature)
        self.assertNotIn("cluster score", json.dumps(challenge.public_record()))
        challenged = net.bridge_withdrawals[first.withdrawal_id]
        self.assertEqual(challenged.release_not_before_height, challenge.hold_until_height)
        self.assertEqual(net.public_snapshot()["bridge_withdrawal_challenge_count"], 1)
        self.assertEqual(
            net.public_snapshot()["bridge_withdrawal_challenge_root"],
            net.bridge_withdrawal_challenge_root(),
        )

        with self.assertRaisesRegex(ValueError, "challenge hold"):
            net.release_bridge_withdrawal(
                first.withdrawal_id,
                monero_txid="monero-release-held",
            )

        while len(net.blocks) < challenge.hold_until_height:
            net.produce_block()
        self.assertEqual(len(net.blocks), challenge.hold_until_height)
        rate_before = net.bridge_withdrawal_release_rate_limit()
        self.assertEqual(rate_before["released_amount"], 0)
        self.assertEqual(
            rate_before["release_amount_limit"],
            devnet.BRIDGE_WITHDRAWAL_RELEASE_RATE_LIMIT_AMOUNT,
        )

        release = net.release_bridge_withdrawal(
            first.withdrawal_id,
            monero_txid="monero-release-after-hold",
            signer_labels=("bridge-signer-1", "bridge-signer-2"),
        )
        self.assertEqual(release.status, "submitted")
        self.assertEqual(release.released_at_height, len(net.blocks))
        rate_after_first = net.bridge_withdrawal_release_rate_limit()
        self.assertEqual(rate_after_first["released_amount"], 7_000)
        self.assertEqual(rate_after_first["remaining_amount"], 3_000)

        with self.assertRaisesRegex(ValueError, "rate limit"):
            net.release_bridge_withdrawal(
                second.withdrawal_id,
                monero_txid="monero-release-rate-limited",
            )

        net.produce_block()
        next_window = net.bridge_withdrawal_release_rate_limit()
        self.assertEqual(next_window["released_amount"], 0)
        second_release = net.release_bridge_withdrawal(
            second.withdrawal_id,
            monero_txid="monero-release-next-window",
        )
        self.assertEqual(second_release.status, "submitted")
        self.assertEqual(second_release.released_at_height, len(net.blocks))

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.bridge_withdrawal_challenge_root(),
            net.bridge_withdrawal_challenge_root(),
        )
        self.assertEqual(
            round_trip.bridge_withdrawals[first.withdrawal_id].release_not_before_height,
            challenge.hold_until_height,
        )

        tampered = net.state_record()
        tampered["bridge_withdrawal_challenges"][0]["auth_signature"] = "00"
        with self.assertRaisesRegex(ValueError, "invalid bridge withdrawal challenge"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_bridge_signer_set_rotation_enforces_release_quorum(self) -> None:
        net = devnet.NebulaL2Devnet()
        signer_set = net.active_bridge_signer_set()
        self.assertEqual(signer_set.threshold, 2)
        self.assertEqual(tuple(signer_set.signer_labels), devnet.DEFAULT_BRIDGE_SIGNER_LABELS)
        self.assertEqual(signer_set.auth_scheme, devnet.ACCOUNT_SIGNATURE_SCHEME)
        self.assertEqual(net.public_snapshot()["bridge_signer_set_count"], 1)
        self.assertEqual(
            net.public_snapshot()["bridge_signer_set_root"],
            net.bridge_signer_set_root(),
        )

        deposit_request = net.request_bridge_deposit_address("observer-view-key")
        with self.assertRaisesRegex(ValueError, "quorum"):
            net.observe_bridge_deposit(
                deposit_request.deposit_id,
                monero_txid="monero-deposit-too-few-signers",
                amount=1_000,
                confirmations=12,
                watcher_labels=("bridge-signer-1",),
            )
        with self.assertRaisesRegex(ValueError, "active signer set"):
            net.observe_bridge_deposit(
                deposit_request.deposit_id,
                monero_txid="monero-deposit-rogue-signer",
                amount=1_000,
                confirmations=12,
                watcher_labels=("bridge-signer-1", "bridge-signer-x"),
            )
        observation = net.observe_bridge_deposit(
            deposit_request.deposit_id,
            monero_txid="monero-deposit-default-quorum",
            amount=1_000,
            confirmations=12,
            watcher_labels=None,
        )
        self.assertEqual(observation.signer_set_id, signer_set.signer_set_id)
        self.assertEqual(observation.signer_threshold, signer_set.threshold)
        self.assertEqual(observation.public_record()["signer_count"], signer_set.threshold)

        wxmr = net.ensure_wrapped_xmr_asset()
        note = net.mint(wxmr.asset_id, "alice-view-key", 3_000)
        withdraw = net.submit_bridge_withdraw(
            note.note_id,
            monero_address="44AFFq5kSignerQuorum",
            amount=1_000,
            bridge_fee=0,
        )
        self.assertEqual(withdraw.queue_signer_set_id, signer_set.signer_set_id)
        self.assertEqual(withdraw.queue_signer_count, signer_set.threshold)
        with self.assertRaisesRegex(ValueError, "queue signer quorum"):
            net._bridge_withdrawal_proof_context(replace(withdraw, queue_signer_count=1))
        net.produce_block()
        withdrawal = net.bridge_withdrawals[withdraw.withdrawal_id]
        while len(net.blocks) < withdrawal.release_not_before_height:
            net.produce_block()

        with self.assertRaisesRegex(ValueError, "quorum"):
            net.release_bridge_withdrawal(
                withdrawal.withdrawal_id,
                monero_txid="monero-release-too-few-signers",
                signer_labels=("bridge-signer-1",),
            )
        with self.assertRaisesRegex(ValueError, "active signer set"):
            net.release_bridge_withdrawal(
                withdrawal.withdrawal_id,
                monero_txid="monero-release-rogue-signer",
                signer_labels=("bridge-signer-1", "bridge-signer-x"),
            )
        release = net.release_bridge_withdrawal(
            withdrawal.withdrawal_id,
            monero_txid="monero-release-default-set",
            signer_labels=("bridge-signer-1", "bridge-signer-2"),
        )
        self.assertEqual(release.release_signer_set_id, signer_set.signer_set_id)
        self.assertEqual(release.release_signer_count, 2)

        rotated = net.rotate_bridge_signer_set(
            signer_labels=("bridge-signer-a", "bridge-signer-b", "bridge-signer-c"),
            threshold=2,
            operator_label="bridge-guardian-2",
        )
        self.assertEqual(rotated.status, "active")
        self.assertEqual(rotated.threshold, 2)
        self.assertEqual(net.active_bridge_signer_set_id, rotated.signer_set_id)
        self.assertEqual(net.bridge_signer_sets[signer_set.signer_set_id].status, "retired")
        self.assertEqual(net.public_snapshot()["bridge_signer_set_count"], 2)

        second_note = net.mint(wxmr.asset_id, "bob-view-key", 2_000)
        second = net.submit_bridge_withdraw(
            second_note.note_id,
            monero_address="84kRotatedSignerRelease",
            amount=1_000,
            bridge_fee=0,
        )
        self.assertEqual(second.queue_signer_set_id, rotated.signer_set_id)
        self.assertEqual(second.queue_signer_count, rotated.threshold)
        net.produce_block()
        second_withdrawal = net.bridge_withdrawals[second.withdrawal_id]
        while len(net.blocks) < second_withdrawal.release_not_before_height:
            net.produce_block()
        with self.assertRaisesRegex(ValueError, "active signer set"):
            net.release_bridge_withdrawal(
                second.withdrawal_id,
                monero_txid="monero-release-old-set",
                signer_labels=("bridge-signer-1", "bridge-signer-2"),
            )
        rotated_release = net.release_bridge_withdrawal(
            second.withdrawal_id,
            monero_txid="monero-release-rotated-set",
            signer_labels=("bridge-signer-a", "bridge-signer-b"),
        )
        self.assertEqual(rotated_release.release_signer_set_id, rotated.signer_set_id)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(round_trip.active_bridge_signer_set_id, rotated.signer_set_id)
        self.assertEqual(round_trip.bridge_signer_set_root(), net.bridge_signer_set_root())

        tampered = net.state_record()
        tampered["bridge_signer_sets"][0]["signer_public_key_root"] = "00"
        with self.assertRaisesRegex(ValueError, "bridge signer public key root"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_bridge_emergency_pause_blocks_new_bridge_risk(self) -> None:
        net = devnet.NebulaL2Devnet()
        request = net.request_bridge_deposit_address("alice-view-key")
        root_before = net.bridge_root()
        signer_set = net.active_bridge_signer_set()

        pause = net.pause_bridge("reserve signer incident", operator_label="guardian-a")
        self.assertEqual(pause.action, "pause")
        self.assertTrue(pause.paused)
        self.assertEqual(pause.operator_label, "guardian-a")
        self.assertEqual(pause.emergency_signer_set_id, signer_set.signer_set_id)
        self.assertEqual(pause.emergency_signer_threshold, signer_set.threshold)
        self.assertEqual(pause.emergency_signer_count, signer_set.threshold)
        self.assertTrue(pause.emergency_signature_root)
        self.assertTrue(pause.auth_signature)
        self.assertNotIn("reserve signer incident", json.dumps(pause.public_record()))
        self.assertTrue(net.bridge_paused)
        self.assertNotEqual(root_before, net.bridge_root())
        self.assertEqual(net.public_snapshot()["bridge_paused"], True)

        with self.assertRaisesRegex(ValueError, "bridge is paused"):
            net.request_bridge_deposit_address("bob-view-key")

        observation = net.observe_bridge_deposit(
            request.deposit_id,
            monero_txid="monero-tx-paused",
            amount=5_000,
            confirmations=12,
            watcher_labels=["bridge-signer-1", "bridge-signer-2"],
        )
        self.assertEqual(observation.status, "observed")
        with self.assertRaisesRegex(ValueError, "bridge is paused"):
            net.submit_bridge_mint(request.deposit_id)

        resume = net.resume_bridge("guardian quorum restored", operator_label="guardian-a")
        self.assertEqual(resume.action, "resume")
        self.assertFalse(resume.paused)
        self.assertEqual(resume.emergency_signer_set_id, signer_set.signer_set_id)
        self.assertEqual(resume.emergency_signer_threshold, signer_set.threshold)
        self.assertEqual(resume.emergency_signer_count, signer_set.threshold)
        self.assertTrue(resume.emergency_signature_root)
        self.assertFalse(net.bridge_paused)
        mint = net.submit_bridge_mint(request.deposit_id)
        self.assertEqual(mint.amount, 5_000)

        net.pause_bridge("halt pending bridge execution", operator_label="guardian-a")
        with self.assertRaisesRegex(ValueError, "bridge is paused"):
            net.produce_block()
        net.resume_bridge("execute audited queue", operator_label="guardian-a")
        mint_block = net.produce_block()
        wxmr_asset_id = net.wrapped_xmr_asset_id
        self.assertIsNotNone(wxmr_asset_id)
        wallet = net.wallet_notes("alice-view-key")
        self.assertEqual(note_amounts(wallet, wxmr_asset_id), [5_000])

        net.pause_bridge("stop new exits", operator_label="guardian-a")
        with self.assertRaisesRegex(ValueError, "bridge is paused"):
            net.submit_bridge_withdraw(
                wallet[0]["note_id"],
                monero_address="44AFFq5kSiGBoZ...",
                amount=2_000,
                bridge_fee=10,
            )
        net.resume_bridge("exit queue reopened", operator_label="guardian-a")
        withdraw = net.submit_bridge_withdraw(
            wallet[0]["note_id"],
            monero_address="44AFFq5kSiGBoZ...",
            amount=2_000,
            bridge_fee=10,
        )
        withdraw_block = net.produce_block()
        self.assertGreater(withdraw_block.header.height, mint_block.header.height)
        withdrawal = net.bridge_withdrawals[withdraw.withdrawal_id]

        net.pause_bridge("stop release signing", operator_label="guardian-a")
        with self.assertRaisesRegex(ValueError, "bridge is paused"):
            net.release_bridge_withdrawal(
                withdrawal.withdrawal_id,
                monero_txid="monero-release-paused",
            )
        report = net.publish_bridge_reserve_report(
            reserve_amount=5_000,
            reserve_address="pause-test-reserve",
        )
        self.assertEqual(report.status, "healthy")
        with self.assertRaisesRegex(ValueError, "already paused"):
            net.pause_bridge("duplicate pause", operator_label="guardian-a")

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertTrue(round_trip.bridge_paused)
        self.assertEqual(round_trip.bridge_pause_action_id, net.bridge_pause_action_id)
        self.assertEqual(round_trip.bridge_emergency_root(), net.bridge_emergency_root())
        tampered = net.state_record()
        tampered["bridge_emergency_actions"][0]["emergency_signature_root"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "bridge emergency signature root"):
            devnet.NebulaL2Devnet.from_state_record(tampered)

    def test_monero_anchor_submission_lifecycle(self) -> None:
        net = devnet.NebulaL2Devnet()
        asset = net.create_asset("WXMR", "devnet-bridge-threshold")
        note = net.mint(asset.asset_id, "alice-view-key", 1_000)
        net.submit_private_transfer(note.note_id, "bob-view-key", amount=100, fee=1)
        block = net.produce_block()

        checkpoint = net.epoch_checkpoint_for_block(block.header.height)
        self.assertEqual(checkpoint.epoch, block.header.epoch)
        self.assertEqual(checkpoint.start_height, 0)
        self.assertEqual(checkpoint.end_height, block.header.height)
        self.assertEqual(checkpoint.block_count, 1)
        self.assertEqual(len(checkpoint.checkpoint_root()), 64)
        self.assertEqual(
            net.public_snapshot()["latest_epoch_checkpoint_root"],
            checkpoint.checkpoint_root(),
        )

        pre_anchor_status = net.settlement_status(block.header.height)
        self.assertEqual(pre_anchor_status["status"], "soft_final")
        self.assertTrue(pre_anchor_status["checkpointed"])
        self.assertFalse(pre_anchor_status["anchored"])
        self.assertFalse(pre_anchor_status["monero_final"])
        self.assertIsNone(pre_anchor_status["best_anchor"])
        self.assertEqual(pre_anchor_status["local_checkpoint_root"], checkpoint.checkpoint_root())
        self.assertEqual(pre_anchor_status["covering_anchor_count"], 0)

        root_before = net.anchor_submission_root()
        submission = net.submit_anchor(
            submitter_label="anchor-operator-1",
            monero_txid="monero-anchor-tx-001",
        )
        self.assertEqual(submission.block_height, block.header.height)
        self.assertEqual(
            submission.anchor_commitment,
            net._anchor_commitment_for_block(block.header.height),
        )
        self.assertEqual(submission.checkpoint_root, checkpoint.checkpoint_root())
        self.assertEqual(submission.epoch_start_height, checkpoint.start_height)
        self.assertEqual(submission.epoch_end_height, checkpoint.end_height)
        self.assertEqual(submission.epoch_block_count, checkpoint.block_count)
        self.assertEqual(submission.block_hash, block.header.block_hash())
        self.assertEqual(submission.bridge_root, block.header.bridge_root)
        public_submission = submission.public_record()
        self.assertEqual(public_submission["checkpoint_root"], checkpoint.checkpoint_root())
        self.assertNotIn("monero_txid", public_submission)
        self.assertEqual(
            public_submission["monero_txid_hash"],
            devnet.domain_hash("MONERO-TXID-HASH", "monero-anchor-tx-001"),
        )
        self.assertTrue(public_submission["auth_signature"])
        self.assertNotEqual(root_before, net.anchor_submission_root())
        self.assertEqual(net.public_snapshot()["anchor_submission_count"], 1)

        anchored_status = net.settlement_status(block.header.height)
        self.assertEqual(anchored_status["status"], "anchored")
        self.assertTrue(anchored_status["anchored"])
        self.assertFalse(anchored_status["monero_final"])
        self.assertEqual(anchored_status["best_anchor"]["anchor_id"], submission.anchor_id)
        self.assertEqual(anchored_status["best_anchor"]["status"], "submitted")
        self.assertEqual(anchored_status["best_anchor"]["checkpoint_root"], checkpoint.checkpoint_root())
        self.assertEqual(anchored_status["covering_anchor_count"], 1)
        self.assertEqual(anchored_status["covering_anchors"][0]["anchor_id"], submission.anchor_id)
        self.assertEqual(anchored_status["anchor_submission_root"], net.anchor_submission_root())

        with self.assertRaisesRegex(ValueError, "already submitted"):
            net.submit_anchor(
                block_height=block.header.height,
                submitter_label="anchor-operator-2",
                monero_txid="monero-anchor-tx-002",
            )

        pending = net.confirm_anchor(
            submission.anchor_id,
            confirmations=4,
            finality_depth=10,
        )
        self.assertEqual(pending.status, "submitted")
        self.assertEqual(pending.finalized_at_ms, 0)
        pending_status = net.settlement_status(block.header.height)
        self.assertEqual(pending_status["status"], "anchored")
        self.assertEqual(pending_status["best_anchor"]["confirmations"], 4)
        self.assertFalse(pending_status["monero_final"])

        final = net.confirm_anchor(
            submission.anchor_id,
            confirmations=10,
            finality_depth=10,
        )
        self.assertEqual(final.status, "final")
        self.assertGreater(final.finalized_at_ms, 0)
        final_status = net.settlement_status(block.header.height)
        self.assertEqual(final_status["status"], "monero_final")
        self.assertTrue(final_status["anchored"])
        self.assertTrue(final_status["monero_final"])
        self.assertEqual(final_status["best_anchor"]["status"], "final")
        self.assertEqual(final_status["best_anchor"]["anchor_id"], submission.anchor_id)

        with self.assertRaisesRegex(ValueError, "cannot decrease"):
            net.confirm_anchor(submission.anchor_id, confirmations=9)

        round_trip = devnet.NebulaL2Devnet.from_state_record(net.state_record())
        self.assertEqual(
            round_trip.anchor_submissions[submission.anchor_id].status,
            "final",
        )
        self.assertEqual(round_trip.anchor_submission_root(), net.anchor_submission_root())

    def test_settlement_status_uses_epoch_checkpoint_range(self) -> None:
        net = devnet.NebulaL2Devnet(epoch_size=2)
        net.create_asset("WXMR", "devnet-bridge-threshold")
        first_block = net.produce_block()
        second_block = net.produce_block()

        first_status = net.settlement_status(first_block.header.height)
        self.assertEqual(first_status["status"], "soft_final")
        self.assertFalse(first_status["anchored"])
        self.assertEqual(first_status["local_checkpoint"]["end_height"], first_block.header.height)

        submission = net.submit_anchor(
            block_height=second_block.header.height,
            submitter_label="anchor-operator-epoch",
            monero_txid="monero-anchor-tx-epoch",
        )
        covered_status = net.settlement_status(first_block.header.height)
        self.assertEqual(covered_status["status"], "anchored")
        self.assertTrue(covered_status["anchored"])
        self.assertEqual(covered_status["best_anchor"]["anchor_id"], submission.anchor_id)
        self.assertEqual(covered_status["best_anchor"]["epoch_start_height"], first_block.header.height)
        self.assertEqual(covered_status["best_anchor"]["epoch_end_height"], second_block.header.height)
        self.assertEqual(covered_status["best_anchor"]["epoch_block_count"], 2)
        self.assertEqual(covered_status["local_checkpoint"]["end_height"], first_block.header.height)
        self.assertEqual(covered_status["covering_anchor_count"], 1)

        net.confirm_anchor(submission.anchor_id, confirmations=10, finality_depth=10)
        final_status = net.settlement_status(first_block.header.height)
        self.assertEqual(final_status["status"], "monero_final")
        self.assertTrue(final_status["monero_final"])

    def test_cli_persistent_amm_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            wxmr = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            dusd = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSD",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            xmr_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "lp-view-key",
                "--amount",
                "10000",
            )
            usd_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "lp-view-key",
                "--amount",
                "20000",
            )
            pool = run_json(
                "pool",
                "--state",
                str(state_path),
                "--asset-a-id",
                wxmr["asset_id"],
                "--asset-b-id",
                dusd["asset_id"],
            )
            liquidity = run_json(
                "liquidity",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-a-id",
                xmr_note["note_id"],
                "--note-b-id",
                usd_note["note_id"],
                "--amount-a",
                "5000",
                "--amount-b",
                "10000",
                "--owner",
                "lp-view-key",
                "--network-fee",
                "5",
            )
            self.assertEqual(liquidity["lp_minted"], 7071)
            self.assertIn("proof_root", liquidity["proof_bundle"])
            run_json("block", "--state", str(state_path))

            trader_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "trader-view-key",
                "--amount",
                "1500",
            )
            swap = run_json(
                "swap",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-in-id",
                trader_note["note_id"],
                "--amount-in",
                "1000",
                "--min-amount-out",
                "1600",
                "--to",
                "trader-view-key",
                "--network-fee",
                "2",
            )
            self.assertEqual(swap["amount_out"], 1662)
            self.assertIn("proof_root", swap["proof_bundle"])
            run_json("block", "--state", str(state_path))

            batch_note_one = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "trader-view-key",
                "--amount",
                "800",
            )
            batch_note_two = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "trader-view-key",
                "--amount",
                "700",
            )
            batch = run_json(
                "batch-swap",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-in-id",
                batch_note_one["note_id"],
                "--amount-in",
                "600",
                "--note-in-id",
                batch_note_two["note_id"],
                "--amount-in",
                "400",
                "--min-total-amount-out",
                "1100",
                "--to",
                "trader-view-key",
                "--network-fee",
                "3",
            )
            self.assertEqual(batch["total_amount_out"], 1188)
            self.assertEqual(batch["input_count"], 2)
            self.assertIn("proof_root", batch["proof_bundle"])
            self.assertNotIn("spent_note_ids", batch)
            block = run_json("block", "--state", str(state_path))

            pools = run_json("pools", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(pools[0]["reserve_a"], 7000)
            self.assertEqual(pools[0]["reserve_b"], 7150)
            self.assertEqual(snapshot["pool_count"], 1)
            self.assertEqual(snapshot["height"], 3)
            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)

            sealed_note_one = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "trader-one-view-key",
                "--amount",
                "800",
            )
            sealed_note_two = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "trader-two-view-key",
                "--amount",
                "700",
            )
            first_commitment = run_json(
                "sealed-swap-commit",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-in-id",
                sealed_note_one["note_id"],
                "--amount-in",
                "600",
                "--min-amount-out",
                "500",
                "--to",
                "trader-one-view-key",
                "--network-fee",
                "2",
                "--reveal-secret",
                "cli-secret-one",
                "--min-reveal-height",
                "3",
            )
            second_commitment = run_json(
                "sealed-swap-commit",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-in-id",
                sealed_note_two["note_id"],
                "--amount-in",
                "400",
                "--min-amount-out",
                "300",
                "--to",
                "trader-two-view-key",
                "--network-fee",
                "1",
                "--reveal-secret",
                "cli-secret-two",
                "--min-reveal-height",
                "3",
            )
            commitments = run_json("sealed-commitments", "--state", str(state_path))
            self.assertEqual(commitments["sealed_swap_order_commitment_count"], 2)
            self.assertEqual(commitments["filtered_commitment_count"], 2)
            self.assertNotIn(sealed_note_one["note_id"], json.dumps(commitments))
            self.assertNotIn("trader-one-view-key", json.dumps(commitments))
            self.assertNotIn("cli-secret-one", json.dumps(commitments))
            bid = run_json(
                "sealed-bid",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--commitment-id",
                first_commitment["commitment_id"],
                "--commitment-id",
                second_commitment["commitment_id"],
                "--asset-in-id",
                wxmr["asset_id"],
                "--asset-out-id",
                dusd["asset_id"],
                "--total-amount-in",
                "1000",
                "--quoted-amount-out",
                "891",
                "--network-fee-total",
                "3",
                "--solver",
                "solver-cli",
            )
            bid_book = run_json(
                "sealed-bids",
                "--state",
                str(state_path),
                "--status",
                "active",
            )
            self.assertEqual(bid_book["filtered_bid_count"], 1)
            self.assertEqual(bid_book["bids"][0]["bid_id"], bid["bid_id"])
            self.assertNotIn("trader-one-view-key", json.dumps(bid_book))
            sealed = run_json(
                "sealed-swap",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-in-id",
                sealed_note_one["note_id"],
                "--amount-in",
                "600",
                "--min-amount-out",
                "500",
                "--to",
                "trader-one-view-key",
                "--network-fee",
                "2",
                "--note-in-id",
                sealed_note_two["note_id"],
                "--amount-in",
                "400",
                "--min-amount-out",
                "300",
                "--to",
                "trader-two-view-key",
                "--network-fee",
                "1",
                "--solver",
                "solver-cli",
                "--commitment-id",
                first_commitment["commitment_id"],
                "--reveal-secret",
                "cli-secret-one",
                "--commitment-id",
                second_commitment["commitment_id"],
                "--reveal-secret",
                "cli-secret-two",
                "--solver-bid-id",
                bid["bid_id"],
            )
            self.assertEqual(sealed["intent_count"], 2)
            self.assertEqual(sealed["total_amount_out"], 891)
            self.assertEqual(sealed["network_fee_total"], 3)
            self.assertEqual(sealed["commitment_count"], 2)
            self.assertEqual(sealed["solver_bid_id"], bid["bid_id"])
            self.assertEqual(
                sealed["commitment_root"],
                devnet.merkle_root(
                    "SEALED-SWAP-COMMITMENT-ID",
                    [
                        first_commitment["commitment_id"],
                        second_commitment["commitment_id"],
                    ],
                ),
            )
            self.assertEqual(
                sealed["solver_commitment"],
                devnet.domain_hash("SEALED-SWAP-SOLVER", "solver-cli"),
            )
            self.assertIn("proof_root", sealed["proof_bundle"])
            self.assertNotIn("fills", sealed)
            self.assertNotIn("cli-secret-one", json.dumps(sealed))
            sealed_block = run_json("block", "--state", str(state_path))
            settlements = run_json(
                "sealed-settlements",
                "--state",
                str(state_path),
                "--block-height",
                str(sealed_block["height"]),
            )
            self.assertEqual(settlements["sealed_swap_settlement_receipt_count"], 1)
            self.assertEqual(settlements["filtered_receipt_count"], 1)
            receipt = settlements["receipts"][0]
            self.assertEqual(receipt["solver_label"], "solver-cli")
            self.assertEqual(receipt["intent_count"], 2)
            self.assertEqual(receipt["intent_root"], sealed["intent_root"])
            self.assertEqual(receipt["total_amount_in"], 1000)
            self.assertEqual(receipt["total_amount_out"], 891)
            self.assertEqual(receipt["solver_bid_id"], bid["bid_id"])
            self.assertEqual(receipt["total_surplus_amount"], 91)
            self.assertEqual(receipt["clearing_price_denominator"], 1000)
            self.assertEqual(len(receipt["clearing_price_commitment_root"]), 64)
            self.assertEqual(len(receipt["aggregate_surplus_commitment_root"]), 64)
            self.assertNotIn("trader-one-view-key", json.dumps(receipt))
            self.assertNotIn("trader-two-view-key", json.dumps(receipt))
            revealed_commitments = run_json(
                "sealed-commitments",
                "--state",
                str(state_path),
                "--status",
                "revealed",
            )
            self.assertEqual(revealed_commitments["filtered_commitment_count"], 2)
            self.assertNotEqual(
                revealed_commitments["sealed_swap_order_commitment_root"],
                commitments["sealed_swap_order_commitment_root"],
            )
            won_bids = run_json(
                "sealed-bids",
                "--state",
                str(state_path),
                "--status",
                "won",
            )
            self.assertEqual(won_bids["filtered_bid_count"], 1)
            self.assertEqual(won_bids["bids"][0]["bid_id"], bid["bid_id"])

            pools = run_json("pools", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            one = run_json("wallet", "--state", str(state_path), "--owner", "trader-one-view-key")
            two = run_json("wallet", "--state", str(state_path), "--owner", "trader-two-view-key")
            self.assertEqual(pools[0]["reserve_a"], 8000)
            self.assertEqual(pools[0]["reserve_b"], 6259)
            self.assertEqual(snapshot["height"], 4)
            self.assertEqual(snapshot["sealed_swap_settlement_receipt_count"], 1)
            self.assertEqual(snapshot["sealed_swap_order_commitment_count"], 2)
            self.assertEqual(snapshot["sealed_swap_solver_bid_count"], 1)
            self.assertEqual(
                snapshot["sealed_swap_order_commitment_root"],
                revealed_commitments["sealed_swap_order_commitment_root"],
            )
            self.assertEqual(
                snapshot["sealed_swap_solver_bid_root"],
                won_bids["sealed_swap_solver_bid_root"],
            )
            self.assertEqual(
                snapshot["sealed_swap_settlement_receipt_root"],
                settlements["sealed_swap_settlement_receipt_root"],
            )
            self.assertEqual(sealed_block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(sealed_block["execution_profile"]["authorization_count"], 2)
            self.assertEqual(note_amounts(one, wxmr["asset_id"]), [198])
            self.assertEqual(note_amounts(one, dusd["asset_id"]), [534])
            self.assertEqual(note_amounts(two, wxmr["asset_id"]), [299])
            self.assertEqual(note_amounts(two, dusd["asset_id"]), [357])

            dusc = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSC",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            stable_a = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "stable-lp-view-key",
                "--amount",
                "20000",
            )
            stable_b = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusc["asset_id"],
                "--owner",
                "stable-lp-view-key",
                "--amount",
                "20000",
            )
            stable_pool = run_json(
                "pool",
                "--state",
                str(state_path),
                "--asset-a-id",
                dusd["asset_id"],
                "--asset-b-id",
                dusc["asset_id"],
                "--fee-bps",
                "5",
                "--curve",
                "stable",
            )
            self.assertEqual(stable_pool["curve"], "stable")
            stable_liquidity = run_json(
                "liquidity",
                "--state",
                str(state_path),
                "--pool-id",
                stable_pool["pool_id"],
                "--note-a-id",
                stable_a["note_id"],
                "--note-b-id",
                stable_b["note_id"],
                "--amount-a",
                "10000",
                "--amount-b",
                "10000",
                "--owner",
                "stable-lp-view-key",
                "--network-fee",
                "5",
            )
            self.assertEqual(stable_liquidity["lp_minted"], 20000)
            run_json("block", "--state", str(state_path))
            stable_trader = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "stable-trader-view-key",
                "--amount",
                "1500",
            )
            stable_swap = run_json(
                "swap",
                "--state",
                str(state_path),
                "--pool-id",
                stable_pool["pool_id"],
                "--note-in-id",
                stable_trader["note_id"],
                "--amount-in",
                "1000",
                "--min-amount-out",
                "995",
                "--to",
                "stable-trader-view-key",
                "--network-fee",
                "2",
            )
            self.assertEqual(stable_swap["amount_out"], 999)
            stable_block = run_json("block", "--state", str(state_path))
            pools = run_json("pools", "--state", str(state_path))
            stable_public = next(
                item for item in pools if item["pool_id"] == stable_pool["pool_id"]
            )
            self.assertEqual(stable_public["curve"], "stable")
            self.assertEqual(stable_public["reserve_a"], 11000)
            self.assertEqual(stable_public["reserve_b"], 9001)
            self.assertEqual(stable_block["execution_profile"]["privacy_proof_count"], 1)

    def test_cli_persistent_route_swap_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            wxmr = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            dusd = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSD",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            dusc = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSC",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            wxmr_liquidity = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "lp-one-view-key",
                "--amount",
                "10000",
            )
            dusd_liquidity = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "lp-one-view-key",
                "--amount",
                "20000",
            )
            pool_one = run_json(
                "pool",
                "--state",
                str(state_path),
                "--asset-a-id",
                wxmr["asset_id"],
                "--asset-b-id",
                dusd["asset_id"],
            )
            run_json(
                "liquidity",
                "--state",
                str(state_path),
                "--pool-id",
                pool_one["pool_id"],
                "--note-a-id",
                wxmr_liquidity["note_id"],
                "--note-b-id",
                dusd_liquidity["note_id"],
                "--amount-a",
                "5000",
                "--amount-b",
                "10000",
                "--owner",
                "lp-one-view-key",
                "--network-fee",
                "5",
            )
            dusd_stable = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "lp-two-view-key",
                "--amount",
                "20000",
            )
            dusc_stable = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusc["asset_id"],
                "--owner",
                "lp-two-view-key",
                "--amount",
                "20000",
            )
            pool_two = run_json(
                "pool",
                "--state",
                str(state_path),
                "--asset-a-id",
                dusd["asset_id"],
                "--asset-b-id",
                dusc["asset_id"],
                "--fee-bps",
                "5",
                "--curve",
                "stable",
            )
            run_json(
                "liquidity",
                "--state",
                str(state_path),
                "--pool-id",
                pool_two["pool_id"],
                "--note-a-id",
                dusd_stable["note_id"],
                "--note-b-id",
                dusc_stable["note_id"],
                "--amount-a",
                "10000",
                "--amount-b",
                "10000",
                "--owner",
                "lp-two-view-key",
                "--network-fee",
                "5",
            )
            run_json("block", "--state", str(state_path))
            trader_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "route-cli-view-key",
                "--amount",
                "1500",
            )
            quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "route-swap",
                "--input-count",
                "2",
                "--output-count",
                "2",
                "--pool-id",
                pool_one["pool_id"],
            )
            self.assertEqual(quote["operation"], "route-swap")
            route = run_json(
                "route-swap",
                "--state",
                str(state_path),
                "--pool-id",
                pool_one["pool_id"],
                "--pool-id",
                pool_two["pool_id"],
                "--note-in-id",
                trader_note["note_id"],
                "--amount-in",
                "1000",
                "--min-amount-out",
                "1600",
                "--to",
                "route-cli-view-key",
                "--network-fee",
                "2",
            )
            self.assertEqual(route["route_hop_count"], 2)
            self.assertEqual(route["hop_amounts"], [1662, 1661])
            self.assertEqual(route["amount_out"], 1661)
            self.assertNotIn(trader_note["note_id"], json.dumps(route))
            self.assertNotIn("route-cli-view-key", json.dumps(route))
            block = run_json("block", "--state", str(state_path))
            pools = run_json("pools", "--state", str(state_path))
            wallet = run_json("wallet", "--state", str(state_path), "--owner", "route-cli-view-key")
            fee_markets = run_json(
                "fee-markets",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
            )

            first_pool = next(item for item in pools if item["pool_id"] == pool_one["pool_id"])
            second_pool = next(item for item in pools if item["pool_id"] == pool_two["pool_id"])
            self.assertEqual(first_pool["reserve_a"], 6000)
            self.assertEqual(first_pool["reserve_b"], 8338)
            self.assertEqual(second_pool["reserve_a"], 11662)
            self.assertEqual(second_pool["reserve_b"], 8339)
            self.assertEqual(note_amounts(wallet, wxmr["asset_id"]), [498])
            self.assertEqual(note_amounts(wallet, dusc["asset_id"]), [1661])
            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(block["execution_profile"]["authorization_count"], 1)
            amm_pool_lanes = [
                lane for lane in fee_markets["lanes"]
                if lane["lane_type"] == "amm_pool"
            ]
            self.assertEqual(len(amm_pool_lanes), 2)

    def test_cli_persistent_dark_pool_swap_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            wxmr = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            dusd = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSD",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            alice_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "alice-view-key",
                "--amount",
                "1000",
            )
            bob_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "bob-view-key",
                "--amount",
                "2500",
            )
            quote = run_json(
                "fee-quote",
                "--state",
                str(state_path),
                "--operation",
                "dark-swap",
                "--input-count",
                "2",
                "--output-count",
                "4",
            )
            self.assertEqual(quote["operation"], "dark-swap")
            self.assertEqual(quote["candidate_profile"]["authorization_count"], 2)
            swap = run_json(
                "dark-swap",
                "--state",
                str(state_path),
                "--note-a-id",
                alice_note["note_id"],
                "--note-b-id",
                bob_note["note_id"],
                "--amount-a",
                "400",
                "--amount-b",
                "800",
                "--to-a",
                "alice-view-key",
                "--to-b",
                "bob-view-key",
                "--network-fee-a",
                "2",
                "--network-fee-b",
                "3",
                "--match-salt",
                "cli-dark-match",
            )
            self.assertEqual(swap["kind"], "dark_pool_swap")
            self.assertNotIn(alice_note["note_id"], json.dumps(swap))
            self.assertNotIn(bob_note["note_id"], json.dumps(swap))
            self.assertNotIn("alice-view-key", json.dumps(swap))
            self.assertNotIn("bob-view-key", json.dumps(swap))
            self.assertNotIn("amount_a", swap)

            block = run_json("block", "--state", str(state_path))
            alice_wallet = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            bob_wallet = run_json("wallet", "--state", str(state_path), "--owner", "bob-view-key")
            alice_history = run_json(
                "wallet-history",
                "--state",
                str(state_path),
                "--owner",
                "alice-view-key",
            )
            snapshot = run_json("snapshot", "--state", str(state_path))

            self.assertEqual(block["execution_profile"]["privacy_proof_count"], 1)
            self.assertEqual(block["execution_profile"]["authorization_count"], 2)
            self.assertEqual(note_amounts(alice_wallet, wxmr["asset_id"]), [598])
            self.assertEqual(note_amounts(alice_wallet, dusd["asset_id"]), [800])
            self.assertEqual(note_amounts(bob_wallet, wxmr["asset_id"]), [400])
            self.assertEqual(note_amounts(bob_wallet, dusd["asset_id"]), [1697])
            dark_spends = [
                event for event in alice_history["events"]
                if event["event"] == "spent" and event["kind"] == "dark_pool_swap"
            ]
            self.assertEqual(len(dark_spends), 1)
            self.assertEqual(dark_spends[0]["side"], "a")
            self.assertEqual(snapshot["height"], 1)

    def test_cli_persistent_sealed_auction_expiry_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            wxmr = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            dusd = run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "DUSD",
                "--issuer-policy",
                "devnet-stable-issuer",
            )
            xmr_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "lp-view-key",
                "--amount",
                "10000",
            )
            usd_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                dusd["asset_id"],
                "--owner",
                "lp-view-key",
                "--amount",
                "20000",
            )
            pool = run_json(
                "pool",
                "--state",
                str(state_path),
                "--asset-a-id",
                wxmr["asset_id"],
                "--asset-b-id",
                dusd["asset_id"],
            )
            run_json(
                "liquidity",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-a-id",
                xmr_note["note_id"],
                "--note-b-id",
                usd_note["note_id"],
                "--amount-a",
                "5000",
                "--amount-b",
                "10000",
                "--owner",
                "lp-view-key",
                "--network-fee",
                "5",
            )
            run_json("block", "--state", str(state_path))
            trader_note = run_json(
                "mint",
                "--state",
                str(state_path),
                "--asset-id",
                wxmr["asset_id"],
                "--owner",
                "trader-view-key",
                "--amount",
                "800",
            )
            commitment = run_json(
                "sealed-swap-commit",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--note-in-id",
                trader_note["note_id"],
                "--amount-in",
                "600",
                "--min-amount-out",
                "900",
                "--to",
                "trader-view-key",
                "--network-fee",
                "2",
                "--reveal-secret",
                "cli-expiry-secret",
                "--ttl-blocks",
                "1",
                "--min-reveal-height",
                "1",
            )
            bid = run_json(
                "sealed-bid",
                "--state",
                str(state_path),
                "--pool-id",
                pool["pool_id"],
                "--commitment-id",
                commitment["commitment_id"],
                "--asset-in-id",
                wxmr["asset_id"],
                "--asset-out-id",
                dusd["asset_id"],
                "--total-amount-in",
                "600",
                "--quoted-amount-out",
                "1000",
                "--network-fee-total",
                "2",
                "--solver",
                "solver-expiry-cli",
                "--ttl-blocks",
                "1",
            )
            run_json("block", "--state", str(state_path))
            run_json("block", "--state", str(state_path))
            report = run_json("sealed-expire", "--state", str(state_path))
            commitments = run_json(
                "sealed-commitments",
                "--state",
                str(state_path),
                "--status",
                "expired",
            )
            bids = run_json(
                "sealed-bids",
                "--state",
                str(state_path),
                "--status",
                "expired",
            )
            snapshot = run_json("snapshot", "--state", str(state_path))

            self.assertEqual(report["expired_commitment_count"], 1)
            self.assertEqual(report["expired_solver_bid_count"], 1)
            self.assertEqual(commitments["filtered_commitment_count"], 1)
            self.assertEqual(bids["filtered_bid_count"], 1)
            self.assertEqual(
                commitments["commitments"][0]["commitment_id"],
                commitment["commitment_id"],
            )
            self.assertEqual(bids["bids"][0]["bid_id"], bid["bid_id"])
            self.assertEqual(
                snapshot["sealed_swap_order_commitment_root"],
                report["sealed_swap_order_commitment_root"],
            )
            self.assertEqual(
                snapshot["sealed_swap_solver_bid_root"],
                report["sealed_swap_solver_bid_root"],
            )
            self.assertNotIn("cli-expiry-secret", json.dumps(report))
            self.assertNotIn("trader-view-key", json.dumps(report))

    def test_cli_persistent_bridge_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            request = run_json(
                "bridge-deposit",
                "--state",
                str(state_path),
                "--owner",
                "alice-view-key",
            )
            self.assertTrue(request["monero_address"].startswith("xmr-devnet-"))

            observation = run_json(
                "bridge-observe",
                "--state",
                str(state_path),
                "--deposit-id",
                request["deposit_id"],
                "--monero-txid",
                "monero-tx-abc",
                "--amount",
                "7000",
                "--confirmations",
                "14",
                "--watcher",
                "bridge-signer-1",
                "--watcher",
                "bridge-signer-2",
            )
            self.assertEqual(observation["status"], "observed")
            self.assertEqual(observation["signer_count"], 2)
            self.assertEqual(observation["signer_threshold"], 2)
            self.assertTrue(observation["signer_set_id"])

            mint = run_json(
                "bridge-mint",
                "--state",
                str(state_path),
                "--deposit-id",
                request["deposit_id"],
            )
            self.assertEqual(mint["amount"], 7000)
            self.assertEqual(mint["signer_set_id"], observation["signer_set_id"])
            self.assertEqual(mint["signer_threshold"], observation["signer_threshold"])
            self.assertEqual(mint["signer_count"], observation["signer_count"])
            mint_block = run_json("block", "--state", str(state_path))

            snapshot = run_json("snapshot", "--state", str(state_path))
            wxmr_asset_id = snapshot["wrapped_xmr_asset_id"]
            self.assertEqual(mint_block["bridge_root"], snapshot["bridge_root"])
            wallet = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            self.assertEqual(note_amounts(wallet, wxmr_asset_id), [7000])

            withdraw = run_json(
                "bridge-withdraw",
                "--state",
                str(state_path),
                "--spent-note-id",
                wallet[0]["note_id"],
                "--monero-address",
                "84kDevnetWithdrawAddress",
                "--amount",
                "3000",
                "--bridge-fee",
                "10",
            )
            self.assertEqual(withdraw["amount"], 3000)
            self.assertTrue(withdraw["auth_signature"])
            self.assertIn("proof_root", withdraw["proof_bundle"])
            self.assertEqual(withdraw["queue_signer_set_id"], observation["signer_set_id"])
            self.assertEqual(withdraw["queue_signer_threshold"], observation["signer_threshold"])
            self.assertEqual(withdraw["queue_signer_count"], observation["signer_threshold"])
            withdraw_block = run_json("block", "--state", str(state_path))

            bridge = run_json("bridge", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            wallet = run_json("wallet", "--state", str(state_path), "--owner", "alice-view-key")
            self.assertEqual(withdraw_block["bridge_root"], snapshot["bridge_root"])
            self.assertEqual(len(bridge["withdrawals"]), 1)
            self.assertEqual(bridge["withdrawals"][0]["status"], "queued")
            self.assertEqual(bridge["withdrawals"][0]["queue_signer_set_id"], observation["signer_set_id"])
            self.assertEqual(bridge["withdrawals"][0]["queue_signer_threshold"], observation["signer_threshold"])
            self.assertEqual(bridge["withdrawals"][0]["queue_signer_count"], observation["signer_threshold"])
            self.assertEqual(bridge["withdrawals"][0]["requested_at_height"], withdraw_block["height"])
            self.assertEqual(bridge["withdrawals"][0]["amount_bucket"], 3000)
            self.assertEqual(
                bridge["withdrawals"][0]["privacy_delay_blocks"],
                devnet.BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS,
            )
            self.assertEqual(
                bridge["withdrawals"][0]["release_not_before_height"],
                withdraw_block["height"] + devnet.BRIDGE_WITHDRAWAL_RELEASE_DELAY_BLOCKS,
            )
            self.assertEqual(bridge["withdrawals"][0]["release_monero_txid_hash"], "")
            self.assertEqual(bridge["reserve_liabilities"]["circulating_amount"], 4000)
            self.assertEqual(bridge["reserve_liabilities"]["queued_withdrawal_amount"], 3000)
            self.assertEqual(bridge["reserve_liabilities"]["outstanding_liability"], 7000)
            self.assertEqual(note_amounts(wallet, wxmr_asset_id), [3990])

            reserve = run_json(
                "bridge-reserve-report",
                "--state",
                str(state_path),
                "--reserve-address",
                "cli-reserve-vault",
                "--reserve-amount",
                "7000",
                "--reporter",
                "reserve-auditor-1",
                "--reporter",
                "reserve-auditor-2",
            )
            self.assertEqual(reserve["status"], "healthy")
            self.assertEqual(reserve["reported_reserve_amount"], 7000)
            self.assertEqual(reserve["circulating_amount"], 4000)
            self.assertEqual(reserve["queued_withdrawal_amount"], 3000)
            self.assertEqual(reserve["outstanding_liability"], 7000)
            self.assertEqual(reserve["reporter_count"], 2)
            self.assertNotIn("cli-reserve-vault", json.dumps(reserve))

            challenge = run_json(
                "bridge-withdraw-challenge",
                "--state",
                str(state_path),
                "--withdrawal-id",
                bridge["withdrawals"][0]["withdrawal_id"],
                "--type",
                "watchtower-hold",
                "--evidence",
                "manual review window",
                "--reporter",
                "bridge-watchtower-cli",
                "--hold-blocks",
                "2",
            )
            self.assertEqual(challenge["withdrawal_id"], bridge["withdrawals"][0]["withdrawal_id"])
            self.assertEqual(challenge["challenge_type"], "watchtower-hold")
            self.assertNotIn("manual review window", json.dumps(challenge))
            challenges = run_json(
                "bridge-withdraw-challenges",
                "--state",
                str(state_path),
                "--withdrawal-id",
                bridge["withdrawals"][0]["withdrawal_id"],
            )
            self.assertEqual(challenges["bridge_withdrawal_challenge_count"], 1)
            self.assertEqual(challenges["filtered_challenge_count"], 1)
            self.assertEqual(challenges["challenges"][0]["challenge_id"], challenge["challenge_id"])
            bridge = run_json("bridge", "--state", str(state_path))
            self.assertEqual(bridge["withdrawal_challenge_count"], 1)
            self.assertEqual(bridge["withdrawal_challenges"][0]["challenge_id"], challenge["challenge_id"])
            self.assertEqual(
                bridge["withdrawals"][0]["release_not_before_height"],
                challenge["hold_until_height"],
            )
            signers = run_json("bridge-signers", "--state", str(state_path))
            self.assertEqual(signers["bridge_signer_set_count"], 1)
            self.assertEqual(signers["active_bridge_signer_set"]["threshold"], 2)
            rotated_signers = run_json(
                "bridge-signer-rotate",
                "--state",
                str(state_path),
                "--signer",
                "bridge-signer-a",
                "--signer",
                "bridge-signer-b",
                "--signer",
                "bridge-signer-c",
                "--threshold",
                "2",
                "--operator",
                "bridge-guardian-cli",
            )
            self.assertEqual(rotated_signers["threshold"], 2)
            self.assertEqual(rotated_signers["status"], "active")
            bridge = run_json("bridge", "--state", str(state_path))
            self.assertEqual(bridge["active_signer_set_id"], rotated_signers["signer_set_id"])
            self.assertEqual(bridge["active_signer_set"]["signer_count"], 3)

            delay_block = run_json("block", "--state", str(state_path))
            self.assertEqual(delay_block["execution_profile"]["tx_count"], 0)
            if delay_block["height"] + 1 < challenge["hold_until_height"]:
                delay_block = run_json("block", "--state", str(state_path))
                self.assertEqual(delay_block["execution_profile"]["tx_count"], 0)

            release = run_json(
                "bridge-withdraw-release",
                "--state",
                str(state_path),
                "--withdrawal-id",
                bridge["withdrawals"][0]["withdrawal_id"],
                "--monero-txid",
                "cli-monero-withdrawal-release",
                "--signer",
                "bridge-signer-a",
                "--signer",
                "bridge-signer-b",
            )
            self.assertEqual(release["status"], "submitted")
            self.assertEqual(release["release_signer_count"], 2)
            self.assertEqual(release["release_signer_set_id"], rotated_signers["signer_set_id"])
            self.assertEqual(release["release_confirmations"], 0)
            self.assertEqual(
                release["release_monero_txid_hash"],
                devnet.domain_hash("MONERO-TXID-HASH", "cli-monero-withdrawal-release"),
            )
            self.assertEqual(release["released_at_height"], challenge["hold_until_height"])
            self.assertNotIn("monero_txid", release)
            rate_limit = run_json("bridge-rate-limit", "--state", str(state_path))
            self.assertEqual(rate_limit["released_amount"], 3000)
            self.assertEqual(rate_limit["remaining_amount"], 7000)

            pending_release = run_json(
                "bridge-withdraw-confirm",
                "--state",
                str(state_path),
                "--withdrawal-id",
                bridge["withdrawals"][0]["withdrawal_id"],
                "--confirmations",
                "5",
                "--finality-depth",
                "10",
            )
            self.assertEqual(pending_release["status"], "submitted")
            self.assertEqual(pending_release["release_confirmations"], 5)

            completed_release = run_json(
                "bridge-withdraw-confirm",
                "--state",
                str(state_path),
                "--withdrawal-id",
                bridge["withdrawals"][0]["withdrawal_id"],
                "--confirmations",
                "10",
                "--finality-depth",
                "10",
            )
            self.assertEqual(completed_release["status"], "completed")
            self.assertGreater(completed_release["completed_at_ms"], 0)

            bridge = run_json("bridge", "--state", str(state_path))
            self.assertEqual(bridge["withdrawals"][0]["status"], "completed")
            self.assertEqual(bridge["withdrawals"][0]["release_confirmations"], 10)
            self.assertEqual(len(bridge["reserve_reports"]), 1)
            self.assertEqual(bridge["reserve_reports"][0]["report_id"], reserve["report_id"])
            self.assertEqual(len(bridge["reserve_report_root"]), 64)

            completed_reserve = run_json(
                "bridge-reserve-report",
                "--state",
                str(state_path),
                "--reserve-address",
                "cli-reserve-vault",
                "--reserve-amount",
                "4000",
            )
            self.assertEqual(completed_reserve["status"], "healthy")
            self.assertEqual(completed_reserve["circulating_amount"], 4000)
            self.assertEqual(completed_reserve["completed_withdrawal_amount"], 3000)
            self.assertEqual(completed_reserve["outstanding_liability"], 4000)
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(snapshot["bridge_reserve_report_count"], 2)
            self.assertEqual(len(snapshot["bridge_reserve_report_root"]), 64)

    def test_cli_persistent_bridge_emergency_pause_flow(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            def run_raw(*args: str):
                return subprocess.run(
                    [sys.executable, str(script), *args],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            run_json("init", "--state", str(state_path))
            signers = run_json("bridge-signers", "--state", str(state_path))
            active_signer_set = signers["active_bridge_signer_set"]
            pause = run_json(
                "bridge-pause",
                "--state",
                str(state_path),
                "--reason",
                "operator incident",
                "--operator",
                "guardian-cli",
            )
            self.assertEqual(pause["action"], "pause")
            self.assertTrue(pause["paused"])
            self.assertEqual(pause["operator_label"], "guardian-cli")
            self.assertEqual(
                pause["emergency_signer_set_id"],
                active_signer_set["signer_set_id"],
            )
            self.assertEqual(
                pause["emergency_signer_threshold"],
                active_signer_set["threshold"],
            )
            self.assertEqual(pause["emergency_signer_count"], active_signer_set["threshold"])
            self.assertTrue(pause["emergency_signature_root"])
            self.assertNotIn("operator incident", json.dumps(pause))

            bridge = run_json("bridge", "--state", str(state_path))
            self.assertTrue(bridge["paused"])
            self.assertEqual(bridge["pause_action_id"], pause["action_id"])
            self.assertEqual(len(bridge["emergency_actions"]), 1)
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertTrue(snapshot["bridge_paused"])
            self.assertEqual(snapshot["bridge_pause_action_id"], pause["action_id"])
            self.assertEqual(len(snapshot["bridge_emergency_root"]), 64)

            failed_deposit = run_raw(
                "bridge-deposit",
                "--state",
                str(state_path),
                "--owner",
                "alice-view-key",
            )
            self.assertNotEqual(failed_deposit.returncode, 0)
            self.assertIn("bridge is paused", failed_deposit.stderr)

            resume = run_json(
                "bridge-resume",
                "--state",
                str(state_path),
                "--reason",
                "quorum restored",
                "--operator",
                "guardian-cli",
            )
            self.assertEqual(resume["action"], "resume")
            self.assertFalse(resume["paused"])
            self.assertEqual(
                resume["emergency_signer_set_id"],
                active_signer_set["signer_set_id"],
            )
            self.assertEqual(
                resume["emergency_signer_threshold"],
                active_signer_set["threshold"],
            )
            self.assertEqual(resume["emergency_signer_count"], active_signer_set["threshold"])
            self.assertTrue(resume["emergency_signature_root"])
            bridge = run_json("bridge", "--state", str(state_path))
            self.assertFalse(bridge["paused"])
            self.assertEqual(len(bridge["emergency_actions"]), 2)

            request = run_json(
                "bridge-deposit",
                "--state",
                str(state_path),
                "--owner",
                "alice-view-key",
            )
            self.assertTrue(request["monero_address"].startswith("xmr-devnet-"))

    def test_cli_persistent_anchor_lifecycle(self) -> None:
        script = Path(__file__).with_name("devnet.py")

        with tempfile.TemporaryDirectory() as tmpdir:
            state_path = Path(tmpdir) / "state.json"

            def run_json(*args: str):
                completed = subprocess.run(
                    [sys.executable, str(script), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return json.loads(completed.stdout)

            run_json("init", "--state", str(state_path))
            run_json(
                "asset",
                "--state",
                str(state_path),
                "--symbol",
                "WXMR",
                "--issuer-policy",
                "devnet-bridge-threshold",
            )
            block = run_json("block", "--state", str(state_path))
            anchor_info = run_json("anchor", "--state", str(state_path))
            checkpoint = run_json(
                "epoch-checkpoint",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
            )
            self.assertEqual(anchor_info["anchor_submission_count"], 0)
            self.assertEqual(len(anchor_info["anchor_commitment"]), 64)
            self.assertEqual(checkpoint["epoch"], block["epoch"])
            self.assertEqual(checkpoint["end_height"], block["height"])
            self.assertEqual(checkpoint["block_count"], 1)
            self.assertEqual(len(checkpoint["checkpoint_root"]), 64)

            pre_anchor_status = run_json(
                "settlement",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
            )
            self.assertEqual(pre_anchor_status["status"], "soft_final")
            self.assertFalse(pre_anchor_status["anchored"])
            self.assertFalse(pre_anchor_status["monero_final"])
            self.assertIsNone(pre_anchor_status["best_anchor"])
            self.assertEqual(pre_anchor_status["local_checkpoint_root"], checkpoint["checkpoint_root"])

            submission = run_json(
                "anchor-submit",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
                "--submitter",
                "anchor-cli-operator",
                "--monero-txid",
                "cli-monero-anchor-tx",
            )
            self.assertEqual(submission["block_height"], block["height"])
            self.assertEqual(submission["anchor_commitment"], anchor_info["anchor_commitment"])
            self.assertEqual(submission["checkpoint_root"], checkpoint["checkpoint_root"])
            self.assertEqual(submission["epoch_start_height"], checkpoint["start_height"])
            self.assertEqual(submission["epoch_end_height"], checkpoint["end_height"])
            self.assertEqual(submission["epoch_block_count"], checkpoint["block_count"])
            self.assertEqual(submission["status"], "submitted")
            self.assertNotIn("monero_txid", submission)
            self.assertTrue(submission["auth_signature"])

            anchored_status = run_json(
                "settlement",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
            )
            self.assertEqual(anchored_status["status"], "anchored")
            self.assertTrue(anchored_status["anchored"])
            self.assertFalse(anchored_status["monero_final"])
            self.assertEqual(anchored_status["best_anchor"]["anchor_id"], submission["anchor_id"])
            self.assertEqual(anchored_status["best_anchor"]["checkpoint_root"], checkpoint["checkpoint_root"])
            self.assertEqual(anchored_status["covering_anchor_count"], 1)

            pending = run_json(
                "anchor-confirm",
                "--state",
                str(state_path),
                "--anchor-id",
                submission["anchor_id"],
                "--confirmations",
                "5",
                "--finality-depth",
                "10",
            )
            self.assertEqual(pending["status"], "submitted")
            pending_status = run_json(
                "settlement",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
            )
            self.assertEqual(pending_status["status"], "anchored")
            self.assertEqual(pending_status["best_anchor"]["confirmations"], 5)

            final = run_json(
                "anchor-confirm",
                "--state",
                str(state_path),
                "--anchor-id",
                submission["anchor_id"],
                "--confirmations",
                "10",
                "--finality-depth",
                "10",
            )
            self.assertEqual(final["status"], "final")
            self.assertGreater(final["finalized_at_ms"], 0)
            final_status = run_json(
                "settlement",
                "--state",
                str(state_path),
                "--block-height",
                str(block["height"]),
            )
            self.assertEqual(final_status["status"], "monero_final")
            self.assertTrue(final_status["anchored"])
            self.assertTrue(final_status["monero_final"])
            self.assertEqual(final_status["best_anchor"]["anchor_id"], submission["anchor_id"])

            anchors = run_json("anchors", "--state", str(state_path))
            snapshot = run_json("snapshot", "--state", str(state_path))
            self.assertEqual(len(anchors["submissions"]), 1)
            self.assertEqual(anchors["submissions"][0]["status"], "final")
            self.assertEqual(snapshot["anchor_submission_count"], 1)
            self.assertEqual(
                snapshot["anchor_submission_root"],
                anchors["anchor_submission_root"],
            )
            self.assertEqual(
                final_status["anchor_submission_root"],
                anchors["anchor_submission_root"],
            )
            self.assertEqual(
                snapshot["latest_epoch_checkpoint_root"],
                checkpoint["checkpoint_root"],
            )


if __name__ == "__main__":
    unittest.main()
