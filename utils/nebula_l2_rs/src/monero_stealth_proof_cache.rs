use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroStealthProofCacheResult<T> = Result<T, String>;

pub const MONERO_STEALTH_PROOF_CACHE_PROTOCOL_VERSION: &str =
    "nebula-monero-stealth-proof-cache-v1";
pub const MONERO_STEALTH_PROOF_CACHE_PROOF_SYSTEM: &str = "zk-monero-stealth-address-membership-v1";
pub const MONERO_STEALTH_PROOF_CACHE_PQ_SIGNATURE_SCHEME: &str =
    "ml-dsa-87+shake256-watcher-attestation";
pub const MONERO_STEALTH_PROOF_CACHE_VIEW_TAG_SCHEME: &str = "monero-view-tag-accelerator-v1";
pub const MONERO_STEALTH_PROOF_CACHE_DEFAULT_TTL_BLOCKS: u64 = 720;
pub const MONERO_STEALTH_PROOF_CACHE_DEFAULT_REORG_DEPTH: u64 = 32;
pub const MONERO_STEALTH_PROOF_CACHE_DEFAULT_SPONSOR_UNITS: u64 = 250_000;
pub const MONERO_STEALTH_PROOF_CACHE_DEFAULT_PRIVACY_BUDGET_UNITS: u64 = 16_384;
pub const MONERO_STEALTH_PROOF_CACHE_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 750;
pub const MONERO_STEALTH_PROOF_CACHE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CacheEntryStatus {
    Pending,
    Hot,
    Cold,
    Invalidated,
    Expired,
}

impl CacheEntryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Hot => "hot",
            Self::Cold => "cold",
            Self::Invalidated => "invalidated",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Pending | Self::Hot | Self::Cold)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProofStatus {
    Committed,
    Verified,
    ReorgQuarantined,
    Superseded,
    Expired,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Verified => "verified",
            Self::ReorgQuarantined => "reorg_quarantined",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Committed | Self::Verified)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum WatcherRole {
    Scanner,
    PqAttester,
    ReorgSentinel,
    SponsorAuditor,
}

impl WatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scanner => "scanner",
            Self::PqAttester => "pq_attester",
            Self::ReorgSentinel => "reorg_sentinel",
            Self::SponsorAuditor => "sponsor_auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SponsorshipStatus {
    Funded,
    Reserved,
    Settled,
    Slashed,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funded => "funded",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Funded | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReorgInvalidationKind {
    DepthExceeded,
    ConflictingOutputProof,
    DuplicateKeyImage,
    WatcherQuorumRollback,
}

impl ReorgInvalidationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepthExceeded => "depth_exceeded",
            Self::ConflictingOutputProof => "conflicting_output_proof",
            Self::DuplicateKeyImage => "duplicate_key_image",
            Self::WatcherQuorumRollback => "watcher_quorum_rollback",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroStealthProofCacheConfig {
    pub ttl_blocks: u64,
    pub reorg_depth: u64,
    pub max_disclosure_bps: u64,
    pub default_sponsor_units: u64,
    pub default_privacy_budget_units: u64,
    pub min_pq_security_bits: u16,
    pub proof_system: String,
    pub pq_signature_scheme: String,
    pub view_tag_scheme: String,
}

impl MoneroStealthProofCacheConfig {
    pub fn devnet() -> Self {
        Self {
            ttl_blocks: MONERO_STEALTH_PROOF_CACHE_DEFAULT_TTL_BLOCKS,
            reorg_depth: MONERO_STEALTH_PROOF_CACHE_DEFAULT_REORG_DEPTH,
            max_disclosure_bps: MONERO_STEALTH_PROOF_CACHE_DEFAULT_MAX_DISCLOSURE_BPS,
            default_sponsor_units: MONERO_STEALTH_PROOF_CACHE_DEFAULT_SPONSOR_UNITS,
            default_privacy_budget_units: MONERO_STEALTH_PROOF_CACHE_DEFAULT_PRIVACY_BUDGET_UNITS,
            min_pq_security_bits: 256,
            proof_system: MONERO_STEALTH_PROOF_CACHE_PROOF_SYSTEM.to_string(),
            pq_signature_scheme: MONERO_STEALTH_PROOF_CACHE_PQ_SIGNATURE_SCHEME.to_string(),
            view_tag_scheme: MONERO_STEALTH_PROOF_CACHE_VIEW_TAG_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ttl_blocks": self.ttl_blocks,
            "reorg_depth": self.reorg_depth,
            "max_disclosure_bps": self.max_disclosure_bps,
            "default_sponsor_units": self.default_sponsor_units,
            "default_privacy_budget_units": self.default_privacy_budget_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "proof_system": self.proof_system,
            "pq_signature_scheme": self.pq_signature_scheme,
            "view_tag_scheme": self.view_tag_scheme,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> MoneroStealthProofCacheResult<()> {
        ensure_positive("ttl_blocks", self.ttl_blocks)?;
        ensure_positive("reorg_depth", self.reorg_depth)?;
        ensure_bps("max_disclosure_bps", self.max_disclosure_bps)?;
        ensure_positive("default_sponsor_units", self.default_sponsor_units)?;
        ensure_positive(
            "default_privacy_budget_units",
            self.default_privacy_budget_units,
        )?;
        ensure_nonempty("proof_system", &self.proof_system)?;
        ensure_nonempty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_nonempty("view_tag_scheme", &self.view_tag_scheme)?;
        if self.min_pq_security_bits < 192 {
            return Err("monero stealth cache pq security below 192 bits".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthCacheWatcher {
    pub watcher_id: String,
    pub operator_commitment: String,
    pub role: WatcherRole,
    pub pq_public_key_commitment: String,
    pub bond_asset_id: String,
    pub bond_units: u64,
    pub attestation_weight: u64,
    pub last_seen_height: u64,
    pub active: bool,
}

impl StealthCacheWatcher {
    pub fn devnet(label: &str, role: WatcherRole, height: u64) -> Self {
        let watcher_id = monero_stealth_proof_cache_string_root("WATCHER-ID", label);
        Self {
            watcher_id: watcher_id.clone(),
            operator_commitment: monero_stealth_proof_cache_string_root("WATCHER-OPERATOR", label),
            role,
            pq_public_key_commitment: monero_stealth_proof_cache_string_root(
                "WATCHER-PQ-PUBKEY",
                label,
            ),
            bond_asset_id: "dxmr".to_string(),
            bond_units: 50_000,
            attestation_weight: match role {
                WatcherRole::Scanner => 1,
                WatcherRole::PqAttester => 2,
                WatcherRole::ReorgSentinel => 3,
                WatcherRole::SponsorAuditor => 1,
            },
            last_seen_height: height,
            active: true,
        }
    }

    pub fn set_height(&mut self, height: u64, ttl_blocks: u64) {
        if height > self.last_seen_height.saturating_add(ttl_blocks) {
            self.active = false;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watcher_id": self.watcher_id,
            "operator_commitment": self.operator_commitment,
            "role": self.role.as_str(),
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "bond_asset_id": self.bond_asset_id,
            "bond_units": self.bond_units,
            "attestation_weight": self.attestation_weight,
            "last_seen_height": self.last_seen_height,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("WATCHER", &self.public_record())
    }

    pub fn validate(&self) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("watcher_id", &self.watcher_id)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        ensure_nonempty("bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("bond_units", self.bond_units)?;
        ensure_positive("attestation_weight", self.attestation_weight)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagCacheEntry {
    pub entry_id: String,
    pub view_tag_commitment: String,
    pub output_key_commitment: String,
    pub encrypted_match_hint: String,
    pub scan_epoch: u64,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: CacheEntryStatus,
    pub watcher_ids: Vec<String>,
    pub privacy_budget_units: u64,
    pub disclosure_bps: u64,
}

impl ViewTagCacheEntry {
    pub fn devnet(
        index: u64,
        watcher_ids: Vec<String>,
        height: u64,
        config: &MoneroStealthProofCacheConfig,
    ) -> Self {
        let seed = format!("view-tag:{index}:{height}");
        Self {
            entry_id: monero_stealth_proof_cache_string_root("VIEW-TAG-ENTRY", &seed),
            view_tag_commitment: monero_stealth_proof_cache_string_root("VIEW-TAG", &seed),
            output_key_commitment: monero_stealth_proof_cache_string_root("OUTPUT-KEY", &seed),
            encrypted_match_hint: monero_stealth_proof_cache_string_root("MATCH-HINT", &seed),
            scan_epoch: height / config.ttl_blocks.max(1),
            first_seen_height: height,
            expires_at_height: height.saturating_add(config.ttl_blocks),
            status: if index % 2 == 0 {
                CacheEntryStatus::Hot
            } else {
                CacheEntryStatus::Cold
            },
            watcher_ids,
            privacy_budget_units: config.default_privacy_budget_units / 4,
            disclosure_bps: config.max_disclosure_bps / 3,
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.live() {
            self.status = CacheEntryStatus::Expired;
        }
    }

    pub fn invalidate_for_reorg(&mut self) {
        if self.status.live() {
            self.status = CacheEntryStatus::Invalidated;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "view_tag_commitment": self.view_tag_commitment,
            "output_key_commitment": self.output_key_commitment,
            "encrypted_match_hint": self.encrypted_match_hint,
            "scan_epoch": self.scan_epoch,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "watcher_ids": self.watcher_ids,
            "privacy_budget_units": self.privacy_budget_units,
            "disclosure_bps": self.disclosure_bps,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("VIEW-TAG-CACHE-ENTRY", &self.public_record())
    }

    pub fn validate(
        &self,
        watchers: &BTreeMap<String, StealthCacheWatcher>,
    ) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("entry_id", &self.entry_id)?;
        ensure_nonempty("view_tag_commitment", &self.view_tag_commitment)?;
        ensure_nonempty("output_key_commitment", &self.output_key_commitment)?;
        ensure_nonempty("encrypted_match_hint", &self.encrypted_match_hint)?;
        ensure_ordered_heights(
            "view tag cache entry",
            self.first_seen_height,
            self.expires_at_height,
        )?;
        ensure_bps("disclosure_bps", self.disclosure_bps)?;
        if self.watcher_ids.is_empty() {
            return Err(format!(
                "view tag entry {} missing watcher quorum",
                self.entry_id
            ));
        }
        for watcher_id in &self.watcher_ids {
            if !watchers.contains_key(watcher_id) {
                return Err(format!(
                    "view tag entry {} references unknown watcher {}",
                    self.entry_id, watcher_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeAddressProof {
    pub proof_id: String,
    pub output_key_commitment: String,
    pub one_time_address_commitment: String,
    pub key_image_nullifier: String,
    pub proof_commitment: String,
    pub verifier_key_commitment: String,
    pub status: ProofStatus,
    pub cache_entry_id: String,
    pub block_height: u64,
    pub expires_at_height: u64,
    pub pq_attestation_ids: Vec<String>,
}

impl OneTimeAddressProof {
    pub fn devnet(
        index: u64,
        cache_entry_id: &str,
        height: u64,
        config: &MoneroStealthProofCacheConfig,
    ) -> Self {
        let seed = format!("one-time-proof:{index}:{cache_entry_id}");
        Self {
            proof_id: monero_stealth_proof_cache_string_root("PROOF-ID", &seed),
            output_key_commitment: monero_stealth_proof_cache_string_root("PROOF-OUTPUT", &seed),
            one_time_address_commitment: monero_stealth_proof_cache_string_root(
                "ONE-TIME-ADDRESS",
                &seed,
            ),
            key_image_nullifier: monero_stealth_proof_cache_string_root(
                "KEY-IMAGE-NULLIFIER",
                &seed,
            ),
            proof_commitment: monero_stealth_proof_cache_string_root("PROOF-COMMITMENT", &seed),
            verifier_key_commitment: monero_stealth_proof_cache_string_root("PROOF-VK", &seed),
            status: if index % 2 == 0 {
                ProofStatus::Verified
            } else {
                ProofStatus::Committed
            },
            cache_entry_id: cache_entry_id.to_string(),
            block_height: height,
            expires_at_height: height.saturating_add(config.ttl_blocks),
            pq_attestation_ids: Vec::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.usable() {
            self.status = ProofStatus::Expired;
        }
    }

    pub fn quarantine_for_reorg(&mut self) {
        if self.status.usable() {
            self.status = ProofStatus::ReorgQuarantined;
        }
    }

    pub fn attach_attestation(&mut self, attestation_id: String) {
        if !self.pq_attestation_ids.contains(&attestation_id) {
            self.pq_attestation_ids.push(attestation_id);
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "output_key_commitment": self.output_key_commitment,
            "one_time_address_commitment": self.one_time_address_commitment,
            "key_image_nullifier": self.key_image_nullifier,
            "proof_commitment": self.proof_commitment,
            "verifier_key_commitment": self.verifier_key_commitment,
            "status": self.status.as_str(),
            "cache_entry_id": self.cache_entry_id,
            "block_height": self.block_height,
            "expires_at_height": self.expires_at_height,
            "pq_attestation_ids": self.pq_attestation_ids,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("ONE-TIME-ADDRESS-PROOF", &self.public_record())
    }

    pub fn validate(
        &self,
        cache_entries: &BTreeMap<String, ViewTagCacheEntry>,
    ) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("proof_id", &self.proof_id)?;
        ensure_nonempty("output_key_commitment", &self.output_key_commitment)?;
        ensure_nonempty(
            "one_time_address_commitment",
            &self.one_time_address_commitment,
        )?;
        ensure_nonempty("key_image_nullifier", &self.key_image_nullifier)?;
        ensure_nonempty("proof_commitment", &self.proof_commitment)?;
        ensure_nonempty("verifier_key_commitment", &self.verifier_key_commitment)?;
        ensure_nonempty("cache_entry_id", &self.cache_entry_id)?;
        ensure_ordered_heights(
            "one-time address proof",
            self.block_height,
            self.expires_at_height,
        )?;
        if !cache_entries.contains_key(&self.cache_entry_id) {
            return Err(format!(
                "proof {} references missing cache entry {}",
                self.proof_id, self.cache_entry_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub height: u64,
    pub expires_at_height: u64,
}

impl PqWatcherAttestation {
    pub fn devnet(
        index: u64,
        watcher_id: &str,
        subject_id: &str,
        subject_root: &str,
        height: u64,
        config: &MoneroStealthProofCacheConfig,
    ) -> Self {
        let seed = format!("attestation:{index}:{watcher_id}:{subject_id}");
        Self {
            attestation_id: monero_stealth_proof_cache_string_root("ATTESTATION-ID", &seed),
            watcher_id: watcher_id.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            signature_root: monero_stealth_proof_cache_string_root("PQ-SIGNATURE", &seed),
            transcript_root: monero_stealth_proof_cache_string_root("PQ-TRANSCRIPT", &seed),
            security_bits: config.min_pq_security_bits,
            height,
            expires_at_height: height.saturating_add(config.ttl_blocks),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height {
            self.security_bits = self.security_bits.saturating_sub(1);
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "height": self.height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("PQ-WATCHER-ATTESTATION", &self.public_record())
    }

    pub fn validate(
        &self,
        watchers: &BTreeMap<String, StealthCacheWatcher>,
        config: &MoneroStealthProofCacheConfig,
    ) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("attestation_id", &self.attestation_id)?;
        ensure_nonempty("watcher_id", &self.watcher_id)?;
        ensure_nonempty("subject_id", &self.subject_id)?;
        ensure_nonempty("subject_root", &self.subject_root)?;
        ensure_nonempty("signature_root", &self.signature_root)?;
        ensure_nonempty("transcript_root", &self.transcript_root)?;
        ensure_ordered_heights(
            "pq watcher attestation",
            self.height,
            self.expires_at_height,
        )?;
        if self.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "attestation {} security below policy",
                self.attestation_id
            ));
        }
        if !watchers.contains_key(&self.watcher_id) {
            return Err(format!(
                "attestation {} references missing watcher {}",
                self.attestation_id, self.watcher_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSponsorshipTicket {
    pub ticket_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub status: SponsorshipStatus,
    pub fee_asset_id: String,
    pub funded_units: u64,
    pub reserved_units: u64,
    pub privacy_budget_units: u64,
    pub entry_ids: Vec<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ScanSponsorshipTicket {
    pub fn devnet(
        index: u64,
        entry_ids: Vec<String>,
        height: u64,
        config: &MoneroStealthProofCacheConfig,
    ) -> Self {
        let seed = format!("scan-sponsor:{index}:{height}");
        Self {
            ticket_id: monero_stealth_proof_cache_string_root("SPONSOR-TICKET-ID", &seed),
            sponsor_commitment: monero_stealth_proof_cache_string_root("SPONSOR", &seed),
            beneficiary_commitment: monero_stealth_proof_cache_string_root("BENEFICIARY", &seed),
            status: if index % 2 == 0 {
                SponsorshipStatus::Reserved
            } else {
                SponsorshipStatus::Funded
            },
            fee_asset_id: "dxmr".to_string(),
            funded_units: config.default_sponsor_units,
            reserved_units: config.default_sponsor_units / 4,
            privacy_budget_units: config.default_privacy_budget_units,
            entry_ids,
            opened_at_height: height,
            expires_at_height: height.saturating_add(config.ttl_blocks),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if height > self.expires_at_height && self.status.spendable() {
            self.status = SponsorshipStatus::Expired;
            self.reserved_units = 0;
        }
    }

    pub fn available_units(&self) -> u64 {
        self.funded_units.saturating_sub(self.reserved_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "funded_units": self.funded_units,
            "reserved_units": self.reserved_units,
            "available_units": self.available_units(),
            "privacy_budget_units": self.privacy_budget_units,
            "entry_ids": self.entry_ids,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("SCAN-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(
        &self,
        cache_entries: &BTreeMap<String, ViewTagCacheEntry>,
    ) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("ticket_id", &self.ticket_id)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("beneficiary_commitment", &self.beneficiary_commitment)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("funded_units", self.funded_units)?;
        ensure_ordered_heights(
            "scan sponsorship",
            self.opened_at_height,
            self.expires_at_height,
        )?;
        if self.reserved_units > self.funded_units {
            return Err(format!("sponsorship {} over-reserved", self.ticket_id));
        }
        for entry_id in &self.entry_ids {
            if !cache_entries.contains_key(entry_id) {
                return Err(format!(
                    "sponsorship {} references missing cache entry {}",
                    self.ticket_id, entry_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgInvalidationRecord {
    pub invalidation_id: String,
    pub kind: ReorgInvalidationKind,
    pub affected_block_height: u64,
    pub detected_at_height: u64,
    pub old_block_hash: String,
    pub replacement_block_hash: String,
    pub invalidated_entry_ids: Vec<String>,
    pub quarantined_proof_ids: Vec<String>,
    pub sentinel_watcher_ids: Vec<String>,
    pub evidence_root: String,
}

impl ReorgInvalidationRecord {
    pub fn devnet(
        entry_ids: Vec<String>,
        proof_ids: Vec<String>,
        watcher_ids: Vec<String>,
        height: u64,
    ) -> Self {
        let seed = format!("reorg:{height}:{}", entry_ids.len());
        Self {
            invalidation_id: monero_stealth_proof_cache_string_root("REORG-INVALIDATION-ID", &seed),
            kind: ReorgInvalidationKind::WatcherQuorumRollback,
            affected_block_height: height.saturating_sub(2),
            detected_at_height: height,
            old_block_hash: monero_stealth_proof_cache_string_root("OLD-BLOCK", &seed),
            replacement_block_hash: monero_stealth_proof_cache_string_root("NEW-BLOCK", &seed),
            invalidated_entry_ids: entry_ids,
            quarantined_proof_ids: proof_ids,
            sentinel_watcher_ids: watcher_ids,
            evidence_root: monero_stealth_proof_cache_string_root("REORG-EVIDENCE", &seed),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invalidation_id": self.invalidation_id,
            "kind": self.kind.as_str(),
            "affected_block_height": self.affected_block_height,
            "detected_at_height": self.detected_at_height,
            "old_block_hash": self.old_block_hash,
            "replacement_block_hash": self.replacement_block_hash,
            "invalidated_entry_ids": self.invalidated_entry_ids,
            "quarantined_proof_ids": self.quarantined_proof_ids,
            "sentinel_watcher_ids": self.sentinel_watcher_ids,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("REORG-INVALIDATION", &self.public_record())
    }

    pub fn validate(
        &self,
        cache_entries: &BTreeMap<String, ViewTagCacheEntry>,
        proofs: &BTreeMap<String, OneTimeAddressProof>,
        watchers: &BTreeMap<String, StealthCacheWatcher>,
    ) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("invalidation_id", &self.invalidation_id)?;
        ensure_nonempty("old_block_hash", &self.old_block_hash)?;
        ensure_nonempty("replacement_block_hash", &self.replacement_block_hash)?;
        ensure_nonempty("evidence_root", &self.evidence_root)?;
        if self.detected_at_height < self.affected_block_height {
            return Err(format!(
                "reorg invalidation {} detected before affected block",
                self.invalidation_id
            ));
        }
        for entry_id in &self.invalidated_entry_ids {
            if !cache_entries.contains_key(entry_id) {
                return Err(format!(
                    "reorg invalidation {} references missing entry {}",
                    self.invalidation_id, entry_id
                ));
            }
        }
        for proof_id in &self.quarantined_proof_ids {
            if !proofs.contains_key(proof_id) {
                return Err(format!(
                    "reorg invalidation {} references missing proof {}",
                    self.invalidation_id, proof_id
                ));
            }
        }
        for watcher_id in &self.sentinel_watcher_ids {
            if !watchers.contains_key(watcher_id) {
                return Err(format!(
                    "reorg invalidation {} references missing sentinel {}",
                    self.invalidation_id, watcher_id
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroStealthProofCacheRoots {
    pub watcher_root: String,
    pub view_tag_entry_root: String,
    pub proof_root: String,
    pub pq_attestation_root: String,
    pub sponsorship_root: String,
    pub reorg_invalidation_root: String,
}

impl MoneroStealthProofCacheRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_root": self.watcher_root,
            "view_tag_entry_root": self.view_tag_entry_root,
            "proof_root": self.proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "reorg_invalidation_root": self.reorg_invalidation_root,
        })
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroStealthProofCacheCounters {
    pub watchers: usize,
    pub active_watchers: usize,
    pub view_tag_entries: usize,
    pub live_view_tag_entries: usize,
    pub proofs: usize,
    pub usable_proofs: usize,
    pub pq_attestations: usize,
    pub sponsorship_tickets: usize,
    pub spendable_sponsorship_tickets: usize,
    pub reorg_invalidations: usize,
    pub available_sponsor_units: u64,
    pub reserved_privacy_budget_units: u64,
}

impl MoneroStealthProofCacheCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "watchers": self.watchers,
            "active_watchers": self.active_watchers,
            "view_tag_entries": self.view_tag_entries,
            "live_view_tag_entries": self.live_view_tag_entries,
            "proofs": self.proofs,
            "usable_proofs": self.usable_proofs,
            "pq_attestations": self.pq_attestations,
            "sponsorship_tickets": self.sponsorship_tickets,
            "spendable_sponsorship_tickets": self.spendable_sponsorship_tickets,
            "reorg_invalidations": self.reorg_invalidations,
            "available_sponsor_units": self.available_sponsor_units,
            "reserved_privacy_budget_units": self.reserved_privacy_budget_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroStealthProofCacheState {
    pub protocol_version: String,
    pub height: u64,
    pub config: MoneroStealthProofCacheConfig,
    pub watchers: BTreeMap<String, StealthCacheWatcher>,
    pub view_tag_entries: BTreeMap<String, ViewTagCacheEntry>,
    pub one_time_address_proofs: BTreeMap<String, OneTimeAddressProof>,
    pub pq_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub scan_sponsorships: BTreeMap<String, ScanSponsorshipTicket>,
    pub reorg_invalidations: BTreeMap<String, ReorgInvalidationRecord>,
    pub used_key_image_nullifiers: BTreeSet<String>,
}

impl MoneroStealthProofCacheState {
    pub fn devnet() -> MoneroStealthProofCacheResult<Self> {
        let config = MoneroStealthProofCacheConfig::devnet();
        let height = 1;
        let mut state = Self {
            protocol_version: MONERO_STEALTH_PROOF_CACHE_PROTOCOL_VERSION.to_string(),
            height,
            config,
            watchers: BTreeMap::new(),
            view_tag_entries: BTreeMap::new(),
            one_time_address_proofs: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            scan_sponsorships: BTreeMap::new(),
            reorg_invalidations: BTreeMap::new(),
            used_key_image_nullifiers: BTreeSet::new(),
        };

        for (label, role) in [
            ("devnet-scanner-a", WatcherRole::Scanner),
            ("devnet-pq-attester-a", WatcherRole::PqAttester),
            ("devnet-reorg-sentinel-a", WatcherRole::ReorgSentinel),
            ("devnet-sponsor-auditor-a", WatcherRole::SponsorAuditor),
        ] {
            state.add_watcher(StealthCacheWatcher::devnet(label, role, height))?;
        }

        let watcher_ids = state.watchers.keys().cloned().collect::<Vec<_>>();
        for index in 0..6 {
            let entry = ViewTagCacheEntry::devnet(
                index,
                watcher_ids.iter().take(3).cloned().collect(),
                height,
                &state.config,
            );
            let entry_id = entry.entry_id.clone();
            state.add_view_tag_entry(entry)?;
            let mut proof = OneTimeAddressProof::devnet(index, &entry_id, height, &state.config);
            let proof_root = proof.state_root();
            let watcher_id = watcher_ids
                .get((index as usize) % watcher_ids.len())
                .cloned()
                .ok_or_else(|| "devnet stealth cache missing watcher".to_string())?;
            let attestation = PqWatcherAttestation::devnet(
                index,
                &watcher_id,
                &proof.proof_id,
                &proof_root,
                height,
                &state.config,
            );
            proof.attach_attestation(attestation.attestation_id.clone());
            state.add_one_time_address_proof(proof)?;
            state.add_pq_attestation(attestation)?;
        }

        let entry_ids = state
            .view_tag_entries
            .keys()
            .take(3)
            .cloned()
            .collect::<Vec<_>>();
        state.add_scan_sponsorship(ScanSponsorshipTicket::devnet(
            0,
            entry_ids,
            height,
            &state.config,
        ))?;

        let invalidated_entries = state
            .view_tag_entries
            .keys()
            .take(1)
            .cloned()
            .collect::<Vec<_>>();
        let quarantined_proofs = state
            .one_time_address_proofs
            .keys()
            .take(1)
            .cloned()
            .collect::<Vec<_>>();
        let sentinel_ids = state
            .watchers
            .values()
            .filter(|watcher| watcher.role == WatcherRole::ReorgSentinel)
            .map(|watcher| watcher.watcher_id.clone())
            .collect::<Vec<_>>();
        state.add_reorg_invalidation(ReorgInvalidationRecord::devnet(
            invalidated_entries,
            quarantined_proofs,
            sentinel_ids,
            height,
        ))?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroStealthProofCacheResult<()> {
        if height < self.height {
            return Err("monero stealth proof cache height cannot move backwards".to_string());
        }
        self.height = height;
        for watcher in self.watchers.values_mut() {
            watcher.set_height(height, self.config.ttl_blocks);
        }
        for entry in self.view_tag_entries.values_mut() {
            entry.set_height(height);
        }
        for proof in self.one_time_address_proofs.values_mut() {
            proof.set_height(height);
        }
        for attestation in self.pq_attestations.values_mut() {
            attestation.set_height(height);
        }
        for sponsorship in self.scan_sponsorships.values_mut() {
            sponsorship.set_height(height);
        }
        self.validate()
    }

    pub fn roots(&self) -> MoneroStealthProofCacheRoots {
        MoneroStealthProofCacheRoots {
            watcher_root: merkle_record_root("STEALTH-WATCHERS", &self.watchers),
            view_tag_entry_root: merkle_record_root(
                "STEALTH-VIEW-TAG-ENTRIES",
                &self.view_tag_entries,
            ),
            proof_root: merkle_record_root("STEALTH-PROOFS", &self.one_time_address_proofs),
            pq_attestation_root: merkle_record_root(
                "STEALTH-PQ-ATTESTATIONS",
                &self.pq_attestations,
            ),
            sponsorship_root: merkle_record_root("STEALTH-SPONSORSHIPS", &self.scan_sponsorships),
            reorg_invalidation_root: merkle_record_root(
                "STEALTH-REORG-INVALIDATIONS",
                &self.reorg_invalidations,
            ),
        }
    }

    pub fn counters(&self) -> MoneroStealthProofCacheCounters {
        MoneroStealthProofCacheCounters {
            watchers: self.watchers.len(),
            active_watchers: self
                .watchers
                .values()
                .filter(|watcher| watcher.active)
                .count(),
            view_tag_entries: self.view_tag_entries.len(),
            live_view_tag_entries: self
                .view_tag_entries
                .values()
                .filter(|entry| entry.status.live())
                .count(),
            proofs: self.one_time_address_proofs.len(),
            usable_proofs: self
                .one_time_address_proofs
                .values()
                .filter(|proof| proof.status.usable())
                .count(),
            pq_attestations: self.pq_attestations.len(),
            sponsorship_tickets: self.scan_sponsorships.len(),
            spendable_sponsorship_tickets: self
                .scan_sponsorships
                .values()
                .filter(|ticket| ticket.status.spendable())
                .count(),
            reorg_invalidations: self.reorg_invalidations.len(),
            available_sponsor_units: self
                .scan_sponsorships
                .values()
                .map(ScanSponsorshipTicket::available_units)
                .sum(),
            reserved_privacy_budget_units: self
                .view_tag_entries
                .values()
                .filter(|entry| entry.status.live())
                .map(|entry| entry.privacy_budget_units)
                .sum(),
        }
    }

    pub fn active_watcher_ids(&self) -> Vec<String> {
        self.watchers
            .values()
            .filter(|watcher| watcher.active)
            .map(|watcher| watcher.watcher_id.clone())
            .collect()
    }

    pub fn hot_entry_ids(&self) -> Vec<String> {
        self.view_tag_entries
            .values()
            .filter(|entry| entry.status == CacheEntryStatus::Hot)
            .map(|entry| entry.entry_id.clone())
            .collect()
    }

    pub fn usable_proof_ids(&self) -> Vec<String> {
        self.one_time_address_proofs
            .values()
            .filter(|proof| proof.status.usable())
            .map(|proof| proof.proof_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        monero_stealth_proof_cache_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> MoneroStealthProofCacheResult<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        self.config.validate()?;
        for (id, watcher) in &self.watchers {
            if id != &watcher.watcher_id {
                return Err(format!("watcher map key mismatch {id}"));
            }
            watcher.validate()?;
        }
        let mut key_images = BTreeSet::new();
        for (id, entry) in &self.view_tag_entries {
            if id != &entry.entry_id {
                return Err(format!("view tag entry key mismatch {id}"));
            }
            entry.validate(&self.watchers)?;
        }
        for (id, proof) in &self.one_time_address_proofs {
            if id != &proof.proof_id {
                return Err(format!("proof map key mismatch {id}"));
            }
            proof.validate(&self.view_tag_entries)?;
            if !key_images.insert(proof.key_image_nullifier.clone()) {
                return Err(format!(
                    "duplicate key image nullifier {}",
                    proof.key_image_nullifier
                ));
            }
            for attestation_id in &proof.pq_attestation_ids {
                if !self.pq_attestations.contains_key(attestation_id) {
                    return Err(format!(
                        "proof {} references missing attestation {}",
                        proof.proof_id, attestation_id
                    ));
                }
            }
        }
        for used in &self.used_key_image_nullifiers {
            if !key_images.contains(used) {
                return Err(format!(
                    "used nullifier index references missing proof {used}"
                ));
            }
        }
        for (id, attestation) in &self.pq_attestations {
            if id != &attestation.attestation_id {
                return Err(format!("attestation map key mismatch {id}"));
            }
            attestation.validate(&self.watchers, &self.config)?;
        }
        for (id, sponsorship) in &self.scan_sponsorships {
            if id != &sponsorship.ticket_id {
                return Err(format!("sponsorship map key mismatch {id}"));
            }
            sponsorship.validate(&self.view_tag_entries)?;
        }
        for (id, invalidation) in &self.reorg_invalidations {
            if id != &invalidation.invalidation_id {
                return Err(format!("reorg invalidation map key mismatch {id}"));
            }
            invalidation.validate(
                &self.view_tag_entries,
                &self.one_time_address_proofs,
                &self.watchers,
            )?;
        }
        Ok(())
    }

    pub fn add_watcher(
        &mut self,
        watcher: StealthCacheWatcher,
    ) -> MoneroStealthProofCacheResult<()> {
        watcher.validate()?;
        self.watchers.insert(watcher.watcher_id.clone(), watcher);
        Ok(())
    }

    pub fn add_view_tag_entry(
        &mut self,
        entry: ViewTagCacheEntry,
    ) -> MoneroStealthProofCacheResult<()> {
        entry.validate(&self.watchers)?;
        self.view_tag_entries.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    pub fn add_one_time_address_proof(
        &mut self,
        proof: OneTimeAddressProof,
    ) -> MoneroStealthProofCacheResult<()> {
        proof.validate(&self.view_tag_entries)?;
        if self
            .used_key_image_nullifiers
            .contains(&proof.key_image_nullifier)
        {
            return Err(format!(
                "key image nullifier {} already cached",
                proof.key_image_nullifier
            ));
        }
        self.used_key_image_nullifiers
            .insert(proof.key_image_nullifier.clone());
        self.one_time_address_proofs
            .insert(proof.proof_id.clone(), proof);
        Ok(())
    }

    pub fn add_pq_attestation(
        &mut self,
        attestation: PqWatcherAttestation,
    ) -> MoneroStealthProofCacheResult<()> {
        attestation.validate(&self.watchers, &self.config)?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn add_scan_sponsorship(
        &mut self,
        sponsorship: ScanSponsorshipTicket,
    ) -> MoneroStealthProofCacheResult<()> {
        sponsorship.validate(&self.view_tag_entries)?;
        self.scan_sponsorships
            .insert(sponsorship.ticket_id.clone(), sponsorship);
        Ok(())
    }

    pub fn add_reorg_invalidation(
        &mut self,
        invalidation: ReorgInvalidationRecord,
    ) -> MoneroStealthProofCacheResult<()> {
        invalidation.validate(
            &self.view_tag_entries,
            &self.one_time_address_proofs,
            &self.watchers,
        )?;
        for entry_id in &invalidation.invalidated_entry_ids {
            if let Some(entry) = self.view_tag_entries.get_mut(entry_id) {
                entry.invalidate_for_reorg();
            }
        }
        for proof_id in &invalidation.quarantined_proof_ids {
            if let Some(proof) = self.one_time_address_proofs.get_mut(proof_id) {
                proof.quarantine_for_reorg();
            }
        }
        self.reorg_invalidations
            .insert(invalidation.invalidation_id.clone(), invalidation);
        Ok(())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "monero_stealth_proof_cache_state",
            "protocol_version": self.protocol_version,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "watchers": keyed_records(&self.watchers),
            "view_tag_entries": keyed_records(&self.view_tag_entries),
            "one_time_address_proofs": keyed_records(&self.one_time_address_proofs),
            "pq_attestations": keyed_records(&self.pq_attestations),
            "scan_sponsorships": keyed_records(&self.scan_sponsorships),
            "reorg_invalidations": keyed_records(&self.reorg_invalidations),
            "used_key_image_nullifier_root": merkle_root(
                "MONERO-STEALTH-CACHE-USED-KEY-IMAGES",
                &self
                    .used_key_image_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect::<Vec<_>>(),
            ),
        })
    }
}

pub fn monero_stealth_proof_cache_state_root_from_record(record: &Value) -> String {
    monero_stealth_proof_cache_payload_root("STATE", record)
}

pub fn monero_stealth_proof_cache_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("MONERO-STEALTH-PROOF-CACHE-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn monero_stealth_proof_cache_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("MONERO-STEALTH-PROOF-CACHE-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

trait CachePublicRecord {
    fn public_record(&self) -> Value;
}

impl CachePublicRecord for StealthCacheWatcher {
    fn public_record(&self) -> Value {
        StealthCacheWatcher::public_record(self)
    }
}

impl CachePublicRecord for ViewTagCacheEntry {
    fn public_record(&self) -> Value {
        ViewTagCacheEntry::public_record(self)
    }
}

impl CachePublicRecord for OneTimeAddressProof {
    fn public_record(&self) -> Value {
        OneTimeAddressProof::public_record(self)
    }
}

impl CachePublicRecord for PqWatcherAttestation {
    fn public_record(&self) -> Value {
        PqWatcherAttestation::public_record(self)
    }
}

impl CachePublicRecord for ScanSponsorshipTicket {
    fn public_record(&self) -> Value {
        ScanSponsorshipTicket::public_record(self)
    }
}

impl CachePublicRecord for ReorgInvalidationRecord {
    fn public_record(&self) -> Value {
        ReorgInvalidationRecord::public_record(self)
    }
}

fn keyed_records<T: CachePublicRecord>(records: &BTreeMap<String, T>) -> Vec<Value> {
    records
        .iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record.public_record(),
            })
        })
        .collect()
}

fn merkle_record_root<T: CachePublicRecord>(domain: &str, records: &BTreeMap<String, T>) -> String {
    merkle_root(
        domain,
        &records
            .iter()
            .map(|(id, record)| {
                json!({
                    "id": id,
                    "root": monero_stealth_proof_cache_payload_root(
                        domain,
                        &json!({
                            "id": id,
                            "record": record.public_record(),
                        }),
                    ),
                })
            })
            .collect::<Vec<_>>(),
    )
}

fn ensure_nonempty(field: &str, value: &str) -> MoneroStealthProofCacheResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> MoneroStealthProofCacheResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> MoneroStealthProofCacheResult<()> {
    if value > MONERO_STEALTH_PROOF_CACHE_MAX_BPS {
        Err(format!("{field} exceeds bps denominator"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    label: &str,
    start_height: u64,
    end_height: u64,
) -> MoneroStealthProofCacheResult<()> {
    if end_height <= start_height {
        Err(format!("{label} end height must be after start height"))
    } else {
        Ok(())
    }
}
