use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    api::ApiControlPlaneState,
    daemon::{DaemonHealthSnapshot, DaemonStorageCommit, NebulaDaemon},
    hash::{domain_hash, merkle_root, HashPart},
    p2p::P2pOverlayState,
    prover::proof_market_snapshot,
    relayer::RelayerState,
    rpc::RpcControlPlaneState,
    storage::StorageState,
    CHAIN_ID,
};

pub type TelemetryResult<T> = Result<T, String>;

pub const TELEMETRY_PROTOCOL_VERSION: &str = "nebula-l2-telemetry-v1";
pub const TELEMETRY_DEFAULT_EVENT_RETENTION_MS: u64 = 86_400_000;
pub const TELEMETRY_DEFAULT_MAX_EVENTS: usize = 512;
pub const TELEMETRY_DEFAULT_THROUGHPUT_WINDOW_MS: u64 = 60_000;
pub const TELEMETRY_UNIT_COUNT: &str = "count";
pub const TELEMETRY_UNIT_RECORDS: &str = "records";
pub const TELEMETRY_UNIT_ROOT: &str = "root";
pub const TELEMETRY_UNIT_MILLI_PER_MINUTE: &str = "milli_per_minute";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetrySeverity {
    Info,
    Notice,
    Warning,
    Critical,
}

impl TelemetrySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetrySignalKind {
    Counter,
    Gauge,
    Event,
    Alert,
    Snapshot,
    Daemon,
    Api,
    Rpc,
    P2p,
    Relayer,
    Storage,
    Throughput,
    PendingTransactions,
    FeeSmoothing,
    Bridge,
    Monero,
    ProofMarket,
}

impl TelemetrySignalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Event => "event",
            Self::Alert => "alert",
            Self::Snapshot => "snapshot",
            Self::Daemon => "daemon",
            Self::Api => "api",
            Self::Rpc => "rpc",
            Self::P2p => "p2p",
            Self::Relayer => "relayer",
            Self::Storage => "storage",
            Self::Throughput => "throughput",
            Self::PendingTransactions => "pending_transactions",
            Self::FeeSmoothing => "fee_smoothing",
            Self::Bridge => "bridge",
            Self::Monero => "monero",
            Self::ProofMarket => "proof_market",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryCounter {
    pub counter_id: String,
    pub name: String,
    pub source: String,
    pub unit: String,
    pub labels_root: String,
    pub value: u64,
    pub first_seen_height: u64,
    pub last_seen_height: u64,
    pub updated_at_ms: u64,
}

impl TelemetryCounter {
    pub fn new(
        name: impl Into<String>,
        source: impl Into<String>,
        value: u64,
        unit: impl Into<String>,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<Self> {
        let name = name.into();
        let source = source.into();
        let unit = unit.into();
        ensure_nonempty("telemetry counter name", &name)?;
        ensure_nonempty("telemetry counter source", &source)?;
        ensure_nonempty("telemetry counter unit", &unit)?;
        let labels_root = telemetry_payload_root("TELEMETRY-COUNTER-LABELS", labels);
        let counter_id = telemetry_counter_id(&name, &source, &unit, &labels_root);
        Ok(Self {
            counter_id,
            name,
            source,
            unit,
            labels_root,
            value,
            first_seen_height: height,
            last_seen_height: height,
            updated_at_ms,
        })
    }

    pub fn set(&mut self, value: u64, height: u64, updated_at_ms: u64) {
        self.value = value;
        self.last_seen_height = height;
        self.updated_at_ms = updated_at_ms;
    }

    pub fn increment(&mut self, delta: u64, height: u64, updated_at_ms: u64) {
        self.value = self.value.saturating_add(delta);
        self.last_seen_height = height;
        self.updated_at_ms = updated_at_ms;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "telemetry_counter",
            "signal_kind": TelemetrySignalKind::Counter.as_str(),
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "counter_id": self.counter_id,
            "name": self.name,
            "source": self.source,
            "unit": self.unit,
            "labels_root": self.labels_root,
            "value": self.value,
            "first_seen_height": self.first_seen_height,
            "last_seen_height": self.last_seen_height,
            "updated_at_ms": self.updated_at_ms,
        })
    }

    pub fn counter_root(&self) -> String {
        domain_hash(
            "TELEMETRY-COUNTER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryGauge {
    pub gauge_id: String,
    pub name: String,
    pub source: String,
    pub unit: String,
    pub labels_root: String,
    pub value: u64,
    pub root: Option<String>,
    pub payload_root: Option<String>,
    pub height: u64,
    pub updated_at_ms: u64,
}

impl TelemetryGauge {
    pub fn numeric(
        name: impl Into<String>,
        source: impl Into<String>,
        value: u64,
        unit: impl Into<String>,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<Self> {
        Self::new(
            name,
            source,
            value,
            unit,
            None,
            None,
            labels,
            height,
            updated_at_ms,
        )
    }

    pub fn root(
        name: impl Into<String>,
        source: impl Into<String>,
        root: impl Into<String>,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<Self> {
        Self::new(
            name,
            source,
            0,
            TELEMETRY_UNIT_ROOT,
            Some(root.into()),
            None,
            labels,
            height,
            updated_at_ms,
        )
    }

    pub fn payload_root(
        name: impl Into<String>,
        source: impl Into<String>,
        payload_root: impl Into<String>,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<Self> {
        Self::new(
            name,
            source,
            0,
            TELEMETRY_UNIT_ROOT,
            None,
            Some(payload_root.into()),
            labels,
            height,
            updated_at_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        name: impl Into<String>,
        source: impl Into<String>,
        value: u64,
        unit: impl Into<String>,
        root: Option<String>,
        payload_root: Option<String>,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<Self> {
        let name = name.into();
        let source = source.into();
        let unit = unit.into();
        ensure_nonempty("telemetry gauge name", &name)?;
        ensure_nonempty("telemetry gauge source", &source)?;
        ensure_nonempty("telemetry gauge unit", &unit)?;
        let labels_root = telemetry_payload_root("TELEMETRY-GAUGE-LABELS", labels);
        let gauge_id = telemetry_gauge_id(&name, &source, &unit, &labels_root);
        Ok(Self {
            gauge_id,
            name,
            source,
            unit,
            labels_root,
            value,
            root,
            payload_root,
            height,
            updated_at_ms,
        })
    }

    pub fn set_numeric(&mut self, value: u64, height: u64, updated_at_ms: u64) {
        self.value = value;
        self.root = None;
        self.payload_root = None;
        self.height = height;
        self.updated_at_ms = updated_at_ms;
    }

    pub fn set_root(&mut self, root: impl Into<String>, height: u64, updated_at_ms: u64) {
        self.value = 0;
        self.root = Some(root.into());
        self.payload_root = None;
        self.height = height;
        self.updated_at_ms = updated_at_ms;
    }

    pub fn set_payload_root(
        &mut self,
        payload_root: impl Into<String>,
        height: u64,
        updated_at_ms: u64,
    ) {
        self.value = 0;
        self.root = None;
        self.payload_root = Some(payload_root.into());
        self.height = height;
        self.updated_at_ms = updated_at_ms;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "telemetry_gauge",
            "signal_kind": TelemetrySignalKind::Gauge.as_str(),
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "gauge_id": self.gauge_id,
            "name": self.name,
            "source": self.source,
            "unit": self.unit,
            "labels_root": self.labels_root,
            "value": self.value,
            "root": self.root,
            "payload_root": self.payload_root,
            "height": self.height,
            "updated_at_ms": self.updated_at_ms,
        })
    }

    pub fn gauge_root(&self) -> String {
        domain_hash(
            "TELEMETRY-GAUGE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub event_id: String,
    pub event_kind: String,
    pub source: String,
    pub severity: TelemetrySeverity,
    pub height: u64,
    pub timestamp_ms: u64,
    pub payload_root: String,
    pub message_root: String,
    pub related_root: String,
}

impl TelemetryEvent {
    pub fn new(
        event_kind: impl Into<String>,
        source: impl Into<String>,
        severity: TelemetrySeverity,
        height: u64,
        timestamp_ms: u64,
        payload: &Value,
        message: Option<&str>,
        related: &[String],
    ) -> TelemetryResult<Self> {
        let event_kind = event_kind.into();
        let source = source.into();
        ensure_nonempty("telemetry event kind", &event_kind)?;
        ensure_nonempty("telemetry event source", &source)?;
        let payload_root = telemetry_payload_root("TELEMETRY-EVENT-PAYLOAD", payload);
        let message_root = message
            .map(|value| telemetry_string_root("TELEMETRY-EVENT-MESSAGE", &[value.to_string()]))
            .unwrap_or_else(|| telemetry_string_root("TELEMETRY-EVENT-MESSAGE", &[]));
        let related_root = telemetry_string_root("TELEMETRY-EVENT-RELATED", related);
        let event_id =
            telemetry_event_id(&event_kind, &source, height, timestamp_ms, &payload_root);
        Ok(Self {
            event_id,
            event_kind,
            source,
            severity,
            height,
            timestamp_ms,
            payload_root,
            message_root,
            related_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "telemetry_event",
            "signal_kind": TelemetrySignalKind::Event.as_str(),
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "source": self.source,
            "severity": self.severity.as_str(),
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "payload_root": self.payload_root,
            "message_root": self.message_root,
            "related_root": self.related_root,
        })
    }

    pub fn event_root(&self) -> String {
        domain_hash(
            "TELEMETRY-EVENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryAlert {
    pub alert_id: String,
    pub alert_kind: String,
    pub source: String,
    pub severity: TelemetrySeverity,
    pub height: u64,
    pub timestamp_ms: u64,
    pub signal_root: String,
    pub detail_root: String,
    pub acknowledged: bool,
}

impl TelemetryAlert {
    pub fn new(
        alert_kind: impl Into<String>,
        source: impl Into<String>,
        severity: TelemetrySeverity,
        height: u64,
        timestamp_ms: u64,
        signal_root: impl Into<String>,
        details: &Value,
    ) -> TelemetryResult<Self> {
        let alert_kind = alert_kind.into();
        let source = source.into();
        let signal_root = signal_root.into();
        ensure_nonempty("telemetry alert kind", &alert_kind)?;
        ensure_nonempty("telemetry alert source", &source)?;
        ensure_nonempty("telemetry alert signal root", &signal_root)?;
        let detail_root = telemetry_payload_root("TELEMETRY-ALERT-DETAILS", details);
        let alert_id = telemetry_alert_id(
            &alert_kind,
            &source,
            severity,
            height,
            &signal_root,
            &detail_root,
        );
        Ok(Self {
            alert_id,
            alert_kind,
            source,
            severity,
            height,
            timestamp_ms,
            signal_root,
            detail_root,
            acknowledged: false,
        })
    }

    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "telemetry_alert",
            "signal_kind": TelemetrySignalKind::Alert.as_str(),
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "alert_id": self.alert_id,
            "alert_kind": self.alert_kind,
            "source": self.source,
            "severity": self.severity.as_str(),
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "signal_root": self.signal_root,
            "detail_root": self.detail_root,
            "acknowledged": self.acknowledged,
        })
    }

    pub fn alert_root(&self) -> String {
        domain_hash(
            "TELEMETRY-ALERT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub snapshot_id: String,
    pub telemetry_id: String,
    pub daemon_id: Option<String>,
    pub node_id: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub severity: TelemetrySeverity,
    pub daemon_root: Option<String>,
    pub daemon_health_root: Option<String>,
    pub node_root: Option<String>,
    pub api_root: Option<String>,
    pub storage_manifest_root: Option<String>,
    pub p2p_overlay_root: Option<String>,
    pub rpc_control_plane_root: Option<String>,
    pub relayer_root: Option<String>,
    pub summary_root: String,
    pub summary: Value,
    pub counter_root: String,
    pub gauge_root: String,
    pub event_root: String,
    pub alert_root: String,
}

impl TelemetrySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        telemetry_id: impl Into<String>,
        daemon_id: Option<String>,
        node_id: impl Into<String>,
        height: u64,
        timestamp_ms: u64,
        severity: TelemetrySeverity,
        daemon_root: Option<String>,
        daemon_health_root: Option<String>,
        node_root: Option<String>,
        api_root: Option<String>,
        storage_manifest_root: Option<String>,
        p2p_overlay_root: Option<String>,
        rpc_control_plane_root: Option<String>,
        relayer_root: Option<String>,
        summary: Value,
        counter_root: String,
        gauge_root: String,
        event_root: String,
        alert_root: String,
        pre_snapshot_state_root: &str,
    ) -> TelemetryResult<Self> {
        let telemetry_id = telemetry_id.into();
        let node_id = node_id.into();
        ensure_nonempty("telemetry snapshot telemetry id", &telemetry_id)?;
        ensure_nonempty("telemetry snapshot node id", &node_id)?;
        let summary_root = telemetry_payload_root("TELEMETRY-SNAPSHOT-SUMMARY", &summary);
        let snapshot_id = telemetry_snapshot_id(
            &telemetry_id,
            &node_id,
            height,
            timestamp_ms,
            daemon_root.as_deref().unwrap_or(""),
            &summary_root,
            pre_snapshot_state_root,
        );
        Ok(Self {
            snapshot_id,
            telemetry_id,
            daemon_id,
            node_id,
            height,
            timestamp_ms,
            severity,
            daemon_root,
            daemon_health_root,
            node_root,
            api_root,
            storage_manifest_root,
            p2p_overlay_root,
            rpc_control_plane_root,
            relayer_root,
            summary_root,
            summary,
            counter_root,
            gauge_root,
            event_root,
            alert_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "telemetry_snapshot",
            "signal_kind": TelemetrySignalKind::Snapshot.as_str(),
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "telemetry_id": self.telemetry_id,
            "daemon_id": self.daemon_id,
            "node_id": self.node_id,
            "height": self.height,
            "timestamp_ms": self.timestamp_ms,
            "severity": self.severity.as_str(),
            "daemon_root": self.daemon_root,
            "daemon_health_root": self.daemon_health_root,
            "node_root": self.node_root,
            "api_root": self.api_root,
            "storage_manifest_root": self.storage_manifest_root,
            "p2p_overlay_root": self.p2p_overlay_root,
            "rpc_control_plane_root": self.rpc_control_plane_root,
            "relayer_root": self.relayer_root,
            "summary_root": self.summary_root,
            "summary": self.summary,
            "counter_root": self.counter_root,
            "gauge_root": self.gauge_root,
            "event_root": self.event_root,
            "alert_root": self.alert_root,
        })
    }

    pub fn snapshot_root(&self) -> String {
        domain_hash(
            "TELEMETRY-SNAPSHOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TelemetryState {
    pub telemetry_id: String,
    pub node_label: String,
    pub current_height: u64,
    pub last_updated_ms: u64,
    pub event_retention_ms: u64,
    pub max_events: usize,
    pub counters: BTreeMap<String, TelemetryCounter>,
    pub gauges: BTreeMap<String, TelemetryGauge>,
    pub events: Vec<TelemetryEvent>,
    pub alerts: BTreeMap<String, TelemetryAlert>,
    pub snapshots: Vec<TelemetrySnapshot>,
    pub throughput_window_ms: u64,
}

impl TelemetryState {
    pub fn new(node_label: impl Into<String>) -> Self {
        let node_label = node_label.into();
        let telemetry_id = domain_hash(
            "TELEMETRY-STATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
                HashPart::Str(&node_label),
            ],
            32,
        );
        Self {
            telemetry_id,
            node_label,
            current_height: 0,
            last_updated_ms: 0,
            event_retention_ms: TELEMETRY_DEFAULT_EVENT_RETENTION_MS,
            max_events: TELEMETRY_DEFAULT_MAX_EVENTS,
            counters: BTreeMap::new(),
            gauges: BTreeMap::new(),
            events: Vec::new(),
            alerts: BTreeMap::new(),
            snapshots: Vec::new(),
            throughput_window_ms: TELEMETRY_DEFAULT_THROUGHPUT_WINDOW_MS,
        }
    }

    pub fn with_limits(
        mut self,
        event_retention_ms: u64,
        max_events: usize,
        throughput_window_ms: u64,
    ) -> Self {
        self.event_retention_ms = event_retention_ms.max(1);
        self.max_events = max_events.max(1);
        self.throughput_window_ms = throughput_window_ms.max(1);
        self
    }

    pub fn set_counter(
        &mut self,
        name: &str,
        source: &str,
        value: u64,
        unit: &str,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<TelemetryCounter> {
        let labels_root = telemetry_payload_root("TELEMETRY-COUNTER-LABELS", labels);
        let counter_id = telemetry_counter_id(name, source, unit, &labels_root);
        if let Some(counter) = self.counters.get_mut(&counter_id) {
            counter.set(value, height, updated_at_ms);
            self.current_height = height;
            self.last_updated_ms = updated_at_ms;
            return Ok(counter.clone());
        }
        let counter =
            TelemetryCounter::new(name, source, value, unit, labels, height, updated_at_ms)?;
        self.counters
            .insert(counter.counter_id.clone(), counter.clone());
        self.current_height = height;
        self.last_updated_ms = updated_at_ms;
        Ok(counter)
    }

    pub fn increment_counter(
        &mut self,
        name: &str,
        source: &str,
        delta: u64,
        unit: &str,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<TelemetryCounter> {
        let labels_root = telemetry_payload_root("TELEMETRY-COUNTER-LABELS", labels);
        let counter_id = telemetry_counter_id(name, source, unit, &labels_root);
        if let Some(counter) = self.counters.get_mut(&counter_id) {
            counter.increment(delta, height, updated_at_ms);
            self.current_height = height;
            self.last_updated_ms = updated_at_ms;
            return Ok(counter.clone());
        }
        self.set_counter(name, source, delta, unit, labels, height, updated_at_ms)
    }

    pub fn record_gauge(
        &mut self,
        name: &str,
        source: &str,
        value: u64,
        unit: &str,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<TelemetryGauge> {
        let labels_root = telemetry_payload_root("TELEMETRY-GAUGE-LABELS", labels);
        let gauge_id = telemetry_gauge_id(name, source, unit, &labels_root);
        if let Some(gauge) = self.gauges.get_mut(&gauge_id) {
            gauge.set_numeric(value, height, updated_at_ms);
            self.current_height = height;
            self.last_updated_ms = updated_at_ms;
            return Ok(gauge.clone());
        }
        let gauge =
            TelemetryGauge::numeric(name, source, value, unit, labels, height, updated_at_ms)?;
        self.gauges.insert(gauge.gauge_id.clone(), gauge.clone());
        self.current_height = height;
        self.last_updated_ms = updated_at_ms;
        Ok(gauge)
    }

    pub fn record_root_gauge(
        &mut self,
        name: &str,
        source: &str,
        root: &str,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<TelemetryGauge> {
        let labels_root = telemetry_payload_root("TELEMETRY-GAUGE-LABELS", labels);
        let gauge_id = telemetry_gauge_id(name, source, TELEMETRY_UNIT_ROOT, &labels_root);
        if let Some(gauge) = self.gauges.get_mut(&gauge_id) {
            gauge.set_root(root, height, updated_at_ms);
            self.current_height = height;
            self.last_updated_ms = updated_at_ms;
            return Ok(gauge.clone());
        }
        let gauge = TelemetryGauge::root(name, source, root, labels, height, updated_at_ms)?;
        self.gauges.insert(gauge.gauge_id.clone(), gauge.clone());
        self.current_height = height;
        self.last_updated_ms = updated_at_ms;
        Ok(gauge)
    }

    pub fn record_payload_root_gauge(
        &mut self,
        name: &str,
        source: &str,
        payload_root: &str,
        labels: &Value,
        height: u64,
        updated_at_ms: u64,
    ) -> TelemetryResult<TelemetryGauge> {
        let labels_root = telemetry_payload_root("TELEMETRY-GAUGE-LABELS", labels);
        let gauge_id = telemetry_gauge_id(name, source, TELEMETRY_UNIT_ROOT, &labels_root);
        if let Some(gauge) = self.gauges.get_mut(&gauge_id) {
            gauge.set_payload_root(payload_root, height, updated_at_ms);
            self.current_height = height;
            self.last_updated_ms = updated_at_ms;
            return Ok(gauge.clone());
        }
        let gauge = TelemetryGauge::payload_root(
            name,
            source,
            payload_root,
            labels,
            height,
            updated_at_ms,
        )?;
        self.gauges.insert(gauge.gauge_id.clone(), gauge.clone());
        self.current_height = height;
        self.last_updated_ms = updated_at_ms;
        Ok(gauge)
    }

    pub fn record_event(
        &mut self,
        event_kind: &str,
        source: &str,
        severity: TelemetrySeverity,
        height: u64,
        timestamp_ms: u64,
        payload: &Value,
    ) -> TelemetryResult<TelemetryEvent> {
        let event = TelemetryEvent::new(
            event_kind,
            source,
            severity,
            height,
            timestamp_ms,
            payload,
            None,
            &[],
        )?;
        self.events.push(event.clone());
        self.current_height = height;
        self.last_updated_ms = timestamp_ms;
        self.prune_old_events(timestamp_ms);
        Ok(event)
    }

    pub fn record_event_with_roots(
        &mut self,
        event_kind: &str,
        source: &str,
        severity: TelemetrySeverity,
        height: u64,
        timestamp_ms: u64,
        payload: &Value,
        message: Option<&str>,
        related: &[String],
    ) -> TelemetryResult<TelemetryEvent> {
        let event = TelemetryEvent::new(
            event_kind,
            source,
            severity,
            height,
            timestamp_ms,
            payload,
            message,
            related,
        )?;
        self.events.push(event.clone());
        self.current_height = height;
        self.last_updated_ms = timestamp_ms;
        self.prune_old_events(timestamp_ms);
        Ok(event)
    }

    pub fn record_alert(
        &mut self,
        alert_kind: &str,
        source: &str,
        severity: TelemetrySeverity,
        height: u64,
        timestamp_ms: u64,
        signal_root: &str,
        details: &Value,
    ) -> TelemetryResult<TelemetryAlert> {
        let alert = TelemetryAlert::new(
            alert_kind,
            source,
            severity,
            height,
            timestamp_ms,
            signal_root,
            details,
        )?;
        self.alerts.insert(alert.alert_id.clone(), alert.clone());
        self.current_height = height;
        self.last_updated_ms = timestamp_ms;
        Ok(alert)
    }

    pub fn capture_daemon_snapshot(
        &mut self,
        daemon: &NebulaDaemon,
        timestamp_ms: u64,
    ) -> TelemetryResult<TelemetrySnapshot> {
        let height = daemon.node.height();
        self.current_height = height;
        self.last_updated_ms = timestamp_ms;
        self.capture_api_roots(&daemon.api, timestamp_ms)?;
        self.capture_storage_roots(&daemon.storage, height, timestamp_ms)?;
        self.capture_daemon_health_roots(daemon, timestamp_ms)?;
        self.capture_sequencer_roots(daemon, timestamp_ms)?;

        self.set_counter(
            "daemon.operation_receipts_total",
            "daemon",
            daemon.state.operation_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "daemon.api_exchanges_total",
            "daemon",
            daemon.state.api_exchanges.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "daemon.storage_commits_total",
            "daemon",
            daemon.state.storage_commits.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "daemon.health_snapshots_total",
            "daemon",
            daemon.state.health_snapshots.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.record_gauge(
            "daemon.last_storage_height",
            "daemon",
            daemon.state.last_storage_height,
            "height",
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.state_root",
            "daemon",
            &daemon.state.state_root(),
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.root",
            "daemon",
            &daemon.daemon_root(),
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;

        if let Some(commit) = daemon
            .state
            .storage_commits
            .values()
            .max_by_key(|commit| commit.block_height)
        {
            self.capture_storage_commit(commit, timestamp_ms)?;
        }

        let throughput = self.throughput_estimate(daemon, timestamp_ms);
        self.record_gauge(
            "daemon.blocks_per_minute_milli",
            "throughput",
            throughput
                .get("blocks_per_minute_milli")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            TELEMETRY_UNIT_MILLI_PER_MINUTE,
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.record_gauge(
            "daemon.operation_receipts_per_minute_milli",
            "throughput",
            throughput
                .get("operation_receipts_per_minute_milli")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            TELEMETRY_UNIT_MILLI_PER_MINUTE,
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;

        let daemon_root = daemon.daemon_root();
        let node_root = daemon.node.node_state_root();
        let api_root = daemon.api.state_root();
        let storage_manifest_root = daemon.storage.manifest_root();
        let daemon_health_root = daemon
            .state
            .health_snapshots
            .last()
            .map(DaemonHealthSnapshot::health_root);
        let summary = self.daemon_summary(daemon, &throughput, timestamp_ms);
        let severity = self.max_severity();
        let pre_snapshot_state_root = self.state_root();
        let snapshot = TelemetrySnapshot::new(
            self.telemetry_id.clone(),
            Some(daemon.config.daemon_id.clone()),
            daemon.config.node_config.node_id.clone(),
            height,
            timestamp_ms,
            severity,
            Some(daemon_root),
            daemon_health_root,
            Some(node_root),
            Some(api_root),
            Some(storage_manifest_root),
            self.root_gauge_value("p2p.overlay_root", "p2p"),
            self.root_gauge_value("rpc.control_plane_root", "rpc"),
            self.root_gauge_value("relayer.state_root", "relayer"),
            summary,
            self.counter_root(),
            self.gauge_root(),
            self.event_root(),
            self.alert_root(),
            &pre_snapshot_state_root,
        )?;
        self.snapshots.push(snapshot.clone());
        Ok(snapshot)
    }

    pub fn capture_p2p_roots(
        &mut self,
        p2p: &P2pOverlayState,
        timestamp_ms: u64,
    ) -> TelemetryResult<String> {
        let height = p2p.height;
        let overlay_root = p2p.overlay_root();
        self.record_root_gauge(
            "p2p.overlay_root",
            "p2p",
            &overlay_root,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "p2p.peer_root",
            "p2p",
            &p2p.peer_root(),
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "p2p.sync_root",
            "p2p",
            &p2p.sync_root(),
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "p2p.gossip_root",
            "p2p",
            &p2p.gossip_root(),
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "p2p.relay_receipt_root",
            "p2p",
            &p2p.relay_receipt_root(),
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.peers_total",
            "p2p",
            p2p.handshakes.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.live_peers_total",
            "p2p",
            p2p.handshakes
                .values()
                .filter(|peer| peer.is_live(height))
                .count() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.sync_requests_total",
            "p2p",
            p2p.sync_requests.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.sync_responses_total",
            "p2p",
            p2p.sync_responses.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.gossip_messages_total",
            "p2p",
            p2p.gossip_messages.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.relay_receipts_total",
            "p2p",
            p2p.relay_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "p2p.quarantined_peers_total",
            "p2p",
            p2p.scorecards
                .values()
                .filter(|score| score.quarantined)
                .count() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "p2p"}),
            height,
            timestamp_ms,
        )?;
        Ok(overlay_root)
    }

    pub fn capture_rpc_roots(
        &mut self,
        rpc: &RpcControlPlaneState,
        timestamp_ms: u64,
    ) -> TelemetryResult<String> {
        let height = rpc.height;
        let state_root = rpc.state_root();
        self.record_root_gauge(
            "rpc.control_plane_root",
            "rpc",
            &state_root,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "rpc.method_registry_root",
            "rpc",
            &rpc.method_registry_root(),
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "rpc.request_receipt_root",
            "rpc",
            &rpc.request_receipt_root(),
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "rpc.response_receipt_root",
            "rpc",
            &rpc.response_receipt_root(),
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "rpc.methods_total",
            "rpc",
            rpc.method_registry.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "rpc.requests_total",
            "rpc",
            rpc.requests.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "rpc.responses_total",
            "rpc",
            rpc.responses.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "rpc.request_receipts_total",
            "rpc",
            rpc.request_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "rpc.response_receipts_total",
            "rpc",
            rpc.response_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "rpc.idempotency_records_total",
            "rpc",
            rpc.idempotency_cache.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "rpc"}),
            height,
            timestamp_ms,
        )?;
        Ok(state_root)
    }

    pub fn capture_relayer_roots(
        &mut self,
        relayer: &RelayerState,
        timestamp_ms: u64,
    ) -> TelemetryResult<String> {
        let height = relayer.current_height;
        let state_root = relayer.state_root();
        self.record_root_gauge(
            "relayer.state_root",
            "relayer",
            &state_root,
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "relayer.endpoint_root",
            "relayer",
            &relayer.endpoint_root(),
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "relayer.job_root",
            "relayer",
            &relayer.job_root(),
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "relayer.observation_receipt_root",
            "relayer",
            &relayer.observation_receipt_root(),
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "relayer.endpoints_total",
            "relayer",
            relayer.endpoints.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "relayer.jobs_total",
            "relayer",
            relayer.jobs.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "relayer.observation_receipts_total",
            "relayer",
            relayer.observation_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "relayer.batches_total",
            "relayer",
            relayer.batches.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "relayer.last_error_hash",
            "relayer",
            &relayer.last_error_hash,
            &json!({"subsystem": "relayer"}),
            height,
            timestamp_ms,
        )?;
        Ok(state_root)
    }

    pub fn capture_api_roots(
        &mut self,
        api: &ApiControlPlaneState,
        timestamp_ms: u64,
    ) -> TelemetryResult<String> {
        let height = api.height;
        let state_root = api.state_root();
        self.record_root_gauge(
            "api.control_plane_root",
            "api",
            &state_root,
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "api.route_registry_root",
            "api",
            &api.route_registry_root(),
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "api.session_root",
            "api",
            &api.session_root(),
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "api.request_receipt_root",
            "api",
            &api.request_receipt_root(),
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "api.response_receipt_root",
            "api",
            &api.response_receipt_root(),
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "api.routes_total",
            "api",
            api.route_registry.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "api.sessions_total",
            "api",
            api.sessions.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "api.request_receipts_total",
            "api",
            api.request_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "api.response_receipts_total",
            "api",
            api.response_receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "api.rate_limit_buckets_total",
            "api",
            api.rate_limit_buckets.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "api"}),
            height,
            timestamp_ms,
        )?;
        Ok(state_root)
    }

    pub fn capture_storage_roots(
        &mut self,
        storage: &StorageState,
        height: u64,
        timestamp_ms: u64,
    ) -> TelemetryResult<String> {
        let manifest_root = storage.manifest_root();
        self.record_root_gauge(
            "storage.manifest_root",
            "storage",
            &manifest_root,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "storage.snapshot_root",
            "storage",
            &storage.snapshot_root(),
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "storage.checkpoint_root",
            "storage",
            &storage.checkpoint_root(),
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "storage.chunk_root",
            "storage",
            &storage.chunk_root(),
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "storage.journal_root",
            "storage",
            &storage.journal_root(),
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "storage.snapshots_total",
            "storage",
            storage.snapshots.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "storage.checkpoints_total",
            "storage",
            storage.checkpoints.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "storage.chunks_total",
            "storage",
            storage.chunks.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "storage.retention_decisions_total",
            "storage",
            storage.retention_decisions.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "storage.restore_plans_total",
            "storage",
            storage.restore_plans.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "storage.journal_entries_total",
            "storage",
            storage.journal.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "storage"}),
            height,
            timestamp_ms,
        )?;
        if let Some(latest_snapshot) = storage
            .snapshots
            .values()
            .max_by_key(|snapshot| snapshot.block_height)
        {
            self.record_gauge(
                "storage.latest_snapshot_height",
                "storage",
                latest_snapshot.block_height,
                "height",
                &json!({"subsystem": "storage"}),
                height,
                timestamp_ms,
            )?;
            self.record_root_gauge(
                "storage.latest_snapshot_state_root",
                "storage",
                &latest_snapshot.state_root,
                &json!({"subsystem": "storage"}),
                height,
                timestamp_ms,
            )?;
        }
        Ok(manifest_root)
    }

    pub fn capture_storage_commit(
        &mut self,
        commit: &DaemonStorageCommit,
        timestamp_ms: u64,
    ) -> TelemetryResult<String> {
        let commit_root = commit.commit_root();
        self.record_root_gauge(
            "daemon.latest_storage_commit_root",
            "daemon",
            &commit_root,
            &json!({"subsystem": "daemon_storage_commit"}),
            commit.block_height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.latest_storage_commit_state_root",
            "daemon",
            &commit.state_root,
            &json!({"subsystem": "daemon_storage_commit"}),
            commit.block_height,
            timestamp_ms,
        )?;
        self.record_gauge(
            "daemon.latest_storage_commit_height",
            "daemon",
            commit.block_height,
            "height",
            &json!({"subsystem": "daemon_storage_commit"}),
            commit.block_height,
            timestamp_ms,
        )?;
        Ok(commit_root)
    }

    pub fn capture_health_snapshot(
        &mut self,
        health: &DaemonHealthSnapshot,
    ) -> TelemetryResult<String> {
        let health_root = health.health_root();
        self.record_root_gauge(
            "daemon.health_root",
            "daemon",
            &health_root,
            &json!({"subsystem": "daemon_health"}),
            health.height,
            health.timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.health_node_root",
            "daemon",
            &health.node_state_root,
            &json!({"subsystem": "daemon_health"}),
            health.height,
            health.timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.health_api_root",
            "daemon",
            &health.api_state_root,
            &json!({"subsystem": "daemon_health"}),
            health.height,
            health.timestamp_ms,
        )?;
        Ok(health_root)
    }

    pub fn throughput_estimate(&self, daemon: &NebulaDaemon, timestamp_ms: u64) -> Value {
        let cutoff_ms = timestamp_ms.saturating_sub(self.throughput_window_ms);
        let samples = daemon
            .state
            .health_snapshots
            .iter()
            .filter(|snapshot| snapshot.timestamp_ms >= cutoff_ms)
            .collect::<Vec<_>>();
        let (base_height, base_ms) = samples
            .first()
            .map(|snapshot| (snapshot.height, snapshot.timestamp_ms))
            .or_else(|| daemon.state.started_at_ms.map(|started| (0, started)))
            .unwrap_or((daemon.node.height(), timestamp_ms));
        let latest_height = daemon.node.height();
        let elapsed_ms = timestamp_ms.saturating_sub(base_ms);
        let block_delta = latest_height.saturating_sub(base_height);
        let operation_receipt_count = daemon
            .state
            .operation_receipts
            .iter()
            .filter(|receipt| receipt.timestamp_ms >= cutoff_ms)
            .count() as u64;
        json!({
            "kind": "telemetry_throughput_estimate",
            "chain_id": CHAIN_ID,
            "sample_window_ms": self.throughput_window_ms,
            "elapsed_ms": elapsed_ms,
            "base_height": base_height,
            "latest_height": latest_height,
            "block_delta": block_delta,
            "operation_receipt_count": operation_receipt_count,
            "blocks_per_minute_milli": rate_per_minute_milli(block_delta, elapsed_ms),
            "operation_receipts_per_minute_milli": rate_per_minute_milli(operation_receipt_count, elapsed_ms),
        })
    }

    pub fn prune_old_events(&mut self, now_ms: u64) -> usize {
        let before = self.events.len();
        let cutoff = now_ms.saturating_sub(self.event_retention_ms);
        self.events.retain(|event| event.timestamp_ms >= cutoff);
        if self.events.len() > self.max_events {
            let excess = self.events.len() - self.max_events;
            self.events.drain(0..excess);
        }
        before.saturating_sub(self.events.len())
    }

    pub fn counter_root(&self) -> String {
        merkle_root(
            "TELEMETRY-COUNTER",
            &self
                .counters
                .values()
                .map(TelemetryCounter::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn gauge_root(&self) -> String {
        merkle_root(
            "TELEMETRY-GAUGE",
            &self
                .gauges
                .values()
                .map(TelemetryGauge::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn event_root(&self) -> String {
        merkle_root(
            "TELEMETRY-EVENT",
            &self
                .events
                .iter()
                .map(TelemetryEvent::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn alert_root(&self) -> String {
        merkle_root(
            "TELEMETRY-ALERT",
            &self
                .alerts
                .values()
                .map(TelemetryAlert::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn snapshot_root(&self) -> String {
        merkle_root(
            "TELEMETRY-SNAPSHOT",
            &self
                .snapshots
                .iter()
                .map(TelemetrySnapshot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.unsigned_record();
        record
            .as_object_mut()
            .expect("telemetry state public record object")
            .insert(
                "telemetry_state_root".to_string(),
                Value::String(self.state_root()),
            );
        record
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "TELEMETRY-STATE",
            &[HashPart::Json(&self.unsigned_record())],
            32,
        )
    }

    fn unsigned_record(&self) -> Value {
        json!({
            "kind": "telemetry_state",
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "telemetry_id": self.telemetry_id,
            "node_label": self.node_label,
            "current_height": self.current_height,
            "last_updated_ms": self.last_updated_ms,
            "event_retention_ms": self.event_retention_ms,
            "max_events": self.max_events as u64,
            "throughput_window_ms": self.throughput_window_ms,
            "counter_root": self.counter_root(),
            "gauge_root": self.gauge_root(),
            "event_root": self.event_root(),
            "alert_root": self.alert_root(),
            "snapshot_root": self.snapshot_root(),
            "counter_count": self.counters.len() as u64,
            "gauge_count": self.gauges.len() as u64,
            "event_count": self.events.len() as u64,
            "alert_count": self.alerts.len() as u64,
            "snapshot_count": self.snapshots.len() as u64,
            "latest_snapshot_id": self.snapshots.last().map(|snapshot| snapshot.snapshot_id.clone()),
        })
    }

    fn capture_daemon_health_roots(
        &mut self,
        daemon: &NebulaDaemon,
        timestamp_ms: u64,
    ) -> TelemetryResult<()> {
        let height = daemon.node.height();
        self.record_root_gauge(
            "daemon.node_state_root",
            "daemon",
            &daemon.node.node_state_root(),
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.api_state_root",
            "daemon",
            &daemon.api.state_root(),
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "daemon.storage_manifest_root",
            "daemon",
            &daemon.storage.manifest_root(),
            &json!({"subsystem": "daemon"}),
            height,
            timestamp_ms,
        )?;
        if let Some(health) = daemon.state.health_snapshots.last() {
            self.capture_health_snapshot(health)?;
        }
        Ok(())
    }

    fn capture_sequencer_roots(
        &mut self,
        daemon: &NebulaDaemon,
        timestamp_ms: u64,
    ) -> TelemetryResult<()> {
        let height = daemon.node.height();
        let sequencer = &daemon.node.sequencer;
        self.record_gauge(
            "sequencer.pending_transactions",
            "sequencer",
            sequencer.pending_transaction_count(),
            "transactions",
            &json!({"subsystem": "sequencer"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "sequencer.state_root",
            "sequencer",
            &sequencer.state_root(),
            &json!({"subsystem": "sequencer"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "fee_smoothing.state_root",
            "fee_smoothing",
            &sequencer.fee_smoothing.state_root(),
            &json!({"subsystem": "fee_smoothing"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "bridge.state_root",
            "bridge",
            &sequencer.bridge.bridge_root(),
            &json!({"subsystem": "bridge"}),
            height,
            timestamp_ms,
        )?;
        self.record_root_gauge(
            "monero.monitor_root",
            "monero",
            &sequencer.monero.state_root(),
            &json!({"subsystem": "monero"}),
            height,
            timestamp_ms,
        )?;
        let proof_market = proof_market_snapshot(&sequencer.prover);
        let proof_market_root =
            telemetry_payload_root("TELEMETRY-PROOF-MARKET-SNAPSHOT", &proof_market);
        self.record_payload_root_gauge(
            "proof_market.snapshot_root",
            "proof_market",
            &proof_market_root,
            &json!({"subsystem": "proof_market"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "proof_market.pending_jobs_total",
            "proof_market",
            sequencer.prover.pending_job_count(),
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "proof_market"}),
            height,
            timestamp_ms,
        )?;
        self.set_counter(
            "proof_market.receipts_total",
            "proof_market",
            sequencer.prover.receipts.len() as u64,
            TELEMETRY_UNIT_RECORDS,
            &json!({"subsystem": "proof_market"}),
            height,
            timestamp_ms,
        )?;
        Ok(())
    }

    fn daemon_summary(
        &self,
        daemon: &NebulaDaemon,
        throughput: &Value,
        timestamp_ms: u64,
    ) -> Value {
        let sequencer = &daemon.node.sequencer;
        let proof_market = proof_market_snapshot(&sequencer.prover);
        json!({
            "kind": "telemetry_daemon_summary",
            "chain_id": CHAIN_ID,
            "telemetry_protocol_version": TELEMETRY_PROTOCOL_VERSION,
            "timestamp_ms": timestamp_ms,
            "daemon_id": daemon.config.daemon_id,
            "node_id": daemon.config.node_config.node_id,
            "height": daemon.node.height(),
            "daemon_status": daemon.state.status,
            "pending_transaction_count": sequencer.pending_transaction_count(),
            "throughput": throughput,
            "fee_smoothing_root": sequencer.fee_smoothing.state_root(),
            "bridge_root": sequencer.bridge.bridge_root(),
            "monero_monitor_root": sequencer.monero.state_root(),
            "proof_market_root": telemetry_payload_root("TELEMETRY-PROOF-MARKET-SNAPSHOT", &proof_market),
            "proof_market_pending_job_count": sequencer.prover.pending_job_count(),
            "storage_manifest_root": daemon.storage.manifest_root(),
            "storage_commit_root": daemon.state.storage_commit_root(),
            "storage_commit_count": daemon.state.storage_commits.len() as u64,
            "api_state_root": daemon.api.state_root(),
            "api_request_receipt_count": daemon.api.request_receipts.len() as u64,
            "api_response_receipt_count": daemon.api.response_receipts.len() as u64,
            "daemon_root": daemon.daemon_root(),
            "node_state_root": daemon.node.node_state_root(),
        })
    }

    fn max_severity(&self) -> TelemetrySeverity {
        self.alerts
            .values()
            .map(|alert| alert.severity)
            .max()
            .unwrap_or(TelemetrySeverity::Info)
    }

    fn root_gauge_value(&self, name: &str, source: &str) -> Option<String> {
        self.gauges
            .values()
            .find(|gauge| gauge.name == name && gauge.source == source)
            .and_then(|gauge| gauge.root.clone())
    }
}

pub fn telemetry_event_id(
    event_kind: &str,
    source: &str,
    height: u64,
    timestamp_ms: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "TELEMETRY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
            HashPart::Str(event_kind),
            HashPart::Str(source),
            HashPart::Int(height as i128),
            HashPart::Int(timestamp_ms as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn telemetry_alert_id(
    alert_kind: &str,
    source: &str,
    severity: TelemetrySeverity,
    height: u64,
    signal_root: &str,
    detail_root: &str,
) -> String {
    domain_hash(
        "TELEMETRY-ALERT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
            HashPart::Str(alert_kind),
            HashPart::Str(source),
            HashPart::Str(severity.as_str()),
            HashPart::Int(height as i128),
            HashPart::Str(signal_root),
            HashPart::Str(detail_root),
        ],
        32,
    )
}

pub fn telemetry_counter_id(name: &str, source: &str, unit: &str, labels_root: &str) -> String {
    domain_hash(
        "TELEMETRY-COUNTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
            HashPart::Str(name),
            HashPart::Str(source),
            HashPart::Str(unit),
            HashPart::Str(labels_root),
        ],
        32,
    )
}

pub fn telemetry_gauge_id(name: &str, source: &str, unit: &str, labels_root: &str) -> String {
    domain_hash(
        "TELEMETRY-GAUGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
            HashPart::Str(name),
            HashPart::Str(source),
            HashPart::Str(unit),
            HashPart::Str(labels_root),
        ],
        32,
    )
}

pub fn telemetry_snapshot_id(
    telemetry_id: &str,
    node_id: &str,
    height: u64,
    timestamp_ms: u64,
    daemon_root: &str,
    summary_root: &str,
    telemetry_state_root: &str,
) -> String {
    domain_hash(
        "TELEMETRY-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
            HashPart::Str(telemetry_id),
            HashPart::Str(node_id),
            HashPart::Int(height as i128),
            HashPart::Int(timestamp_ms as i128),
            HashPart::Str(daemon_root),
            HashPart::Str(summary_root),
            HashPart::Str(telemetry_state_root),
        ],
        32,
    )
}

pub fn telemetry_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(TELEMETRY_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn telemetry_string_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| json!({ "value_root": telemetry_payload_root("TELEMETRY-STRING", &json!({ "value": value })) }))
            .collect::<Vec<_>>(),
    )
}

fn ensure_nonempty(field: &str, value: &str) -> TelemetryResult<()> {
    if value.is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

fn rate_per_minute_milli(count: u64, elapsed_ms: u64) -> u64 {
    if elapsed_ms == 0 {
        return 0;
    }
    (((count as u128) * 60_000_u128 * 1_000_u128) / (elapsed_ms as u128)).min(u64::MAX as u128)
        as u64
}
