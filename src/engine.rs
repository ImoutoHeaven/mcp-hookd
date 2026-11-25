//! Core subscription engine: startup recovery, catalog merge, upstream consumption,
//! ordered webhook delivery with backoff/suspend, and external event ingest (spec §4-§6).

use crate::auth::{
    AuthCheckOutcome, AuthContextClient, compute_refresh_before, intersect_scopes, scopes_subset,
};
use crate::config::{Config, IngestEventConfig};
use crate::outbound::{DeliveryOutcome, OutboundClient, validate_callback_url};
use crate::schema::{normalize_filter_arguments, scalar_eq, validate_against_schema};
use crate::store::{
    PersistedState, PersistedSubscription, STATE_VERSION, StateStore, StoreHandle, VerifiedEndpoint,
};
use crate::types::{
    ByteLease, CallbackErrorReason, MAX_INGEST_BODY_BYTES, MAX_WEBHOOK_PAYLOAD_BYTES, MemoryPools,
    Profile, QuotaConfig, SecretString, SubscriptionKey, decode_whsec, is_valid_event_id,
    random_base64url, random_bytes, sha256_bytes, sha256_hex, unix_now, utc_rfc3339_now,
};
use crate::upstream::{
    UpstreamClient, UpstreamError, UpstreamEventDescriptor, UpstreamPolledEvent,
    UpstreamStreamFrame,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const CATALOG_CACHE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_LIST_PAGE_SIZE: usize = 100;
const MAX_TRANSIENT_RETRIES: u32 = 6;
const VERIFY_RATE_WINDOW: Duration = Duration::from_secs(60);
const VERIFY_RATE_LIMIT: usize = 20;
const KEY_LOCK_PRUNE_THRESHOLD: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineError {
    InvalidParams(String),
    NotFound { kind: &'static str, message: String },
    Forbidden(String),
    ResourceExhausted(String),
    Unsupported(String),
    CallbackEndpoint(CallbackErrorReason),
    Internal(String),
}

impl EngineError {
    pub fn to_jsonrpc_code(&self, profile: Profile) -> i64 {
        match self {
            Self::InvalidParams(_) => -32602,
            Self::NotFound { .. } => profile.not_found_code(),
            Self::Forbidden(_) => profile.forbidden_code(),
            Self::ResourceExhausted(_) => profile.resource_exhausted_code(),
            Self::Unsupported(_) => profile.unsupported_code(),
            Self::CallbackEndpoint(_) => profile.callback_error_code(),
            Self::Internal(_) => -32603,
        }
    }

    pub fn error_data(&self) -> Option<Value> {
        match self {
            Self::NotFound { kind, .. } => Some(json!({ "kind": kind })),
            Self::CallbackEndpoint(reason) => Some(json!({ "reason": reason.as_str() })),
            _ => None,
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParams(m)
            | Self::Forbidden(m)
            | Self::ResourceExhausted(m)
            | Self::Unsupported(m)
            | Self::Internal(m) => f.write_str(m),
            Self::NotFound { message, .. } => f.write_str(message),
            Self::CallbackEndpoint(reason) => {
                write!(
                    f,
                    "callback endpoint verification failed: {}",
                    reason.as_str()
                )
            }
        }
    }
}

impl std::error::Error for EngineError {}

#[derive(Clone, Debug)]
pub enum CallerAuth {
    StaticSlot(usize),
    Delegated {
        auth_ref: String,
        header_scopes: Vec<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CatalogEvent {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub delivery: Vec<String>,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload_schema: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ListEventsResult {
    pub events: Vec<CatalogEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PassthroughResolution {
    NotFound,
    IngestUnsupported,
    DisallowedArgument(String),
    UpstreamAllowed,
}

#[derive(Clone, Debug)]
pub struct SubscribeRequest {
    pub event_name: String,
    pub arguments: Map<String, Value>,
    pub delivery_mode: String,
    pub delivery_url: String,
    pub delivery_secret: SecretString,
    pub ttl_ms: Option<Option<u64>>,
    pub cursor: Option<String>,
    pub max_age_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryStatus {
    pub active: bool,
    pub last_error: Option<CallbackErrorReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SubscribeResponse {
    pub id: String,
    pub refresh_before: u64,
    pub cursor: Option<String>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_status: Option<DeliveryStatus>,
}

#[derive(Clone, Debug)]
pub struct UnsubscribeRequest {
    pub event_name: String,
    pub arguments: Map<String, Value>,
    pub delivery_mode: Option<String>,
    pub delivery_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IngestResult {
    pub ok: bool,
    pub event_id: String,
    pub deduplicated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropped_slow: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IngestError {
    PayloadTooLarge(String),
    BadRequest(String),
    Unprocessable(String),
    Conflict(String),
    ServiceUnavailable(String),
}

impl IngestError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge(m)
            | Self::BadRequest(m)
            | Self::Unprocessable(m)
            | Self::Conflict(m)
            | Self::ServiceUnavailable(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for IngestError {}

#[derive(Clone, Debug)]
struct ResolvedCaller {
    principal: String,
    auth_ref: Option<String>,
    effective_scopes: Vec<String>,
    expires_at: Option<u64>,
}

#[derive(Default)]
struct CatalogCache {
    fetched_at: Option<Instant>,
    upstream_events: Vec<UpstreamEventDescriptor>,
}

#[derive(Clone, Debug)]
enum EventKind {
    Ingest {
        input_schema: Value,
    },
    Upstream {
        input_schema: Value,
        disallow_arguments: Vec<String>,
        supports_webhook: bool,
        supports_push: bool,
    },
}

#[derive(Clone, Debug)]
enum SubSource {
    Ingest {
        filter_fields: Vec<String>,
        arguments: Map<String, Value>,
    },
    Upstream {
        event_name: String,
        arguments: Map<String, Value>,
    },
}

enum OutboxItem {
    Event {
        webhook_id: String,
        event_id: String,
        name: String,
        timestamp: String,
        data_json: String,
        advance_cursor: Option<String>,
        is_ingest: bool,
        _lease: ByteLease,
    },
    Gap {
        cursor: String,
        _lease: ByteLease,
    },
    Checkpoint {
        cursor: String,
        _lease: ByteLease,
    },
}

struct PendingRefresh {
    refresh_before: u64,
    secret: SecretString,
    prev_secret: Option<SecretString>,
    prev_secret_until: Option<u64>,
    resume_suspended: bool,
    resume_auth_paused: bool,
    captured_truncated: bool,
}

struct SubState {
    auth_ref: Option<String>,
    granted_scopes: Vec<String>,
    secret: SecretString,
    prev_secret: Option<SecretString>,
    prev_secret_until: Option<u64>,
    refresh_before: u64,
    safe_cursor: Option<String>,
    ingest_cursor: Option<String>,
    pending_truncated_for_refresh: bool,
    suspended: bool,
    last_error: Option<CallbackErrorReason>,
    consecutive_failures: u32,
    first_failure_at: Option<Instant>,
    auth_paused: bool,
    removed: bool,
    registration_pending: bool,
    pending_refresh: Option<PendingRefresh>,
    outbox: VecDeque<OutboxItem>,
}

struct SubRuntime {
    id: String,
    key: SubscriptionKey,
    source: SubSource,
    state: Mutex<SubState>,
    outbox_notify: Notify,
    space_notify: Notify,
    cancel_tx: watch::Sender<bool>,
    consumer_cancel: Mutex<Option<watch::Sender<bool>>>,
}

impl SubRuntime {
    fn to_persisted(&self) -> PersistedSubscription {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let refresh = st.pending_refresh.as_ref();
        PersistedSubscription {
            id: self.id.clone(),
            key: self.key.clone(),
            arguments: match &self.source {
                SubSource::Ingest { arguments, .. } | SubSource::Upstream { arguments, .. } => {
                    arguments.clone()
                }
            },
            auth_ref: st.auth_ref.clone(),
            granted_scopes: st.granted_scopes.clone(),
            secret: refresh.map_or(&st.secret, |r| &r.secret).clone(),
            prev_secret: refresh.map_or(&st.prev_secret, |r| &r.prev_secret).clone(),
            prev_secret_until: refresh.map_or(st.prev_secret_until, |r| r.prev_secret_until),
            refresh_before: refresh.map_or(st.refresh_before, |r| r.refresh_before),
            safe_cursor: st.safe_cursor.clone(),
            pending_truncated_for_refresh: st.pending_truncated_for_refresh,
            suspended: st.suspended && !refresh.is_some_and(|r| r.resume_suspended),
            last_error: st.last_error,
        }
    }

    fn stop_consumer(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.stop_consumer_locked(&mut state);
    }

    fn stop_consumer_locked(&self, _state: &mut SubState) {
        let mut guard = self
            .consumer_cancel
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(tx) = guard.take() {
            tx.send_replace(true);
        }
    }

    fn cancel_all(&self) {
        self.stop_consumer();
        self.cancel_tx.send_replace(true);
        self.outbox_notify.notify_waiters();
        self.space_notify.notify_waiters();
    }
}

struct RefreshGuard<'a> {
    engine: &'a HookdEngine,
    sub: Arc<SubRuntime>,
    committed: bool,
}

impl RefreshGuard<'_> {
    fn commit(&mut self) -> Result<bool, EngineError> {
        let runtime = self
            .engine
            .runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.engine.ensure_running()?;
        if !runtime
            .subscriptions
            .get(&self.sub.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.sub))
        {
            return Err(EngineError::NotFound {
                kind: "subscription",
                message: "subscription was removed while refreshing".into(),
            });
        }
        let mut state = self.sub.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.removed {
            return Err(EngineError::NotFound {
                kind: "subscription",
                message: "subscription was removed while refreshing".into(),
            });
        }
        let refresh = state
            .pending_refresh
            .take()
            .ok_or_else(|| EngineError::Internal("refresh transaction is missing".into()))?;
        let resume_suspended = refresh.resume_suspended && state.suspended;
        let resume_auth = refresh.resume_auth_paused && state.auth_paused;
        state.refresh_before = refresh.refresh_before;
        state.secret = refresh.secret;
        state.prev_secret = refresh.prev_secret;
        state.prev_secret_until = refresh.prev_secret_until;
        if resume_suspended {
            state.suspended = false;
            state.consecutive_failures = 0;
            state.first_failure_at = None;
        }
        if resume_auth {
            state.auth_paused = false;
        }
        self.committed = true;
        Ok(resume_suspended || resume_auth)
    }
}

impl Drop for RefreshGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let dirty = {
            let runtime = self
                .engine
                .runtime
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let mut state = self.sub.state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(refresh) = state.pending_refresh.take() {
                state.pending_truncated_for_refresh |= refresh.captured_truncated;
            }
            runtime
                .subscriptions
                .get(&self.sub.key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.sub))
        };
        if dirty {
            self.engine.mark_state_dirty();
        }
    }
}

struct RegistrationGuard<'a> {
    engine: &'a HookdEngine,
    sub: Arc<SubRuntime>,
    committed: bool,
}

impl RegistrationGuard<'_> {
    fn commit(&mut self) -> Result<(), EngineError> {
        let runtime = self
            .engine
            .runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.engine.ensure_running()?;
        if !runtime
            .subscriptions
            .get(&self.sub.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.sub))
        {
            return Err(EngineError::NotFound {
                kind: "subscription",
                message: "subscription was removed while registering".into(),
            });
        }
        let mut state = self.sub.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.removed {
            return Err(EngineError::NotFound {
                kind: "subscription",
                message: "subscription was removed while registering".into(),
            });
        }
        state.registration_pending = false;
        self.committed = true;
        Ok(())
    }
}

impl Drop for RegistrationGuard<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let dirty = {
            let mut runtime = self
                .engine
                .runtime
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let still_current = runtime
                .subscriptions
                .get(&self.sub.key)
                .is_some_and(|current| Arc::ptr_eq(current, &self.sub));
            if still_current {
                runtime.subscriptions.remove(&self.sub.key);
            }
            {
                let mut state = self.sub.state.lock().unwrap_or_else(|p| p.into_inner());
                state.removed = true;
                state.outbox.clear();
            }
            self.sub.cancel_all();
            still_current
        };
        if dirty {
            self.engine.mark_state_dirty();
        }
    }
}

struct DedupEntry {
    payload_sha256: [u8; 32],
    inserted_at: u64,
}

struct RuntimeState {
    subscriptions: HashMap<SubscriptionKey, Arc<SubRuntime>>,
    verified_endpoints: HashMap<(String, String, String), u64>,
    dedup: HashMap<(usize, String), DedupEntry>,
}

impl RuntimeState {
    fn snapshot(&self) -> PersistedState {
        let mut subscriptions: Vec<PersistedSubscription> = self
            .subscriptions
            .values()
            .map(|sub| sub.to_persisted())
            .collect();
        subscriptions.sort_by(|a, b| a.id.cmp(&b.id));

        let mut verified_endpoints: Vec<VerifiedEndpoint> = self
            .verified_endpoints
            .iter()
            .map(
                |((principal, url, secret_sha256), &verified_at)| VerifiedEndpoint {
                    principal: principal.clone(),
                    url: url.clone(),
                    secret_sha256: secret_sha256.clone(),
                    verified_at,
                },
            )
            .collect();
        verified_endpoints.sort_by(|a, b| {
            (&a.principal, &a.url, &a.secret_sha256).cmp(&(&b.principal, &b.url, &b.secret_sha256))
        });

        PersistedState {
            version: STATE_VERSION,
            subscriptions,
            verified_endpoints,
        }
    }
}

struct VerifyBucket {
    window_start: Instant,
    count: usize,
}

#[derive(Deserialize)]
struct RawIngestEvent {
    #[serde(rename = "eventId")]
    event_id: String,
    name: String,
    #[serde(default)]
    timestamp: Option<String>,
    data: Value,
}

pub struct HookdEngine {
    config: Config,
    quotas: QuotaConfig,
    pools: MemoryPools,
    outbound: OutboundClient,
    upstream: Option<UpstreamClient>,
    auth_client: Option<AuthContextClient>,
    store: StoreHandle,
    upstream_stream_sem: Arc<Semaphore>,
    global_delivery_sem: Arc<Semaphore>,
    catalog_cache: tokio::sync::Mutex<CatalogCache>,
    key_locks: Mutex<HashMap<SubscriptionKey, Weak<tokio::sync::Mutex<()>>>>,
    verify_rate: Mutex<HashMap<(String, String), VerifyBucket>>,
    runtime: Mutex<RuntimeState>,
    shutdown_tx: watch::Sender<bool>,
    tasks: TaskTracker,
    force_stop: CancellationToken,
    shutdown_result: tokio::sync::OnceCell<Result<(), String>>,
}

impl HookdEngine {
    pub async fn new(
        config: Config,
        quotas: QuotaConfig,
        pools: MemoryPools,
        outbound_override: Option<OutboundClient>,
    ) -> Result<Arc<Self>, String> {
        let (state_store, persisted) = StateStore::open(config.state_path.clone())?;

        let outbound = match outbound_override {
            Some(client) => client,
            None => OutboundClient::from_quotas(&quotas)?,
        };
        let upstream = config
            .upstream
            .as_ref()
            .map(|config| {
                UpstreamClient::new(config, Arc::clone(&pools.proxy), Arc::clone(&pools.control))
            })
            .transpose()?;
        let auth_client = config
            .auth_context
            .as_ref()
            .map(AuthContextClient::new)
            .transpose()?;

        let now = unix_now();
        let mut mutated = false;

        // Prune expired verified endpoints.
        let mut verified_endpoints = HashMap::new();
        for ve in persisted.verified_endpoints {
            if ve
                .verified_at
                .saturating_add(quotas.verified_retention_secs)
                > now
            {
                verified_endpoints.insert((ve.principal, ve.url, ve.secret_sha256), ve.verified_at);
            } else {
                mutated = true;
            }
        }

        // Reconcile persisted subscriptions before launching any consumer or delivery worker.
        let mut kept: Vec<(PersistedSubscription, bool)> = Vec::new();
        let mut transient_auth_refs: HashSet<String> = HashSet::new();

        if let Some(ref client) = auth_client {
            let mut unique_refs: Vec<String> = persisted
                .subscriptions
                .iter()
                .filter_map(|s| s.auth_ref.clone())
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            unique_refs.sort();

            let mut outcomes: HashMap<String, AuthCheckOutcome> = HashMap::new();
            for aref in unique_refs {
                let outcome = client.check_live(&aref).await;
                outcomes.insert(aref, outcome);
            }

            for sub in persisted.subscriptions {
                if sub.refresh_before <= now {
                    mutated = true;
                    continue;
                }
                let Some(ref aref) = sub.auth_ref else {
                    mutated = true;
                    continue;
                };
                match outcomes.get(aref) {
                    Some(AuthCheckOutcome::Active(checked)) => {
                        if scopes_subset(&sub.granted_scopes, &checked.scopes) {
                            kept.push((sub, false));
                        } else {
                            mutated = true;
                        }
                    }
                    Some(AuthCheckOutcome::Inactive) | None => {
                        mutated = true;
                    }
                    Some(AuthCheckOutcome::TransientError(_)) => {
                        transient_auth_refs.insert(aref.clone());
                        kept.push((sub, true));
                    }
                }
            }
        } else {
            let slot_count = config.inbound_tokens.len();
            for sub in persisted.subscriptions {
                if sub.refresh_before <= now {
                    mutated = true;
                    continue;
                }
                let valid_slot = sub
                    .key
                    .principal
                    .strip_prefix("static:")
                    .and_then(|s| s.parse::<usize>().ok())
                    .is_some_and(|idx| idx < slot_count);
                if valid_slot {
                    kept.push((sub, false));
                } else {
                    mutated = true;
                }
            }
        }

        let (shutdown_tx, _) = watch::channel(false);
        let upstream_stream_sem = Arc::new(Semaphore::new(quotas.max_upstream_streams));
        let global_delivery_sem = Arc::new(Semaphore::new(quotas.max_global_deliveries));

        let mut subscriptions = HashMap::new();
        for (sub, auth_paused) in kept {
            let Some(source) = build_sub_source(&config, &sub.key, &sub.arguments) else {
                mutated = true;
                continue;
            };
            let rt = Arc::new(new_sub_runtime(sub, source, auth_paused));
            subscriptions.insert(rt.key.clone(), rt);
        }

        let engine = Arc::new(Self {
            config,
            quotas,
            pools,
            outbound,
            upstream,
            auth_client,
            store: StoreHandle::spawn(state_store),
            upstream_stream_sem,
            global_delivery_sem,
            catalog_cache: tokio::sync::Mutex::new(CatalogCache::default()),
            key_locks: Mutex::new(HashMap::new()),
            verify_rate: Mutex::new(HashMap::new()),
            runtime: Mutex::new(RuntimeState {
                subscriptions,
                verified_endpoints,
                dedup: HashMap::new(),
            }),
            shutdown_tx,
            tasks: TaskTracker::new(),
            force_stop: CancellationToken::new(),
            shutdown_result: tokio::sync::OnceCell::new(),
        });

        if mutated && let Err(error) = engine.persist_state().await {
            let _ = engine.store.shutdown().await;
            return Err(error);
        }

        // Start delivery workers and upstream consumers for active, unpaused subscriptions.
        let active_subs: Vec<Arc<SubRuntime>> = {
            let rt = engine.runtime.lock().unwrap_or_else(|p| p.into_inner());
            rt.subscriptions.values().cloned().collect()
        };
        for sub in active_subs {
            let (paused, suspended) = {
                let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                (st.auth_paused, st.suspended)
            };
            engine.spawn_delivery_worker(Arc::clone(&sub));
            if !paused && !suspended && matches!(sub.source, SubSource::Upstream { .. }) {
                engine.spawn_upstream_consumer(Arc::clone(&sub));
            }
        }

        // If any startup auth_refs hit transient errors, spawn an exponential backoff retry task.
        if !transient_auth_refs.is_empty() {
            let eng = Arc::clone(&engine);
            engine.spawn_task(async move {
                eng.run_startup_auth_recovery(transient_auth_refs).await;
            });
        }

        // Spawn periodic expiry reaper and authorization re-verification loop.
        {
            let eng = Arc::clone(&engine);
            engine.spawn_task(async move {
                eng.run_periodic_maintenance().await;
            });
        }

        Ok(engine)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn quotas(&self) -> &QuotaConfig {
        &self.quotas
    }

    pub fn pools(&self) -> &MemoryPools {
        &self.pools
    }

    pub fn upstream_client(&self) -> Option<&UpstreamClient> {
        self.upstream.as_ref()
    }

    pub fn auth_client(&self) -> Option<&AuthContextClient> {
        self.auth_client.as_ref()
    }

    pub fn active_subscription_count(&self) -> usize {
        self.runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .subscriptions
            .len()
    }

    pub async fn list_events(
        &self,
        caller: &CallerAuth,
        legacy_session: bool,
        cursor: Option<&str>,
        page_size: Option<usize>,
    ) -> Result<ListEventsResult, EngineError> {
        let _resolved = self.resolve_caller(caller, false).await?;
        let upstream_events = self.get_upstream_catalog().await?;

        let mut merged = Vec::new();
        for ev in &upstream_events {
            let cat = self.transform_upstream_event(ev);
            let include = if legacy_session || self.config.profile == Profile::Chatgpt {
                cat.delivery.iter().any(|m| m == "webhook")
            } else {
                true
            };
            if include {
                let mut item = cat;
                if legacy_session {
                    item.delivery = vec!["webhook".into()];
                }
                merged.push(item);
            }
        }

        if let Some(ref ingest) = self.config.ingest {
            for ev in &ingest.events {
                merged.push(CatalogEvent {
                    name: ev.name.clone(),
                    description: ev.description.clone(),
                    delivery: vec!["webhook".into()],
                    input_schema: ev.input_schema.clone(),
                    payload_schema: ev.payload_schema.clone(),
                });
            }
        }

        merged.sort_by(|a, b| a.name.cmp(&b.name));

        let filtered: Vec<CatalogEvent> = match cursor {
            Some(c) if !c.is_empty() => merged
                .into_iter()
                .filter(|ev| ev.name.as_str() > c)
                .collect(),
            _ => merged,
        };

        let limit = page_size.unwrap_or(DEFAULT_LIST_PAGE_SIZE).max(1);
        let has_more = filtered.len() > limit;
        let page: Vec<CatalogEvent> = filtered.into_iter().take(limit).collect();
        let next_cursor = if has_more {
            page.last().map(|ev| ev.name.clone())
        } else {
            None
        };

        Ok(ListEventsResult {
            events: page,
            next_cursor,
        })
    }

    pub async fn routing_input_schema(&self, name: &str) -> Result<Option<Value>, EngineError> {
        if let Some(event) = self.find_ingest_event(name) {
            return Ok(Some(event.input_schema.clone()));
        }
        Ok(self
            .get_upstream_catalog()
            .await?
            .into_iter()
            .find(|event| event.name == name)
            .map(|event| event.input_schema))
    }

    pub async fn resolve_event_for_passthrough(
        &self,
        name: &str,
        arguments: Option<&Map<String, Value>>,
    ) -> Result<PassthroughResolution, EngineError> {
        if self.find_ingest_event(name).is_some() {
            return Ok(PassthroughResolution::IngestUnsupported);
        }
        let upstream_events = self.get_upstream_catalog().await?;
        let exists = upstream_events.iter().any(|ev| ev.name == name);
        if !exists {
            return Ok(PassthroughResolution::NotFound);
        }
        if let Some(args) = arguments
            && let Some(expose) = self.find_expose_event(name)
        {
            for disallowed in &expose.disallow_arguments {
                if args.contains_key(disallowed) {
                    return Ok(PassthroughResolution::DisallowedArgument(
                        disallowed.clone(),
                    ));
                }
            }
        }
        Ok(PassthroughResolution::UpstreamAllowed)
    }

    pub async fn subscribe(
        self: &Arc<Self>,
        caller: &CallerAuth,
        req: SubscribeRequest,
    ) -> Result<SubscribeResponse, EngineError> {
        if req.delivery_mode != "webhook" {
            return Err(EngineError::InvalidParams(
                "delivery.mode must be 'webhook'".into(),
            ));
        }
        let parsed_url =
            validate_callback_url(&req.delivery_url, self.quotas.allow_loopback_callbacks)
                .map_err(EngineError::InvalidParams)?;
        let _ = decode_whsec(req.delivery_secret.expose()).map_err(EngineError::InvalidParams)?;

        let resolved = self.resolve_caller(caller, true).await?;

        let event_kind = self.resolve_event_for_subscribe(&req.event_name).await?;
        let (input_schema, disallow_args, is_ingest) = match &event_kind {
            EventKind::Ingest { input_schema } => (input_schema.clone(), Vec::new(), true),
            EventKind::Upstream {
                input_schema,
                disallow_arguments,
                supports_webhook,
                ..
            } => {
                if !supports_webhook {
                    return Err(EngineError::Unsupported(format!(
                        "event '{}' does not support webhook delivery",
                        req.event_name
                    )));
                }
                (input_schema.clone(), disallow_arguments.clone(), false)
            }
        };

        for bad in &disallow_args {
            if req.arguments.contains_key(bad) {
                return Err(EngineError::InvalidParams(format!(
                    "argument '{bad}' is disallowed for event '{}'",
                    req.event_name
                )));
            }
        }
        let normalized_args = normalize_filter_arguments(&input_schema, &req.arguments)
            .await
            .map_err(EngineError::InvalidParams)?;

        let key = SubscriptionKey::new(
            &resolved.principal,
            &req.delivery_url,
            &req.event_name,
            &normalized_args,
        )
        .map_err(EngineError::InvalidParams)?;
        let sub_id = key.subscription_id();

        let key_lock = self.key_lock(&key);
        let _guard = key_lock.lock().await;

        let now = unix_now();
        let refresh_before = compute_refresh_before(
            now,
            req.ttl_ms,
            self.config.max_ttl_secs,
            resolved.expires_at,
        );
        let secret_sha256 = sha256_hex(req.delivery_secret.expose().as_bytes());
        let target_host = parsed_url.host_str().unwrap_or("").to_ascii_lowercase();

        // Check if an existing non-expired subscription exists for this composite key.
        let existing = {
            let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_running()?;
            if let Some(sub) = rt.subscriptions.get(&key).cloned() {
                let expired = sub
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .refresh_before
                    <= now;
                if expired {
                    sub.cancel_all();
                    rt.subscriptions.remove(&key);
                    None
                } else {
                    Some(sub)
                }
            } else {
                None
            }
        };

        if let Some(sub) = existing {
            // Idempotent refresh path.
            let (granted_scopes, current_secret) = {
                let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                (st.granted_scopes.clone(), st.secret.clone())
            };
            if self.auth_client.is_some()
                && !scopes_subset(&granted_scopes, &resolved.effective_scopes)
            {
                return Err(EngineError::Forbidden(
                    "caller scopes no longer cover subscription granted scopes".into(),
                ));
            }

            let secret_changed = current_secret.expose() != req.delivery_secret.expose();
            if secret_changed {
                self.ensure_callback_verified(
                    &resolved.principal,
                    &req.delivery_url,
                    &target_host,
                    &sub_id,
                    &req.delivery_secret,
                    &secret_sha256,
                )
                .await?;
            }

            let refresh_outcome = {
                let runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                self.ensure_running()?;
                let still_live = runtime
                    .subscriptions
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &sub));
                if still_live {
                    let mut state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                    if state.removed {
                        None
                    } else {
                        let was_suspended = state.suspended;
                        let last_error = state.last_error;
                        let truncated =
                            !is_ingest && std::mem::take(&mut state.pending_truncated_for_refresh);
                        state.pending_refresh = Some(PendingRefresh {
                            refresh_before,
                            secret: req.delivery_secret.clone(),
                            prev_secret: if secret_changed {
                                Some(state.secret.clone())
                            } else {
                                state.prev_secret.clone()
                            },
                            prev_secret_until: if secret_changed {
                                Some(now.saturating_add(self.quotas.dual_secret_window_secs))
                            } else {
                                state.prev_secret_until
                            },
                            resume_suspended: was_suspended,
                            resume_auth_paused: state.auth_paused,
                            captured_truncated: truncated,
                        });
                        Some((
                            was_suspended,
                            last_error,
                            state.safe_cursor.clone(),
                            truncated,
                        ))
                    }
                } else {
                    None
                }
            };

            if let Some((was_suspended, last_error, safe_cursor, truncated)) = refresh_outcome {
                let mut transaction = RefreshGuard {
                    engine: self,
                    sub: Arc::clone(&sub),
                    committed: false,
                };
                self.persist_state().await.map_err(EngineError::Internal)?;
                let resumed = transaction.commit()?;
                if resumed {
                    sub.outbox_notify.notify_one();
                    if matches!(sub.source, SubSource::Upstream { .. }) {
                        self.spawn_upstream_consumer(Arc::clone(&sub));
                    }
                }
                return Ok(SubscribeResponse {
                    id: sub_id,
                    refresh_before,
                    cursor: if is_ingest { None } else { safe_cursor },
                    truncated,
                    delivery_status: Some(DeliveryStatus {
                        active: !was_suspended,
                        last_error,
                    }),
                });
            }
        }

        // New subscription path: enforce quotas before outbound challenge.
        {
            let rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_running()?;
            if rt.subscriptions.len() >= self.quotas.max_subscriptions {
                return Err(EngineError::ResourceExhausted(
                    "global subscription limit reached".into(),
                ));
            }
            let principal_count = rt
                .subscriptions
                .keys()
                .filter(|k| k.principal == resolved.principal)
                .count();
            if principal_count >= self.quotas.max_per_principal {
                return Err(EngineError::ResourceExhausted(
                    "per-principal subscription limit reached".into(),
                ));
            }
        }

        self.ensure_callback_verified(
            &resolved.principal,
            &req.delivery_url,
            &target_host,
            &sub_id,
            &req.delivery_secret,
            &secret_sha256,
        )
        .await?;

        // Bootstrap cursor and optional replay batch for upstream bridge events.
        let (safe_cursor, response_cursor, truncated, replay_events, replay_cursor) = if is_ingest {
            (None, None, false, Vec::new(), None)
        } else {
            let upstream = self
                .upstream
                .as_ref()
                .ok_or_else(|| EngineError::Internal("upstream not configured".into()))?;
            let poll = upstream
                .poll_events(
                    &req.event_name,
                    Some(&normalized_args),
                    &input_schema,
                    req.cursor.as_deref(),
                    req.max_age_ms,
                    Some(self.quotas.max_outbox_per_sub),
                )
                .await
                .map_err(map_upstream_subscribe_error)?;

            if poll.truncated || poll.events.is_empty() {
                let head = poll.cursor.or(req.cursor.clone());
                (head.clone(), head, poll.truncated, Vec::new(), None)
            } else {
                (
                    req.cursor.clone(),
                    req.cursor.clone(),
                    poll.truncated,
                    poll.events,
                    poll.cursor,
                )
            }
        };

        let persisted_arguments = normalized_args.clone();
        let source = if is_ingest {
            let filter_fields = self
                .find_ingest_event(&req.event_name)
                .map(|e| e.filter_fields.clone())
                .unwrap_or_default();
            SubSource::Ingest {
                filter_fields,
                arguments: normalized_args,
            }
        } else {
            SubSource::Upstream {
                event_name: req.event_name.clone(),
                arguments: normalized_args,
            }
        };

        let persisted = PersistedSubscription {
            id: sub_id.clone(),
            key: key.clone(),
            arguments: persisted_arguments,
            auth_ref: resolved.auth_ref,
            granted_scopes: resolved.effective_scopes,
            secret: req.delivery_secret,
            prev_secret: None,
            prev_secret_until: None,
            refresh_before,
            safe_cursor,
            pending_truncated_for_refresh: false,
            suspended: false,
            last_error: None,
        };

        let sub = Arc::new(new_sub_runtime(persisted, source, false));
        if !replay_events.is_empty()
            && !self.enqueue_polled_batch(&sub, replay_events, replay_cursor, None)
        {
            return Err(EngineError::ResourceExhausted(
                "bootstrap replay exceeds outbox capacity".into(),
            ));
        }

        sub.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .registration_pending = true;

        // Re-check quotas under runtime lock before inserting.
        {
            let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_running()?;
            if rt.subscriptions.len() >= self.quotas.max_subscriptions {
                return Err(EngineError::ResourceExhausted(
                    "global subscription limit reached".into(),
                ));
            }
            let principal_count = rt
                .subscriptions
                .keys()
                .filter(|k| k.principal == resolved.principal)
                .count();
            if principal_count >= self.quotas.max_per_principal {
                return Err(EngineError::ResourceExhausted(
                    "per-principal subscription limit reached".into(),
                ));
            }
            rt.subscriptions.insert(key.clone(), Arc::clone(&sub));
        }

        let mut transaction = RegistrationGuard {
            engine: self,
            sub: Arc::clone(&sub),
            committed: false,
        };
        self.persist_state().await.map_err(EngineError::Internal)?;
        transaction.commit()?;

        self.spawn_delivery_worker(Arc::clone(&sub));
        if !is_ingest {
            self.spawn_upstream_consumer(Arc::clone(&sub));
        }

        Ok(SubscribeResponse {
            id: sub_id,
            refresh_before,
            cursor: response_cursor,
            truncated,
            delivery_status: None,
        })
    }

    pub async fn unsubscribe(
        &self,
        caller: &CallerAuth,
        req: UnsubscribeRequest,
    ) -> Result<(), EngineError> {
        if let Some(ref mode) = req.delivery_mode
            && mode != "webhook"
        {
            return Err(EngineError::InvalidParams(
                "delivery.mode must be 'webhook'".into(),
            ));
        }

        let resolved = self.resolve_caller(caller, false).await?;

        // Normalize arguments if we know the event schema so key matches subscribe().
        let normalized_args = match self.resolve_event_for_subscribe(&req.event_name).await {
            Ok(EventKind::Ingest { input_schema })
            | Ok(EventKind::Upstream { input_schema, .. }) => {
                normalize_filter_arguments(&input_schema, &req.arguments)
                    .await
                    .unwrap_or(req.arguments)
            }
            Err(_) => req.arguments,
        };

        let key = SubscriptionKey::new(
            &resolved.principal,
            &req.delivery_url,
            &req.event_name,
            &normalized_args,
        )
        .map_err(EngineError::InvalidParams)?;

        let key_lock = self.key_lock(&key);
        let _guard = key_lock.lock().await;

        let removed = {
            let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_running()?;
            rt.subscriptions.remove(&key)
        };

        let Some(sub) = removed else {
            self.persist_state().await.map_err(EngineError::Internal)?;
            return match self.config.profile {
                Profile::Sep3415 => Err(EngineError::NotFound {
                    kind: "subscription",
                    message: "subscription not found".into(),
                }),
                Profile::Chatgpt => Ok(()),
            };
        };

        {
            let mut st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
            st.removed = true;
            st.outbox.clear();
        }
        sub.cancel_all();

        self.persist_state().await.map_err(EngineError::Internal)?;

        Ok(())
    }

    pub async fn ingest_event(
        &self,
        token_slot: usize,
        raw_body: &[u8],
    ) -> Result<IngestResult, IngestError> {
        if raw_body.len() > MAX_INGEST_BODY_BYTES {
            return Err(IngestError::PayloadTooLarge(format!(
                "ingest body exceeds {} byte limit",
                MAX_INGEST_BODY_BYTES
            )));
        }
        let parsed: RawIngestEvent = serde_json::from_slice(raw_body)
            .map_err(|e| IngestError::BadRequest(format!("invalid JSON body: {e}")))?;

        if !is_valid_event_id(&parsed.event_id) {
            return Err(IngestError::Unprocessable(
                "eventId must match ^[A-Za-z0-9_-]{1,128}$".into(),
            ));
        }

        let Some(ev_cfg) = self.find_ingest_event(&parsed.name) else {
            return Err(IngestError::Unprocessable(format!(
                "unknown ingest event '{}'",
                parsed.name
            )));
        };

        validate_against_schema(&ev_cfg.payload_schema, &parsed.data)
            .await
            .map_err(|e| IngestError::Unprocessable(format!("payload schema violation: {e}")))?;

        let data_json = serde_json::to_string(&parsed.data)
            .map_err(|e| IngestError::BadRequest(format!("cannot serialize data: {e}")))?;
        let timestamp = parsed.timestamp.unwrap_or_else(utc_rfc3339_now);
        let payload_sha256 = sha256_bytes(raw_body);
        let now = unix_now();

        // Check and update dedup table.
        let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        if *self.shutdown_tx.borrow() {
            return Err(IngestError::ServiceUnavailable(
                "daemon is shutting down".into(),
            ));
        }
        let dedup_key = (token_slot, parsed.event_id.clone());

        if let Some(existing) = rt.dedup.get(&dedup_key) {
            if existing
                .inserted_at
                .saturating_add(self.quotas.dedup_retention_secs)
                > now
            {
                if existing.payload_sha256 == payload_sha256 {
                    return Ok(IngestResult {
                        ok: true,
                        event_id: parsed.event_id,
                        deduplicated: true,
                        matched: None,
                        dropped_slow: None,
                    });
                }
                return Err(IngestError::Conflict(
                    "eventId already seen with different payload".into(),
                ));
            }
            rt.dedup.remove(&dedup_key);
        }

        if rt.dedup.len() >= self.quotas.max_dedup_entries {
            let retention = self.quotas.dedup_retention_secs;
            rt.dedup
                .retain(|_, v| v.inserted_at.saturating_add(retention) > now);
            if rt.dedup.len() >= self.quotas.max_dedup_entries {
                return Err(IngestError::ServiceUnavailable(
                    "ingest deduplication table is full".into(),
                ));
            }
        }

        // Collect matching active, non-suspended, non-expired ingest subscriptions.
        let mut matched_subs = Vec::new();
        for sub in rt.subscriptions.values() {
            if sub.key.event_name != parsed.name {
                continue;
            }
            let SubSource::Ingest {
                filter_fields,
                arguments,
            } = &sub.source
            else {
                continue;
            };
            if !matches_ingest_filter(filter_fields, arguments, &parsed.data) {
                continue;
            }
            let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
            if self.sub_accepts_events(&st, None) {
                matched_subs.push(Arc::clone(sub));
            }
        }

        // Pre-check envelope size for all matched subscriptions.
        let envelope_size =
            serialize_event_envelope(&parsed.event_id, &parsed.name, &timestamp, &data_json, None)
                .len();
        if envelope_size > MAX_WEBHOOK_PAYLOAD_BYTES {
            return Err(IngestError::PayloadTooLarge(format!(
                "event envelope exceeds {} byte limit",
                MAX_WEBHOOK_PAYLOAD_BYTES
            )));
        }

        // Attempt to acquire byte leases for every matched subscription that has outbox room.
        // If global outbox byte budget is exhausted, fail the whole request with 503 before recording dedup.
        let mut planned: Vec<(Arc<SubRuntime>, Option<ByteLease>)> =
            Vec::with_capacity(matched_subs.len());
        for sub in matched_subs {
            let is_full = {
                let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                st.outbox.len() >= self.quotas.max_outbox_per_sub
            };
            if is_full {
                planned.push((sub, None));
            } else {
                let lease = self
                    .pools
                    .outbox
                    .try_acquire(envelope_size)
                    .ok_or_else(|| {
                        IngestError::ServiceUnavailable("outbox memory budget exhausted".into())
                    })?;
                planned.push((sub, Some(lease)));
            }
        }

        rt.dedup.insert(
            dedup_key,
            DedupEntry {
                payload_sha256,
                inserted_at: now,
            },
        );

        // Commit items into each subscription's outbox.
        let mut matched = 0usize;
        let mut dropped_slow = 0usize;
        for (sub, lease_opt) in planned {
            matched += 1;
            let Some(lease) = lease_opt else {
                dropped_slow += 1;
                continue;
            };
            let webhook_id = match self.config.profile {
                Profile::Chatgpt => parsed.event_id.clone(),
                Profile::Sep3415 => format!(
                    "msg_{}",
                    random_base64url(18).unwrap_or_else(|_| parsed.event_id.clone())
                ),
            };
            let pushed = {
                let mut st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                if !self.sub_accepts_events(&st, None)
                    || st.outbox.len() >= self.quotas.max_outbox_per_sub
                {
                    false
                } else {
                    st.outbox.push_back(OutboxItem::Event {
                        webhook_id,
                        event_id: parsed.event_id.clone(),
                        name: parsed.name.clone(),
                        timestamp: timestamp.clone(),
                        data_json: data_json.clone(),
                        advance_cursor: None,
                        is_ingest: true,
                        _lease: lease,
                    });
                    true
                }
            };
            if pushed {
                sub.outbox_notify.notify_one();
            } else {
                dropped_slow += 1;
            }
        }

        Ok(IngestResult {
            ok: true,
            event_id: parsed.event_id,
            deduplicated: false,
            matched: Some(matched),
            dropped_slow: Some(dropped_slow),
        })
    }

    pub fn begin_shutdown(&self) {
        let runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        self.shutdown_tx.send_replace(true);
        self.tasks.close();
        for sub in runtime.subscriptions.values() {
            sub.stop_consumer();
            sub.outbox_notify.notify_waiters();
        }
    }

    pub async fn shutdown_until(&self, deadline: tokio::time::Instant) -> Result<(), String> {
        self.begin_shutdown();
        self.shutdown_result
            .get_or_init(|| async {
                if tokio::time::timeout_at(deadline, self.tasks.wait())
                    .await
                    .is_err()
                {
                    self.force_stop.cancel();
                    self.tasks.wait().await;
                }
                {
                    let runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                    for sub in runtime.subscriptions.values() {
                        sub.cancel_all();
                        sub.state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .outbox
                            .clear();
                    }
                    self.store.mark_dirty(runtime.snapshot());
                }
                self.store.shutdown().await
            })
            .await
            .clone()
    }

    pub async fn shutdown(&self) -> Result<(), String> {
        self.shutdown_until(
            tokio::time::Instant::now() + Duration::from_secs(self.quotas.drain_timeout_secs),
        )
        .await
    }

    fn ensure_running(&self) -> Result<(), EngineError> {
        if *self.shutdown_tx.borrow() {
            Err(EngineError::ResourceExhausted(
                "server is shutting down".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn spawn_task(&self, future: impl Future<Output = ()> + Send + 'static) {
        let _runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        if *self.shutdown_tx.borrow() {
            return;
        }
        let force_stop = self.force_stop.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                biased;
                () = force_stop.cancelled() => {}
                () = future => {}
            }
        });
    }

    async fn resolve_caller(
        &self,
        caller: &CallerAuth,
        live: bool,
    ) -> Result<ResolvedCaller, EngineError> {
        match (&self.auth_client, caller) {
            (None, CallerAuth::StaticSlot(slot)) => Ok(ResolvedCaller {
                principal: format!("static:{slot}"),
                auth_ref: None,
                effective_scopes: Vec::new(),
                expires_at: None,
            }),
            (
                Some(client),
                CallerAuth::Delegated {
                    auth_ref,
                    header_scopes,
                },
            ) => {
                let outcome = if live {
                    client.check_live(auth_ref).await
                } else {
                    client.check_cached(auth_ref).await
                };
                match outcome {
                    AuthCheckOutcome::Active(checked) => {
                        let effective = intersect_scopes(header_scopes, &checked.scopes);
                        if effective.is_empty() {
                            return Err(EngineError::Forbidden(
                                "no effective scopes after intersection".into(),
                            ));
                        }
                        Ok(ResolvedCaller {
                            principal: checked.principal,
                            auth_ref: Some(auth_ref.clone()),
                            effective_scopes: effective,
                            expires_at: Some(checked.expires_at),
                        })
                    }
                    AuthCheckOutcome::Inactive => {
                        Err(EngineError::Forbidden("authorization is not active".into()))
                    }
                    AuthCheckOutcome::TransientError(err) => Err(EngineError::Internal(err)),
                }
            }
            (Some(_), CallerAuth::StaticSlot(_)) => Err(EngineError::Internal(
                "delegated auth_context is enabled but caller has no delegation headers".into(),
            )),
            (None, CallerAuth::Delegated { .. }) => Err(EngineError::Internal(
                "delegated caller provided without auth_context".into(),
            )),
        }
    }

    async fn get_upstream_catalog(&self) -> Result<Vec<UpstreamEventDescriptor>, EngineError> {
        let Some(ref upstream) = self.upstream else {
            return Ok(Vec::new());
        };
        let mut cache = self.catalog_cache.lock().await;
        if let Some(ts) = cache.fetched_at
            && ts.elapsed() < CATALOG_CACHE_TTL
        {
            return Ok(cache.upstream_events.clone());
        }

        let allow_not_found = self
            .config
            .upstream
            .as_ref()
            .is_some_and(|u| u.expose_events.is_empty());
        let events = upstream
            .list_events_all_pages(allow_not_found)
            .await
            .map_err(|e| EngineError::Internal(format!("upstream catalog refresh failed: {e}")))?;

        if let Some(ref ingest) = self.config.ingest {
            let ingest_names: HashSet<&str> =
                ingest.events.iter().map(|e| e.name.as_str()).collect();
            for ev in &events {
                if ingest_names.contains(ev.name.as_str()) {
                    return Err(EngineError::Internal(format!(
                        "event name '{}' collides between upstream and ingest",
                        ev.name
                    )));
                }
            }
        }

        cache.upstream_events = events.clone();
        cache.fetched_at = Some(Instant::now());
        Ok(events)
    }

    async fn resolve_event_for_subscribe(&self, name: &str) -> Result<EventKind, EngineError> {
        if let Some(ev) = self.find_ingest_event(name) {
            return Ok(EventKind::Ingest {
                input_schema: ev.input_schema.clone(),
            });
        }
        let upstream_events = self.get_upstream_catalog().await?;
        let Some(ev) = upstream_events.iter().find(|e| e.name == name) else {
            return Err(EngineError::NotFound {
                kind: "event",
                message: format!("event '{name}' not found"),
            });
        };
        let transformed = self.transform_upstream_event(ev);
        let disallow_arguments = self
            .find_expose_event(name)
            .map(|e| e.disallow_arguments.clone())
            .unwrap_or_default();
        let supports_webhook = transformed.delivery.iter().any(|m| m == "webhook");
        let supports_push = transformed.delivery.iter().any(|m| m == "push");
        Ok(EventKind::Upstream {
            input_schema: transformed.input_schema,
            disallow_arguments,
            supports_webhook,
            supports_push,
        })
    }

    fn transform_upstream_event(&self, ev: &UpstreamEventDescriptor) -> CatalogEvent {
        let mut delivery = ev.delivery.clone();
        let mut input_schema = ev.input_schema.clone();
        if let Some(expose) = self.find_expose_event(&ev.name) {
            if !delivery.iter().any(|m| m == "webhook") {
                delivery.push("webhook".into());
            }
            strip_disallowed_arguments(&mut input_schema, &expose.disallow_arguments);
        }
        CatalogEvent {
            name: ev.name.clone(),
            description: ev.description.clone(),
            delivery,
            input_schema,
            payload_schema: ev.payload_schema.clone(),
        }
    }

    fn find_ingest_event(&self, name: &str) -> Option<&IngestEventConfig> {
        self.config
            .ingest
            .as_ref()?
            .events
            .iter()
            .find(|e| e.name == name)
    }

    fn find_expose_event(&self, name: &str) -> Option<&crate::config::ExposeEventConfig> {
        self.config
            .upstream
            .as_ref()?
            .expose_events
            .iter()
            .find(|e| e.name == name)
    }

    fn key_lock(&self, key: &SubscriptionKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut map = self.key_locks.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(existing) = map.get(key).and_then(Weak::upgrade) {
            return existing;
        }
        if map.len() >= KEY_LOCK_PRUNE_THRESHOLD {
            map.retain(|_, w| w.strong_count() > 0);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        map.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    async fn ensure_callback_verified(
        &self,
        principal: &str,
        url: &str,
        target_host: &str,
        sub_id: &str,
        secret: &SecretString,
        secret_sha256: &str,
    ) -> Result<(), EngineError> {
        let now = unix_now();
        let cache_key = (
            principal.to_owned(),
            url.to_owned(),
            secret_sha256.to_owned(),
        );

        let hit = {
            let rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            rt.verified_endpoints
                .get(&cache_key)
                .is_some_and(|ts| ts.saturating_add(self.quotas.verified_retention_secs) > now)
        };
        if hit {
            return Ok(());
        }

        // Per-(principal, target_host) rate limit on verification challenges.
        {
            let mut rl = self.verify_rate.lock().unwrap_or_else(|p| p.into_inner());
            let now_inst = Instant::now();
            if rl.len() >= 256 {
                rl.retain(|_, b| {
                    now_inst.saturating_duration_since(b.window_start) < VERIFY_RATE_WINDOW
                });
            }
            let entry = rl
                .entry((principal.to_owned(), target_host.to_owned()))
                .or_insert(VerifyBucket {
                    window_start: now_inst,
                    count: 0,
                });
            if now_inst.saturating_duration_since(entry.window_start) >= VERIFY_RATE_WINDOW {
                entry.window_start = now_inst;
                entry.count = 0;
            }
            if entry.count >= VERIFY_RATE_LIMIT {
                return Err(EngineError::ResourceExhausted(
                    "callback verification rate limit exceeded".into(),
                ));
            }
            entry.count += 1;
        }

        self.outbound
            .verify_callback(url, sub_id, secret)
            .await
            .map_err(EngineError::CallbackEndpoint)?;

        {
            let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_running()?;
            if rt.verified_endpoints.len() >= self.quotas.max_verified_endpoints
                && !rt.verified_endpoints.contains_key(&cache_key)
            {
                let retention = self.quotas.verified_retention_secs;
                rt.verified_endpoints
                    .retain(|_, ts| ts.saturating_add(retention) > now);
                if rt.verified_endpoints.len() >= self.quotas.max_verified_endpoints
                    && let Some(oldest) = rt
                        .verified_endpoints
                        .iter()
                        .min_by_key(|(_, ts)| **ts)
                        .map(|(k, _)| k.clone())
                {
                    rt.verified_endpoints.remove(&oldest);
                }
            }
            rt.verified_endpoints.insert(cache_key, now);
        }

        Ok(())
    }

    #[cfg(test)]
    fn snapshot_state(&self) -> PersistedState {
        self.runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .snapshot()
    }

    fn mark_state_dirty(&self) {
        let runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        self.store.mark_dirty(runtime.snapshot());
    }

    async fn persist_state(&self) -> Result<(), String> {
        self.mark_state_dirty();
        self.store.flush().await
    }

    fn spawn_delivery_worker(self: &Arc<Self>, sub: Arc<SubRuntime>) {
        let engine = Arc::clone(self);
        self.spawn_task(async move {
            engine.run_delivery_worker(sub).await;
        });
    }

    fn spawn_upstream_consumer(self: &Arc<Self>, sub: Arc<SubRuntime>) {
        let (tx, rx) = watch::channel(false);
        {
            let state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
            if !self.sub_accepts_events(&state, None) {
                return;
            }
            let mut guard = sub
                .consumer_cancel
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(old) = guard.replace(tx) {
                old.send_replace(true);
            }
        }
        let eng = Arc::clone(self);
        self.spawn_task(async move {
            eng.run_upstream_consumer(sub, rx).await;
        });
    }

    async fn run_delivery_worker(self: Arc<Self>, sub: Arc<SubRuntime>) {
        let mut cancel_rx = sub.cancel_tx.subscribe();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            if *cancel_rx.borrow() {
                break;
            }

            let head_snapshot = {
                let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                if st.removed {
                    break;
                }
                if st.suspended || st.auth_paused {
                    None
                } else {
                    st.outbox.front().map(clone_outbox_head)
                }
            };

            let Some(head) = head_snapshot else {
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::select! {
                    () = sub.outbox_notify.notified() => {}
                    _ = cancel_rx.changed() => {}
                    _ = shutdown_rx.changed() => {}
                }
                continue;
            };

            match head {
                HeadAction::Checkpoint { cursor } => {
                    let notify_space = {
                        let mut state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                        state.outbox.pop_front();
                        state.safe_cursor = Some(cursor);
                        state.outbox.len() < self.quotas.max_outbox_per_sub / 2
                    };
                    self.mark_state_dirty();
                    if notify_space {
                        sub.space_notify.notify_one();
                    }
                }
                HeadAction::Gap { cursor } => {
                    if !self
                        .verify_auth_before_delivery(&sub, &mut cancel_rx, &mut shutdown_rx)
                        .await
                    {
                        break;
                    }
                    if self.config.profile == Profile::Sep3415 {
                        let body = json!({ "type": "gap", "cursor": cursor }).to_string();
                        let wid = format!(
                            "msg_{}",
                            random_base64url(18).unwrap_or_else(|_| "gap".into())
                        );
                        let (secret, prev_secret) = active_secrets(&sub);
                        let _permit = tokio::select! {
                            res = self.global_delivery_sem.acquire() => match res {
                                Ok(p) => p,
                                Err(_) => return,
                            },
                            _ = cancel_rx.changed() => return,
                            _ = shutdown_rx.changed() => return,
                        };
                        let _ = self
                            .outbound
                            .post_webhook(
                                &sub.key.url,
                                &sub.id,
                                &wid,
                                body.as_bytes(),
                                &secret,
                                prev_secret.as_ref(),
                            )
                            .await;
                    }
                    let should_notify_space = {
                        let mut st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                        st.outbox.pop_front();
                        st.safe_cursor = Some(cursor);
                        if self.config.profile == Profile::Chatgpt {
                            st.pending_truncated_for_refresh = true;
                        }
                        st.outbox.len() < self.quotas.max_outbox_per_sub / 2
                    };
                    self.mark_state_dirty();
                    if should_notify_space {
                        sub.space_notify.notify_one();
                    }
                }
                HeadAction::Event {
                    webhook_id,
                    event_id,
                    name,
                    timestamp,
                    data_json,
                    advance_cursor,
                    is_ingest,
                } => {
                    let mut attempt: u32 = 0;
                    loop {
                        if *cancel_rx.borrow() {
                            return;
                        }
                        if !self
                            .verify_auth_before_delivery(&sub, &mut cancel_rx, &mut shutdown_rx)
                            .await
                        {
                            return;
                        }

                        let (secret, prev_secret, safe_cursor, is_suspended) = {
                            let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                            let now = unix_now();
                            let prev = match (&st.prev_secret, st.prev_secret_until) {
                                (Some(s), Some(until)) if now <= until => Some(s.clone()),
                                _ => None,
                            };
                            (
                                st.secret.clone(),
                                prev,
                                st.safe_cursor.clone(),
                                st.suspended,
                            )
                        };
                        if is_suspended {
                            break;
                        }

                        let payload_cursor = if is_ingest {
                            None
                        } else {
                            advance_cursor.as_deref().or(safe_cursor.as_deref())
                        };
                        let body = serialize_event_envelope(
                            &event_id,
                            &name,
                            &timestamp,
                            &data_json,
                            payload_cursor,
                        );

                        let _permit = tokio::select! {
                            res = self.global_delivery_sem.acquire() => match res {
                                Ok(p) => p,
                                Err(_) => return,
                            },
                            _ = cancel_rx.changed() => return,
                            _ = shutdown_rx.changed() => return,
                        };
                        let outcome = self
                            .outbound
                            .post_webhook(
                                &sub.key.url,
                                &sub.id,
                                &webhook_id,
                                body.as_bytes(),
                                &secret,
                                prev_secret.as_ref(),
                            )
                            .await;
                        drop(_permit);

                        match outcome {
                            DeliveryOutcome::Success => {
                                let (dirty, notify_space) = {
                                    let mut st =
                                        sub.state.lock().unwrap_or_else(|p| p.into_inner());
                                    st.consecutive_failures = 0;
                                    st.first_failure_at = None;
                                    st.last_error = None;
                                    st.outbox.pop_front();
                                    let mut dirty = false;
                                    if let Some(ref c) = advance_cursor {
                                        st.safe_cursor = Some(c.clone());
                                        dirty = true;
                                    }
                                    (dirty, st.outbox.len() < self.quotas.max_outbox_per_sub / 2)
                                };
                                if dirty {
                                    self.mark_state_dirty();
                                }
                                if notify_space {
                                    sub.space_notify.notify_one();
                                }
                                break;
                            }
                            DeliveryOutcome::PermanentDrop(reason) => {
                                let notify_space = {
                                    let mut st =
                                        sub.state.lock().unwrap_or_else(|p| p.into_inner());
                                    st.last_error = Some(reason);
                                    st.outbox.pop_front();
                                    if let Some(ref c) = advance_cursor {
                                        st.safe_cursor = Some(c.clone());
                                    }
                                    st.outbox.len() < self.quotas.max_outbox_per_sub / 2
                                };
                                self.mark_state_dirty();
                                if notify_space {
                                    sub.space_notify.notify_one();
                                }
                                break;
                            }
                            DeliveryOutcome::Transient(reason) => {
                                let mut became_suspended = false;
                                let mut exhausted_drop = false;
                                let mut notify_space = false;

                                {
                                    let mut st =
                                        sub.state.lock().unwrap_or_else(|p| p.into_inner());
                                    st.consecutive_failures =
                                        st.consecutive_failures.saturating_add(1);
                                    let first =
                                        *st.first_failure_at.get_or_insert_with(Instant::now);
                                    st.last_error = Some(reason);

                                    if st.consecutive_failures >= self.quotas.suspend_failure_count
                                        && first.elapsed()
                                            >= Duration::from_secs(
                                                self.quotas.suspend_min_duration_secs,
                                            )
                                    {
                                        st.suspended = true;
                                        became_suspended = true;
                                        if matches!(sub.source, SubSource::Upstream { .. }) {
                                            sub.stop_consumer_locked(&mut st);
                                            st.outbox.clear();
                                            st.ingest_cursor = st.safe_cursor.clone();
                                        }
                                    } else if attempt >= MAX_TRANSIENT_RETRIES {
                                        st.outbox.pop_front();
                                        if let Some(ref c) = advance_cursor {
                                            st.safe_cursor = Some(c.clone());
                                        }
                                        exhausted_drop = true;
                                        notify_space =
                                            st.outbox.len() < self.quotas.max_outbox_per_sub / 2;
                                    }
                                }

                                if became_suspended {
                                    self.mark_state_dirty();
                                    break;
                                }
                                if exhausted_drop {
                                    self.mark_state_dirty();
                                    if notify_space {
                                        sub.space_notify.notify_one();
                                    }
                                    break;
                                }
                                if *shutdown_rx.borrow() {
                                    return;
                                }

                                let delay = backoff_with_jitter(self.quotas.retry_base_ms, attempt);
                                attempt += 1;
                                tokio::select! {
                                    () = tokio::time::sleep(delay) => {}
                                    _ = cancel_rx.changed() => return,
                                    _ = shutdown_rx.changed() => return,
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Returns `true` if delivery may proceed, `false` if the subscription was cancelled/revoked.
    async fn verify_auth_before_delivery(
        self: &Arc<Self>,
        sub: &Arc<SubRuntime>,
        cancel_rx: &mut watch::Receiver<bool>,
        shutdown_rx: &mut watch::Receiver<bool>,
    ) -> bool {
        let Some(ref client) = self.auth_client else {
            return true;
        };
        let (auth_ref, granted_scopes) = {
            let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
            (st.auth_ref.clone(), st.granted_scopes.clone())
        };
        let Some(aref) = auth_ref else {
            self.revoke_subscription(&sub.key, true).await;
            return false;
        };

        loop {
            if *cancel_rx.borrow() {
                return false;
            }
            match client.check_cached(&aref).await {
                AuthCheckOutcome::Active(checked) => {
                    if scopes_subset(&granted_scopes, &checked.scopes) {
                        return true;
                    }
                    self.revoke_subscription(&sub.key, true).await;
                    return false;
                }
                AuthCheckOutcome::Inactive => {
                    self.revoke_subscription(&sub.key, true).await;
                    return false;
                }
                AuthCheckOutcome::TransientError(_) => {
                    if *shutdown_rx.borrow() {
                        return false;
                    }
                    let wait = client.reverify_interval().min(Duration::from_secs(2));
                    tokio::select! {
                        () = tokio::time::sleep(wait) => {}
                        _ = cancel_rx.changed() => return false,
                        _ = shutdown_rx.changed() => return false,
                    }
                }
            }
        }
    }

    async fn run_upstream_consumer(
        self: Arc<Self>,
        sub: Arc<SubRuntime>,
        mut consumer_cancel: watch::Receiver<bool>,
    ) {
        let Some(ref upstream) = self.upstream else {
            return;
        };
        let SubSource::Upstream {
            ref event_name,
            ref arguments,
        } = sub.source
        else {
            return;
        };
        let mut cancel_rx = sub.cancel_tx.subscribe();
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut backpressure_paused = false;

        loop {
            if *cancel_rx.borrow() || *consumer_cancel.borrow() || *shutdown_rx.borrow() {
                return;
            }

            // Backpressure pause with half-water hysteresis when outbox or byte pool saturates.
            let need_wait = {
                let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                let len = st.outbox.len();
                let pool_used = self.pools.outbox.used();
                let pool_limit = self.pools.outbox.limit();
                if st.suspended || st.removed {
                    true
                } else {
                    if len >= self.quotas.max_outbox_per_sub || pool_used >= pool_limit {
                        backpressure_paused = true;
                    }
                    if backpressure_paused {
                        if len < self.quotas.max_outbox_per_sub / 2 && pool_used < pool_limit {
                            backpressure_paused = false;
                            false
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                }
            };
            if need_wait {
                tokio::select! {
                    () = sub.space_notify.notified() => {}
                    () = tokio::time::sleep(Duration::from_millis(200)) => {}
                    _ = cancel_rx.changed() => return,
                    _ = consumer_cancel.changed() => return,
                    _ = shutdown_rx.changed() => return,
                }
                continue;
            }

            let resolved_event = tokio::select! {
                result = self.resolve_event_for_subscribe(event_name) => result,
                _ = cancel_rx.changed() => return,
                _ = consumer_cancel.changed() => return,
                _ = shutdown_rx.changed() => return,
            };
            let (supports_push, input_schema) = match resolved_event {
                Ok(EventKind::Upstream {
                    supports_push,
                    input_schema,
                    ..
                }) => (supports_push, input_schema),
                _ => {
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(300)) => {}
                        _ = cancel_rx.changed() => return,
                        _ = consumer_cancel.changed() => return,
                        _ = shutdown_rx.changed() => return,
                    }
                    continue;
                }
            };

            let mut use_poll = true;
            if supports_push
                && let Ok(_stream_permit) = self.upstream_stream_sem.clone().try_acquire_owned()
            {
                let cursor = {
                    let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                    st.ingest_cursor.clone()
                };
                let opening_stream = upstream.open_event_stream(
                    event_name,
                    Some(arguments),
                    &input_schema,
                    cursor.as_deref(),
                    None,
                    None,
                );
                let opened_stream = tokio::select! {
                    result = opening_stream => result,
                    _ = cancel_rx.changed() => return,
                    _ = consumer_cancel.changed() => return,
                    _ = shutdown_rx.changed() => return,
                };
                match opened_stream {
                    Ok(mut stream) => {
                        use_poll = false;
                        loop {
                            let next = tokio::select! {
                                frame = stream.next_frame() => frame,
                                _ = cancel_rx.changed() => return,
                                _ = consumer_cancel.changed() => return,
                                _ = shutdown_rx.changed() => return,
                            };
                            match next {
                                Ok(Some(UpstreamStreamFrame::Active {
                                    cursor, truncated, ..
                                })) => {
                                    if truncated {
                                        if let Some(c) = cursor
                                            && !self.enqueue_gap(&sub, c, Some(&consumer_cancel))
                                        {
                                            backpressure_paused = true;
                                            break;
                                        }
                                    } else if let Some(c) = cursor
                                        && !self.advance_idle_cursor(
                                            &sub,
                                            c,
                                            Some(&consumer_cancel),
                                        )
                                    {
                                        backpressure_paused = true;
                                        break;
                                    }
                                }
                                Ok(Some(UpstreamStreamFrame::Heartbeat { cursor })) => {
                                    if let Some(c) = cursor
                                        && !self.advance_idle_cursor(
                                            &sub,
                                            c,
                                            Some(&consumer_cancel),
                                        )
                                    {
                                        backpressure_paused = true;
                                        break;
                                    }
                                }
                                Ok(Some(UpstreamStreamFrame::Event {
                                    event_id,
                                    name,
                                    timestamp,
                                    data,
                                    cursor,
                                })) => {
                                    let ev = UpstreamPolledEvent {
                                        event_id,
                                        name,
                                        timestamp,
                                        data,
                                    };
                                    if !self.enqueue_single_upstream_event(
                                        &sub,
                                        ev,
                                        cursor,
                                        Some(&consumer_cancel),
                                    ) {
                                        backpressure_paused = true;
                                        break;
                                    }
                                }
                                Ok(Some(UpstreamStreamFrame::Error { .. }))
                                | Ok(Some(UpstreamStreamFrame::Terminated { .. }))
                                | Ok(None)
                                | Err(_) => {
                                    break;
                                }
                            }
                            if sub
                                .state
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .outbox
                                .len()
                                >= self.quotas.max_outbox_per_sub
                            {
                                backpressure_paused = true;
                                break;
                            }
                        }
                        if !backpressure_paused {
                            tokio::select! {
                                () = tokio::time::sleep(Duration::from_millis(200)) => {}
                                _ = cancel_rx.changed() => return,
                                _ = consumer_cancel.changed() => return,
                                _ = shutdown_rx.changed() => return,
                            }
                        }
                    }
                    Err(UpstreamError::JsonRpc {
                        code: -32025 | -32026,
                        ..
                    }) => {
                        // Fall back to independent events/poll loop.
                        use_poll = true;
                    }
                    Err(_) => {
                        use_poll = false;
                        tokio::select! {
                            () = tokio::time::sleep(Duration::from_millis(300)) => {}
                            _ = cancel_rx.changed() => return,
                            _ = consumer_cancel.changed() => return,
                            _ = shutdown_rx.changed() => return,
                        }
                    }
                }
            }

            if use_poll {
                let cursor = {
                    let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                    st.ingest_cursor.clone()
                };
                let max_events = {
                    let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                    self.quotas
                        .max_outbox_per_sub
                        .saturating_sub(st.outbox.len())
                        .max(1)
                };
                let poll_fut = upstream.poll_events(
                    event_name,
                    Some(arguments),
                    &input_schema,
                    cursor.as_deref(),
                    None,
                    Some(max_events),
                );
                let poll_res = tokio::select! {
                    r = poll_fut => r,
                    _ = cancel_rx.changed() => return,
                    _ = consumer_cancel.changed() => return,
                    _ = shutdown_rx.changed() => return,
                };
                match poll_res {
                    Ok(resp) => {
                        if resp.truncated {
                            if let Some(c) = resp.cursor
                                && !self.enqueue_gap(&sub, c, Some(&consumer_cancel))
                            {
                                backpressure_paused = true;
                            }
                        } else if resp.events.is_empty() {
                            if let Some(c) = resp.cursor
                                && !self.advance_idle_cursor(&sub, c, Some(&consumer_cancel))
                            {
                                backpressure_paused = true;
                            }
                        } else if !self.enqueue_polled_batch(
                            &sub,
                            resp.events,
                            resp.cursor,
                            Some(&consumer_cancel),
                        ) {
                            backpressure_paused = true;
                        }

                        if !backpressure_paused && !resp.has_more {
                            let sleep_ms = resp.next_poll_ms.clamp(20, 60_000);
                            tokio::select! {
                                () = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
                                _ = cancel_rx.changed() => return,
                                _ = consumer_cancel.changed() => return,
                                _ = shutdown_rx.changed() => return,
                            }
                        }
                    }
                    Err(_) => {
                        tokio::select! {
                            () = tokio::time::sleep(Duration::from_millis(300)) => {}
                            _ = cancel_rx.changed() => return,
                            _ = consumer_cancel.changed() => return,
                            _ = shutdown_rx.changed() => return,
                        }
                    }
                }
            }
            if backpressure_paused {
                tokio::select! {
                    () = sub.space_notify.notified() => {}
                    () = tokio::time::sleep(Duration::from_millis(200)) => {}
                    _ = cancel_rx.changed() => return,
                    _ = consumer_cancel.changed() => return,
                    _ = shutdown_rx.changed() => return,
                }
            }
        }
    }

    fn sub_accepts_events(
        &self,
        state: &SubState,
        consumer_cancel: Option<&watch::Receiver<bool>>,
    ) -> bool {
        !*self.shutdown_tx.borrow()
            && !consumer_cancel.is_some_and(|cancel| *cancel.borrow())
            && !state.removed
            && !state.registration_pending
            && !state.suspended
            && !state.auth_paused
            && state.refresh_before > unix_now()
    }

    fn advance_idle_cursor(
        &self,
        sub: &SubRuntime,
        cursor: String,
        consumer_cancel: Option<&watch::Receiver<bool>>,
    ) -> bool {
        let runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        let mut state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
        if !self.sub_accepts_events(&state, consumer_cancel) {
            return false;
        }
        if state.ingest_cursor.as_deref() == Some(cursor.as_str()) {
            return true;
        }
        let dirty = state.outbox.is_empty();
        if dirty {
            state.safe_cursor = Some(cursor.clone());
        } else {
            if state.outbox.len() >= self.quotas.max_outbox_per_sub {
                return false;
            }
            let Some(lease) = self.pools.outbox.try_acquire(cursor.len()) else {
                return false;
            };
            state.outbox.push_back(OutboxItem::Checkpoint {
                cursor: cursor.clone(),
                _lease: lease,
            });
        }
        state.ingest_cursor = Some(cursor);
        drop(state);
        drop(runtime);
        if dirty {
            self.mark_state_dirty();
        } else {
            sub.outbox_notify.notify_one();
        }
        true
    }

    fn enqueue_gap(
        &self,
        sub: &SubRuntime,
        cursor: String,
        consumer_cancel: Option<&watch::Receiver<bool>>,
    ) -> bool {
        let _runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        let mut state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
        if !self.sub_accepts_events(&state, consumer_cancel)
            || state.outbox.len() >= self.quotas.max_outbox_per_sub
        {
            return false;
        }
        let body_len = json!({ "type": "gap", "cursor": cursor }).to_string().len();
        if self.config.profile == Profile::Sep3415 && body_len > MAX_WEBHOOK_PAYLOAD_BYTES {
            return false;
        }
        let Some(lease) = self.pools.outbox.try_acquire(body_len) else {
            return false;
        };
        state.ingest_cursor = Some(cursor.clone());
        state.outbox.push_back(OutboxItem::Gap {
            cursor,
            _lease: lease,
        });
        sub.outbox_notify.notify_one();
        true
    }

    fn enqueue_single_upstream_event(
        &self,
        sub: &SubRuntime,
        ev: UpstreamPolledEvent,
        cursor: Option<String>,
        consumer_cancel: Option<&watch::Receiver<bool>>,
    ) -> bool {
        self.enqueue_polled_batch(sub, vec![ev], cursor, consumer_cancel)
    }

    fn enqueue_polled_batch(
        &self,
        sub: &SubRuntime,
        events: Vec<UpstreamPolledEvent>,
        batch_cursor: Option<String>,
        consumer_cancel: Option<&watch::Receiver<bool>>,
    ) -> bool {
        if events.is_empty() {
            return batch_cursor
                .is_none_or(|cursor| self.advance_idle_cursor(sub, cursor, consumer_cancel));
        }

        let _runtime = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        let mut state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
        if !self.sub_accepts_events(&state, consumer_cancel) {
            return false;
        }

        // Any earlier queued cursor can become safe before this batch is delivered.
        let cursor_bytes = state
            .safe_cursor
            .as_deref()
            .into_iter()
            .chain(state.ingest_cursor.as_deref())
            .chain(batch_cursor.as_deref())
            .chain(state.outbox.iter().filter_map(outbox_cursor))
            .map(|cursor| serde_json::to_string(cursor).expect("JSON string").len())
            .fold(4, usize::max);

        let total = events.len();
        let mut prepared = Vec::with_capacity(total);
        let mut skipped_tail_cursor = None;

        for (idx, event) in events.into_iter().enumerate() {
            let advance_cursor = (idx + 1 == total).then(|| batch_cursor.clone()).flatten();
            if self.config.profile == Profile::Chatgpt && !is_valid_event_id(&event.event_id) {
                skipped_tail_cursor = advance_cursor;
                continue;
            }

            let Ok(data_json) = serde_json::to_string(&event.data) else {
                skipped_tail_cursor = advance_cursor;
                continue;
            };
            let envelope_bytes = serialize_event_envelope(
                &event.event_id,
                &event.name,
                &event.timestamp,
                &data_json,
                None,
            )
            .len()
                - 4
                + cursor_bytes;
            if envelope_bytes > MAX_WEBHOOK_PAYLOAD_BYTES {
                skipped_tail_cursor = advance_cursor;
                continue;
            }
            let Some(lease) = self.pools.outbox.try_acquire(envelope_bytes) else {
                return false;
            };
            let webhook_id = match self.config.profile {
                Profile::Chatgpt => event.event_id.clone(),
                Profile::Sep3415 => format!(
                    "msg_{}",
                    random_base64url(18).unwrap_or_else(|_| event.event_id.clone())
                ),
            };
            prepared.push(OutboxItem::Event {
                webhook_id,
                event_id: event.event_id,
                name: event.name,
                timestamp: event.timestamp,
                data_json,
                advance_cursor,
                is_ingest: false,
                _lease: lease,
            });
        }

        if let Some(cursor) = skipped_tail_cursor {
            let Some(lease) = self.pools.outbox.try_acquire(cursor.len()) else {
                return false;
            };
            prepared.push(OutboxItem::Checkpoint {
                cursor,
                _lease: lease,
            });
        }
        if prepared.len()
            > self
                .quotas
                .max_outbox_per_sub
                .saturating_sub(state.outbox.len())
        {
            return false;
        }
        if let Some(cursor) = batch_cursor {
            state.ingest_cursor = Some(cursor);
        }
        state.outbox.extend(prepared);
        sub.outbox_notify.notify_one();
        true
    }

    async fn revoke_subscription(self: &Arc<Self>, key: &SubscriptionKey, send_terminated: bool) {
        let removed = {
            let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
            rt.subscriptions.remove(key)
        };
        let Some(sub) = removed else {
            return;
        };

        let (secret, prev_secret) = {
            let mut st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
            st.removed = true;
            st.outbox.clear();
            let now = unix_now();
            let prev = match (&st.prev_secret, st.prev_secret_until) {
                (Some(s), Some(until)) if now <= until => Some(s.clone()),
                _ => None,
            };
            (st.secret.clone(), prev)
        };
        sub.cancel_all();
        self.mark_state_dirty();

        if send_terminated && self.config.profile == Profile::Sep3415 {
            let outbound = self.outbound.clone();
            let url = sub.key.url.clone();
            let sub_id = sub.id.clone();
            self.spawn_task(async move {
                let wid = format!(
                    "msg_{}",
                    random_base64url(18).unwrap_or_else(|_| "terminated".into())
                );
                let body = r#"{"type":"terminated","reason":"authorization_revoked"}"#;
                let _ = outbound
                    .post_webhook(
                        &url,
                        &sub_id,
                        &wid,
                        body.as_bytes(),
                        &secret,
                        prev_secret.as_ref(),
                    )
                    .await;
            });
        }
    }

    async fn run_startup_auth_recovery(self: Arc<Self>, mut pending_refs: HashSet<String>) {
        let Some(ref client) = self.auth_client else {
            return;
        };
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut attempt: u32 = 0;

        while !pending_refs.is_empty() {
            let delay = Duration::from_secs(1u64 << attempt.min(5));
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = shutdown_rx.changed() => return,
            }
            attempt = attempt.saturating_add(1);

            let refs: Vec<String> = pending_refs.iter().cloned().collect();
            for aref in refs {
                match client.check_live(&aref).await {
                    AuthCheckOutcome::Active(checked) => {
                        pending_refs.remove(&aref);
                        let subs: Vec<Arc<SubRuntime>> = {
                            let rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                            rt.subscriptions
                                .values()
                                .filter(|s| {
                                    s.state
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .auth_ref
                                        .as_deref()
                                        == Some(aref.as_str())
                                })
                                .cloned()
                                .collect()
                        };
                        for sub in subs {
                            let (ok_scopes, resumed, suspended) = {
                                let mut state = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                                let ok = scopes_subset(&state.granted_scopes, &checked.scopes);
                                let resumed = ok && state.auth_paused;
                                if resumed {
                                    state.auth_paused = false;
                                }
                                (ok, resumed, state.suspended)
                            };
                            if ok_scopes {
                                if resumed {
                                    sub.outbox_notify.notify_one();
                                    if !suspended
                                        && matches!(sub.source, SubSource::Upstream { .. })
                                    {
                                        self.spawn_upstream_consumer(Arc::clone(&sub));
                                    }
                                }
                            } else {
                                self.revoke_subscription(&sub.key, true).await;
                            }
                        }
                    }
                    AuthCheckOutcome::Inactive => {
                        pending_refs.remove(&aref);
                        let keys: Vec<SubscriptionKey> = {
                            let rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                            rt.subscriptions
                                .values()
                                .filter(|s| {
                                    s.state
                                        .lock()
                                        .unwrap_or_else(|p| p.into_inner())
                                        .auth_ref
                                        .as_deref()
                                        == Some(aref.as_str())
                                })
                                .map(|s| s.key.clone())
                                .collect()
                        };
                        for key in keys {
                            self.revoke_subscription(&key, true).await;
                        }
                    }
                    AuthCheckOutcome::TransientError(_) => {}
                }
            }
        }
    }

    async fn run_periodic_maintenance(self: Arc<Self>) {
        let interval = self
            .config
            .auth_context
            .as_ref()
            .map(|ac| Duration::from_secs(ac.reverify_secs))
            .unwrap_or(Duration::from_secs(5));
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                _ = shutdown_rx.changed() => return,
            }

            let now = unix_now();
            let mut expired_subs = Vec::new();
            let mut dirty = false;

            {
                let mut rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                let keys_to_remove: Vec<SubscriptionKey> = rt
                    .subscriptions
                    .iter()
                    .filter(|(_, sub)| {
                        sub.state
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .refresh_before
                            <= now
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in keys_to_remove {
                    if let Some(sub) = rt.subscriptions.remove(&k) {
                        expired_subs.push(sub);
                        dirty = true;
                    }
                }

                let ve_before = rt.verified_endpoints.len();
                let ve_ret = self.quotas.verified_retention_secs;
                rt.verified_endpoints
                    .retain(|_, ts| ts.saturating_add(ve_ret) > now);
                if rt.verified_endpoints.len() != ve_before {
                    dirty = true;
                }

                let dd_ret = self.quotas.dedup_retention_secs;
                rt.dedup
                    .retain(|_, v| v.inserted_at.saturating_add(dd_ret) > now);
            }

            {
                let now_inst = Instant::now();
                let mut rl = self.verify_rate.lock().unwrap_or_else(|p| p.into_inner());
                rl.retain(|_, b| {
                    now_inst.saturating_duration_since(b.window_start) < VERIFY_RATE_WINDOW
                });
            }

            for sub in expired_subs {
                {
                    let mut st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                    st.removed = true;
                    st.outbox.clear();
                }
                sub.cancel_all();
            }
            if dirty {
                self.mark_state_dirty();
            }

            if let Some(ref client) = self.auth_client {
                let ref_groups: HashMap<String, Vec<Arc<SubRuntime>>> = {
                    let rt = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
                    let mut map: HashMap<String, Vec<Arc<SubRuntime>>> = HashMap::new();
                    for sub in rt.subscriptions.values() {
                        let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(ref aref) = st.auth_ref {
                            map.entry(aref.clone()).or_default().push(Arc::clone(sub));
                        }
                    }
                    map
                };

                for (aref, subs) in ref_groups {
                    match client.check_cached(&aref).await {
                        AuthCheckOutcome::Active(checked) => {
                            for sub in subs {
                                let ok = {
                                    let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
                                    scopes_subset(&st.granted_scopes, &checked.scopes)
                                };
                                if !ok {
                                    self.revoke_subscription(&sub.key, true).await;
                                }
                            }
                        }
                        AuthCheckOutcome::Inactive => {
                            for sub in subs {
                                self.revoke_subscription(&sub.key, true).await;
                            }
                        }
                        AuthCheckOutcome::TransientError(_) => {}
                    }
                }
            }
        }
    }
}

enum HeadAction {
    Event {
        webhook_id: String,
        event_id: String,
        name: String,
        timestamp: String,
        data_json: String,
        advance_cursor: Option<String>,
        is_ingest: bool,
    },
    Gap {
        cursor: String,
    },
    Checkpoint {
        cursor: String,
    },
}

fn clone_outbox_head(item: &OutboxItem) -> HeadAction {
    match item {
        OutboxItem::Event {
            webhook_id,
            event_id,
            name,
            timestamp,
            data_json,
            advance_cursor,
            is_ingest,
            ..
        } => HeadAction::Event {
            webhook_id: webhook_id.clone(),
            event_id: event_id.clone(),
            name: name.clone(),
            timestamp: timestamp.clone(),
            data_json: data_json.clone(),
            advance_cursor: advance_cursor.clone(),
            is_ingest: *is_ingest,
        },
        OutboxItem::Gap { cursor, .. } => HeadAction::Gap {
            cursor: cursor.clone(),
        },
        OutboxItem::Checkpoint { cursor, .. } => HeadAction::Checkpoint {
            cursor: cursor.clone(),
        },
    }
}

fn active_secrets(sub: &SubRuntime) -> (SecretString, Option<SecretString>) {
    let st = sub.state.lock().unwrap_or_else(|p| p.into_inner());
    let now = unix_now();
    let prev = match (&st.prev_secret, st.prev_secret_until) {
        (Some(s), Some(until)) if now <= until => Some(s.clone()),
        _ => None,
    };
    (st.secret.clone(), prev)
}

fn outbox_cursor(item: &OutboxItem) -> Option<&str> {
    match item {
        OutboxItem::Event { advance_cursor, .. } => advance_cursor.as_deref(),
        OutboxItem::Gap { cursor, .. } | OutboxItem::Checkpoint { cursor, .. } => Some(cursor),
    }
}

fn build_sub_source(
    config: &Config,
    key: &SubscriptionKey,
    arguments: &Map<String, Value>,
) -> Option<SubSource> {
    if let Some(ref ingest) = config.ingest
        && let Some(ev) = ingest.events.iter().find(|e| e.name == key.event_name)
    {
        return Some(SubSource::Ingest {
            filter_fields: ev.filter_fields.clone(),
            arguments: arguments.clone(),
        });
    }
    if config.upstream.is_some() {
        return Some(SubSource::Upstream {
            event_name: key.event_name.clone(),
            arguments: arguments.clone(),
        });
    }
    None
}

fn new_sub_runtime(sub: PersistedSubscription, source: SubSource, auth_paused: bool) -> SubRuntime {
    let (cancel_tx, _) = watch::channel(false);
    SubRuntime {
        id: sub.id,
        key: sub.key,
        source,
        state: Mutex::new(SubState {
            auth_ref: sub.auth_ref,
            granted_scopes: sub.granted_scopes,
            secret: sub.secret,
            prev_secret: sub.prev_secret,
            prev_secret_until: sub.prev_secret_until,
            refresh_before: sub.refresh_before,
            ingest_cursor: sub.safe_cursor.clone(),
            safe_cursor: sub.safe_cursor,
            pending_truncated_for_refresh: sub.pending_truncated_for_refresh,
            suspended: sub.suspended,
            last_error: sub.last_error,
            consecutive_failures: 0,
            first_failure_at: None,
            auth_paused,
            removed: false,
            registration_pending: false,
            pending_refresh: None,
            outbox: VecDeque::new(),
        }),
        outbox_notify: Notify::new(),
        space_notify: Notify::new(),
        cancel_tx,
        consumer_cancel: Mutex::new(None),
    }
}

fn strip_disallowed_arguments(schema: &mut Value, disallow: &[String]) {
    if disallow.is_empty() {
        return;
    }
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    if let Some(props) = obj.get_mut("properties").and_then(Value::as_object_mut) {
        for name in disallow {
            props.remove(name);
        }
    }
    if let Some(req) = obj.get_mut("required").and_then(Value::as_array_mut) {
        req.retain(|v| !v.as_str().is_some_and(|s| disallow.iter().any(|d| d == s)));
    }
}

fn matches_ingest_filter(
    filter_fields: &[String],
    arguments: &Map<String, Value>,
    event_data: &Value,
) -> bool {
    if filter_fields.is_empty() || arguments.is_empty() {
        return true;
    }
    let Some(data_obj) = event_data.as_object() else {
        return false;
    };
    for field in filter_fields {
        let Some(expected) = arguments.get(field) else {
            continue;
        };
        if expected.is_null() {
            continue;
        }
        let Some(actual) = data_obj.get(field) else {
            return false;
        };
        if !scalar_eq(expected, actual) {
            return false;
        }
    }
    true
}

fn serialize_event_envelope(
    event_id: &str,
    name: &str,
    timestamp: &str,
    data_json: &str,
    cursor: Option<&str>,
) -> String {
    let id_json = serde_json::to_string(event_id).unwrap_or_else(|_| "\"\"".into());
    let name_json = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".into());
    let ts_json = serde_json::to_string(timestamp).unwrap_or_else(|_| "\"\"".into());
    let cursor_json = match cursor {
        Some(c) => serde_json::to_string(c).unwrap_or_else(|_| "null".into()),
        None => "null".into(),
    };
    format!(
        r#"{{"type":"event","eventId":{id_json},"name":{name_json},"timestamp":{ts_json},"data":{data_json},"cursor":{cursor_json}}}"#
    )
}

fn backoff_with_jitter(base_ms: u64, attempt: u32) -> Duration {
    let shift = attempt.min(5);
    let base = base_ms.saturating_mul(1u64 << shift);
    let jitter_pct = random_bytes(1).map(|b| (b[0] as u64) % 26).unwrap_or(0);
    let total = base.saturating_add(base.saturating_mul(jitter_pct) / 100);
    Duration::from_millis(total)
}

fn map_upstream_subscribe_error(err: UpstreamError) -> EngineError {
    match err {
        UpstreamError::JsonRpc {
            code: -32602,
            message,
            ..
        } => EngineError::InvalidParams(message),
        UpstreamError::JsonRpc {
            code: -32023,
            message,
            ..
        } => EngineError::NotFound {
            kind: "event",
            message,
        },
        UpstreamError::JsonRpc {
            code: -32026,
            message,
            ..
        } => EngineError::Unsupported(message),
        other => EngineError::Internal(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthContextConfig, ExposeEventConfig, IngestConfig, UpstreamConfig};
    use crate::outbound::SafeHttpsConnector;
    use crate::schema::build_filter_input_schema;
    use crate::types::sign_webhook_v1;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use bytes::Bytes;
    use http::{HeaderMap, Request, Response};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig};
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_rustls::TlsAcceptor;
    use url::Url;

    fn test_secret(byte: u8) -> SecretString {
        SecretString::new(format!("whsec_{}", BASE64_STD.encode([byte; 32])))
    }

    #[derive(Clone, Debug)]
    struct CapturedWebhook {
        headers: HeaderMap,
        body: Bytes,
    }

    struct MockTlsCallback {
        url: String,
        roots: RootCertStore,
        captured: Arc<tokio::sync::Mutex<Vec<CapturedWebhook>>>,
        handle: JoinHandle<()>,
    }

    impl Drop for MockTlsCallback {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_tls_callback<F, Fut>(responder: F) -> MockTlsCallback
    where
        F: Fn(HeaderMap, Bytes) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = (StatusCode, Vec<u8>)> + Send + 'static,
    {
        let ck = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let cert_der: CertificateDer<'static> = ck.cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();

        let server_cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key_der)
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let captured_bg = Arc::clone(&captured);
        let responder = Arc::new(responder);

        let handle = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let captured_conn = Arc::clone(&captured_bg);
                let responder_conn = Arc::clone(&responder);
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let io = TokioIo::new(tls);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let captured_req = Arc::clone(&captured_conn);
                        let responder_req = Arc::clone(&responder_conn);
                        async move {
                            let headers = req.headers().clone();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            captured_req.lock().await.push(CapturedWebhook {
                                headers: headers.clone(),
                                body: body.clone(),
                            });
                            let (status, resp_body) = (responder_req)(headers, body).await;
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .header(http::header::CONTENT_TYPE, "application/json")
                                    .body(Full::new(Bytes::from(resp_body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });

        MockTlsCallback {
            url: format!("https://127.0.0.1:{}/hook", addr.port()),
            roots,
            captured,
            handle,
        }
    }

    fn loopback_outbound(roots: RootCertStore) -> OutboundClient {
        let resolver: crate::outbound::DnsResolver = Arc::new(|_host, port| {
            Box::pin(async move { Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]) })
        });
        let connector = SafeHttpsConnector::with_roots_and_resolver(roots, true, resolver).unwrap();
        OutboundClient::from_connector(connector, true, Duration::from_secs(60))
    }

    async fn spawn_http_mock<F, Fut>(handler: F) -> (Url, JoinHandle<()>)
    where
        F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handler = Arc::new(handler);
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req| {
                        let handler = Arc::clone(&handler);
                        async move { Ok::<_, Infallible>(handler(req).await) }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });
        (Url::parse(&format!("http://{addr}/mcp")).unwrap(), handle)
    }

    fn sample_ingest_event_cfg() -> IngestEventConfig {
        let payload_schema = json!({
            "type": "object",
            "properties": {
                "repo": { "type": "string" },
                "pr": { "type": "integer" }
            },
            "required": ["repo"],
            "additionalProperties": false
        });
        let filter_fields = vec!["repo".into(), "pr".into()];
        let input_schema = build_filter_input_schema(&payload_schema, &filter_fields).unwrap();
        IngestEventConfig {
            name: "ci.build_failed".into(),
            description: "CI build failed.".into(),
            filter_fields,
            payload_schema,
            input_schema,
        }
    }

    fn base_config(
        state_path: std::path::PathBuf,
        profile: Profile,
        upstream: Option<UpstreamConfig>,
        ingest: Option<IngestConfig>,
        auth_context: Option<AuthContextConfig>,
    ) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            resource_path: "/mcp".into(),
            state_path,
            profile,
            inbound_tokens: vec![SecretString::new("inbound_tok_0")],
            allowed_origins: Vec::new(),
            max_ttl_secs: 3600,
            auth_context,
            upstream,
            ingest,
        }
    }

    fn test_quotas() -> QuotaConfig {
        QuotaConfig {
            allow_loopback_callbacks: true,
            retry_base_ms: 5,
            drain_timeout_secs: 2,
            ..QuotaConfig::default()
        }
    }

    async fn wait_for_captured(
        captured: &Arc<tokio::sync::Mutex<Vec<CapturedWebhook>>>,
        min_count: usize,
    ) -> Vec<CapturedWebhook> {
        for _ in 0..100 {
            let guard = captured.lock().await;
            if guard.len() >= min_count {
                return guard.clone();
            }
            drop(guard);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        captured.lock().await.clone()
    }

    #[test]
    fn persisted_arguments_do_not_round_trip_through_the_canonical_key() {
        let dir = tempfile::TempDir::new().unwrap();
        let arguments = json!({"limit": 9_223_372_036_854_775_808u64})
            .as_object()
            .unwrap()
            .clone();
        let key = SubscriptionKey {
            principal: "static:0".into(),
            url: "https://hooks.example.com/callback".into(),
            event_name: "task.exited".into(),
            canonical_arguments: r#"{"limit":9223372036854776000}"#.into(),
        };
        let sub = new_sub_runtime(
            PersistedSubscription {
                id: key.subscription_id(),
                key: key.clone(),
                arguments: arguments.clone(),
                auth_ref: None,
                granted_scopes: Vec::new(),
                secret: test_secret(3),
                prev_secret: None,
                prev_secret_until: None,
                refresh_before: unix_now() + 1800,
                safe_cursor: None,
                pending_truncated_for_refresh: false,
                suspended: false,
                last_error: None,
            },
            SubSource::Upstream {
                event_name: key.event_name.clone(),
                arguments: arguments.clone(),
            },
            false,
        );
        let path = dir.path().join("subs.json");
        let (store, _) = StateStore::open(path.clone()).unwrap();
        store
            .save(&PersistedState {
                version: STATE_VERSION,
                subscriptions: vec![sub.to_persisted()],
                verified_endpoints: Vec::new(),
            })
            .unwrap();
        let (_, saved) = StateStore::open(path.clone()).unwrap();
        let saved = &saved.subscriptions[0];
        assert_eq!(saved.arguments, arguments);
        let cfg = base_config(
            path,
            Profile::Sep3415,
            Some(UpstreamConfig {
                url: Url::parse("http://127.0.0.1:1/mcp").unwrap(),
                bearer_token: None,
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 5,
                expose_events: Vec::new(),
            }),
            None,
            None,
        );
        let Some(SubSource::Upstream {
            arguments: restored,
            ..
        }) = build_sub_source(&cfg, &saved.key, &saved.arguments)
        else {
            panic!("missing source")
        };
        assert_eq!(restored, arguments);
        assert_ne!(
            serde_json::from_str::<Value>(&saved.key.canonical_arguments).unwrap(),
            Value::Object(restored)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_snapshots_preserve_the_latest_runtime_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("subs.json");
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            base_config(
                path.clone(),
                Profile::Sep3415,
                None,
                Some(IngestConfig {
                    tokens: vec![SecretString::new("prod")],
                    events: vec![sample_ingest_event_cfg()],
                }),
                None,
            ),
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            None,
        )
        .await
        .unwrap();
        let mut tasks = Vec::new();
        for worker in 0..8 {
            let engine = Arc::clone(&engine);
            tasks.push(tokio::spawn(async move {
                for step in 0..128 {
                    let key = (format!("p{worker}"), format!("url{step}"), "hash".into());
                    engine
                        .runtime
                        .lock()
                        .unwrap()
                        .verified_endpoints
                        .insert(key.clone(), unix_now());
                    engine.mark_state_dirty();
                    engine
                        .runtime
                        .lock()
                        .unwrap()
                        .verified_endpoints
                        .remove(&key);
                    engine.mark_state_dirty();
                    tokio::task::yield_now().await;
                }
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        engine.store.flush().await.unwrap();
        let persisted: PersistedState =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(persisted.verified_endpoints.is_empty());
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_waits_for_forced_delivery_cancellation_before_final_snapshot() {
        let release_callback = Arc::new(Notify::new());
        let release = Arc::clone(&release_callback);
        let callback = spawn_tls_callback(move |_headers, _body| {
            let release = Arc::clone(&release);
            async move {
                release.notified().await;
                (StatusCode::OK, b"{}".to_vec())
            }
        })
        .await;
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("subs.json");
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            base_config(
                path.clone(),
                Profile::Sep3415,
                None,
                Some(IngestConfig {
                    tokens: vec![SecretString::new("producer")],
                    events: vec![sample_ingest_event_cfg()],
                }),
                None,
            ),
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(callback.roots.clone())),
        )
        .await
        .unwrap();
        let sub = sample_upstream_sub(&callback.url);
        engine
            .runtime
            .lock()
            .unwrap()
            .subscriptions
            .insert(sub.key.clone(), Arc::clone(&sub));
        assert!(engine.enqueue_single_upstream_event(
            &sub,
            sample_polled_event("inflight", json!({})),
            Some("c1".into()),
            None,
        ));
        engine.spawn_delivery_worker(Arc::clone(&sub));
        assert_eq!(wait_for_captured(&callback.captured, 1).await.len(), 1);

        engine.begin_shutdown();
        assert!(!engine.enqueue_gap(&sub, "late".into(), None));
        assert!(matches!(
            engine
                .ingest_event(
                    0,
                    br#"{"eventId":"late","name":"ci.build_failed","data":{"repo":"demo"}}"#
                )
                .await,
            Err(IngestError::ServiceUnavailable(_))
        ));
        tokio::time::timeout(
            Duration::from_secs(2),
            engine.shutdown_until(tokio::time::Instant::now()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(engine.tasks.len(), 0);
        assert_eq!(engine.pools.outbox.used(), 0);
        assert_eq!(sub.state.lock().unwrap().safe_cursor.as_deref(), Some("c0"));
        let (_, persisted) = StateStore::open(path).unwrap();
        assert_eq!(
            persisted.subscriptions[0].safe_cursor.as_deref(),
            Some("c0")
        );
        release_callback.notify_one();
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn verification_finishing_after_shutdown_cannot_register_a_subscription() {
        let release_verification = Arc::new(Notify::new());
        let release = Arc::clone(&release_verification);
        let callback = spawn_tls_callback(move |_headers, body| {
            let release = Arc::clone(&release);
            async move {
                let payload: Value = serde_json::from_slice(&body).unwrap();
                release.notified().await;
                (
                    StatusCode::OK,
                    json!({"challenge": payload["challenge"]})
                        .to_string()
                        .into_bytes(),
                )
            }
        })
        .await;
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("subs.json");
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            base_config(
                path.clone(),
                Profile::Sep3415,
                None,
                Some(IngestConfig {
                    tokens: vec![SecretString::new("producer")],
                    events: vec![sample_ingest_event_cfg()],
                }),
                None,
            ),
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(callback.roots.clone())),
        )
        .await
        .unwrap();
        let subscribing_engine = Arc::clone(&engine);
        let url = callback.url.clone();
        let subscribe = tokio::spawn(async move {
            subscribing_engine
                .subscribe(
                    &CallerAuth::StaticSlot(0),
                    SubscribeRequest {
                        event_name: "ci.build_failed".into(),
                        arguments: Map::new(),
                        delivery_mode: "webhook".into(),
                        delivery_url: url,
                        delivery_secret: test_secret(15),
                        ttl_ms: None,
                        cursor: None,
                        max_age_ms: None,
                    },
                )
                .await
        });
        assert_eq!(wait_for_captured(&callback.captured, 1).await.len(), 1);
        engine
            .shutdown_until(tokio::time::Instant::now())
            .await
            .unwrap();
        release_verification.notify_one();
        assert!(matches!(
            subscribe.await.unwrap(),
            Err(EngineError::ResourceExhausted(_))
        ));
        assert_eq!(engine.active_subscription_count(), 0);
        assert_eq!(engine.tasks.len(), 0);
        let (_, persisted) = StateStore::open(path).unwrap();
        assert!(persisted.subscriptions.is_empty());
        assert!(persisted.verified_endpoints.is_empty());
    }

    fn hold_store_writes(
        store: &StoreHandle,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let save_lock = store.save_lock();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _guard = save_lock.lock().unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        ready_rx.recv().unwrap();
        (release_tx, thread)
    }

    #[tokio::test]
    async fn cancelled_registration_removes_provisional_state_and_retry_starts_delivery() {
        let callback = spawn_tls_callback(|_headers, body| async move {
            let payload: Value = serde_json::from_slice(&body).unwrap();
            (
                StatusCode::OK,
                json!({"challenge": payload["challenge"]})
                    .to_string()
                    .into_bytes(),
            )
        })
        .await;
        let directory = tempfile::TempDir::new().unwrap();
        let path = directory.path().join("subs.json");
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            base_config(
                path.clone(),
                Profile::Sep3415,
                None,
                Some(IngestConfig {
                    tokens: vec![SecretString::new("producer")],
                    events: vec![sample_ingest_event_cfg()],
                }),
                None,
            ),
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(callback.roots.clone())),
        )
        .await
        .unwrap();
        let request = SubscribeRequest {
            event_name: "ci.build_failed".into(),
            arguments: Map::new(),
            delivery_mode: "webhook".into(),
            delivery_url: callback.url.clone(),
            delivery_secret: test_secret(16),
            ttl_ms: None,
            cursor: None,
            max_age_ms: None,
        };
        let (release, writer) = hold_store_writes(&engine.store);
        let mut pending = Box::pin(engine.subscribe(&CallerAuth::StaticSlot(0), request.clone()));
        tokio::select! {
            result = &mut pending => panic!("registration finished before persistence: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let provisional = engine.runtime.lock().unwrap().subscriptions.values()
                        .any(|sub| sub.state.lock().unwrap().registration_pending);
                    if provisional {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }) => result.unwrap(),
        }
        assert_eq!(engine.active_subscription_count(), 1);
        let admitted = engine
            .ingest_event(
                0,
                br#"{"eventId":"before_commit","name":"ci.build_failed","data":{"repo":"demo"}}"#,
            )
            .await
            .unwrap();
        assert_eq!(admitted.matched, Some(0));
        drop(pending);
        assert_eq!(engine.active_subscription_count(), 0);
        release.send(()).unwrap();
        writer.join().unwrap();
        engine.store.flush().await.unwrap();
        let (_, persisted) = StateStore::open(path).unwrap();
        assert!(persisted.subscriptions.is_empty());

        engine
            .subscribe(&CallerAuth::StaticSlot(0), request)
            .await
            .unwrap();
        engine
            .ingest_event(
                0,
                br#"{"eventId":"after_commit","name":"ci.build_failed","data":{"repo":"demo"}}"#,
            )
            .await
            .unwrap();
        let delivered = wait_for_captured(&callback.captured, 2).await;
        assert_eq!(delivered.len(), 2);
        assert_eq!(
            serde_json::from_slice::<Value>(&delivered[1].body).unwrap()["eventId"],
            "after_commit"
        );
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_or_failed_refresh_preserves_independent_runtime_updates() {
        let (url, upstream_task) = spawn_http_mock(|request| async move {
            let bytes = request.into_body().collect().await.unwrap().to_bytes();
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            Response::builder()
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(
                    json!({
                        "jsonrpc": "2.0", "id": request["id"],
                        "result": {"events": [{
                            "name": "task.exited", "delivery": ["poll"],
                            "inputSchema": {"type": "object"},
                            "payloadSchema": {"type": "object"}
                        }]}
                    })
                    .to_string(),
                )))
                .unwrap()
        })
        .await;
        let directory = tempfile::TempDir::new().unwrap();
        for fail_write in [false, true] {
            let path = directory.path().join(if fail_write {
                "failure.json"
            } else {
                "cancel.json"
            });
            let quotas = test_quotas();
            let engine = HookdEngine::new(
                base_config(
                    path.clone(),
                    Profile::Chatgpt,
                    Some(UpstreamConfig {
                        url: url.clone(),
                        bearer_token: None,
                        passthrough_prefixes: Vec::new(),
                        request_timeout_secs: 5,
                        expose_events: vec![ExposeEventConfig {
                            name: "task.exited".into(),
                            disallow_arguments: Vec::new(),
                        }],
                    }),
                    None,
                    None,
                ),
                quotas.clone(),
                MemoryPools::from_quotas(&quotas),
                None,
            )
            .await
            .unwrap();
            let sub = sample_upstream_sub("https://hooks.example.com/refresh");
            let old_expiry = {
                let mut state = sub.state.lock().unwrap();
                state.suspended = true;
                state.auth_paused = true;
                state.consecutive_failures = 7;
                state.pending_truncated_for_refresh = !fail_write;
                state.refresh_before
            };
            engine
                .runtime
                .lock()
                .unwrap()
                .subscriptions
                .insert(sub.key.clone(), Arc::clone(&sub));
            engine.persist_state().await.unwrap();
            let (release, writer) = hold_store_writes(&engine.store);
            let mut pending = Box::pin(engine.subscribe(
                &CallerAuth::StaticSlot(0),
                SubscribeRequest {
                    event_name: "task.exited".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: sub.key.url.clone(),
                    delivery_secret: test_secret(12),
                    ttl_ms: Some(Some(600_000)),
                    cursor: None,
                    max_age_ms: None,
                },
            ));
            tokio::select! {
                result = &mut pending => panic!("refresh finished before persistence: {result:?}"),
                result = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if sub.state.lock().unwrap().pending_refresh.is_some() {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                }) => result.unwrap(),
            }
            {
                let mut state = sub.state.lock().unwrap();
                assert!(state.suspended);
                assert!(state.auth_paused);
                assert_eq!(state.refresh_before, old_expiry);
                assert!(!state.pending_truncated_for_refresh);
                state.auth_paused = false;
                state.pending_truncated_for_refresh = true;
            }
            if fail_write {
                std::fs::remove_file(&path).unwrap();
                std::fs::create_dir(&path).unwrap();
                release.send(()).unwrap();
                writer.join().unwrap();
                assert!(matches!(pending.await, Err(EngineError::Internal(_))));
                std::fs::remove_dir(&path).unwrap();
            } else {
                drop(pending);
                release.send(()).unwrap();
                writer.join().unwrap();
            }
            {
                let state = sub.state.lock().unwrap();
                assert!(state.pending_refresh.is_none());
                assert!(state.suspended);
                assert!(!state.auth_paused);
                assert!(state.pending_truncated_for_refresh);
                assert_eq!(state.consecutive_failures, 7);
                assert_eq!(state.refresh_before, old_expiry);
            }
            engine.persist_state().await.unwrap();
            let (_, persisted) = StateStore::open(path).unwrap();
            assert!(persisted.subscriptions[0].suspended);
            assert!(persisted.subscriptions[0].pending_truncated_for_refresh);
            assert_eq!(persisted.subscriptions[0].refresh_before, old_expiry);
            engine.shutdown().await.unwrap();
        }
        upstream_task.abort();
    }

    #[tokio::test]
    async fn subscribe_verify_cache_dual_secret_rotation_and_profile_unsubscribe() {
        let verify_count = Arc::new(AtomicUsize::new(0));
        let vc = Arc::clone(&verify_count);
        let cb = spawn_tls_callback(move |_headers, body| {
            let vc = Arc::clone(&vc);
            async move {
                let v: Value = serde_json::from_slice(&body).unwrap();
                if v["type"] == "verification" {
                    vc.fetch_add(1, Ordering::SeqCst);
                    let resp = json!({ "challenge": v["challenge"] });
                    (StatusCode::OK, resp.to_string().into_bytes())
                } else {
                    (StatusCode::OK, b"{}".to_vec())
                }
            }
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Sep3415,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("prod_tok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let quotas = test_quotas();
        let pools = MemoryPools::from_quotas(&quotas);
        let engine = HookdEngine::new(
            cfg,
            quotas.clone(),
            pools,
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();

        let caller = CallerAuth::StaticSlot(0);
        let sec1 = test_secret(1);
        let sec2 = test_secret(2);
        let mut args = Map::new();
        args.insert("repo".into(), json!("demo"));

        // First subscribe triggers verification challenge.
        let r1 = engine
            .subscribe(
                &caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args.clone(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: sec1.clone(),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(verify_count.load(Ordering::SeqCst), 1);
        assert!(r1.delivery_status.is_none());

        // Idempotent refresh with same secret uses cache (no new challenge).
        let r2 = engine
            .subscribe(
                &caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args.clone(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: sec1.clone(),
                    ttl_ms: Some(None),
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(verify_count.load(Ordering::SeqCst), 1);
        assert_eq!(r2.id, r1.id);
        assert_eq!(
            r2.delivery_status,
            Some(DeliveryStatus {
                active: true,
                last_error: None
            })
        );

        // Refresh with new secret triggers challenge and enables dual-signature window.
        let _r3 = engine
            .subscribe(
                &caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args.clone(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: sec2.clone(),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(verify_count.load(Ordering::SeqCst), 2);

        // Ingest an event and verify dual signatures (old + new).
        let ingest_body = json!({
            "eventId": "evt_dual_1",
            "name": "ci.build_failed",
            "data": { "repo": "demo", "pr": 1 }
        })
        .to_string();
        let ir = engine
            .ingest_event(0, ingest_body.as_bytes())
            .await
            .unwrap();
        assert_eq!(ir.matched, Some(1));
        assert_eq!(ir.dropped_slow, Some(0));

        // 2 verification requests + 1 event delivery = 3 captured requests.
        let captured = wait_for_captured(&cb.captured, 3).await;
        assert!(captured.len() >= 3);
        let ev_req = &captured[2];
        let wid = ev_req.headers["webhook-id"].to_str().unwrap();
        assert!(wid.starts_with("msg_"));
        let ts: u64 = ev_req.headers["webhook-timestamp"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let sig_hdr = ev_req.headers["webhook-signature"].to_str().unwrap();
        let sig_old = sign_webhook_v1(sec1.expose(), wid, ts, &ev_req.body).unwrap();
        let sig_new = sign_webhook_v1(sec2.expose(), wid, ts, &ev_req.body).unwrap();
        assert_eq!(sig_hdr, format!("{sig_old} {sig_new}"));

        // Unsubscribe removes subscription; second unsubscribe returns NotFound under sep3415.
        engine
            .unsubscribe(
                &caller,
                UnsubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args.clone(),
                    delivery_mode: None,
                    delivery_url: cb.url.clone(),
                },
            )
            .await
            .unwrap();
        let err = engine
            .unsubscribe(
                &caller,
                UnsubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args.clone(),
                    delivery_mode: Some("webhook".into()),
                    delivery_url: cb.url.clone(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            EngineError::NotFound {
                kind: "subscription",
                ..
            }
        ));
        engine.shutdown().await.unwrap();

        // Under chatgpt profile, missing unsubscribe is idempotent Ok(()).
        let cfg_cgpt = base_config(
            dir.path().join("subs_cgpt.json"),
            Profile::Chatgpt,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("prod_tok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let eng_cgpt = HookdEngine::new(
            cfg_cgpt,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();
        eng_cgpt
            .unsubscribe(
                &caller,
                UnsubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args,
                    delivery_mode: None,
                    delivery_url: cb.url.clone(),
                },
            )
            .await
            .unwrap();
        eng_cgpt.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn ingest_dedup_conflict_and_burst_tail_drop() {
        let gate = Arc::new(tokio::sync::Notify::new());
        let gate_cb = Arc::clone(&gate);
        let cb = spawn_tls_callback(move |_headers, body| {
            let gate_cb = Arc::clone(&gate_cb);
            async move {
                let v: Value = serde_json::from_slice(&body).unwrap();
                if v["type"] == "verification" {
                    let resp = json!({ "challenge": v["challenge"] });
                    (StatusCode::OK, resp.to_string().into_bytes())
                } else {
                    // Block first event delivery until test releases gate.
                    gate_cb.notified().await;
                    (StatusCode::OK, b"{}".to_vec())
                }
            }
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Chatgpt,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("prod_tok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            cfg,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();

        let caller = CallerAuth::StaticSlot(0);
        let mut args = Map::new();
        args.insert("repo".into(), json!("demo"));
        engine
            .subscribe(
                &caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: args,
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: test_secret(3),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();

        // Dedup & 409 Conflict check.
        let b1 = json!({
            "eventId": "evt_0",
            "name": "ci.build_failed",
            "data": { "repo": "demo", "pr": 1 }
        })
        .to_string();
        let r1 = engine.ingest_event(0, b1.as_bytes()).await.unwrap();
        assert!(!r1.deduplicated);
        let r1_dup = engine.ingest_event(0, b1.as_bytes()).await.unwrap();
        assert!(r1_dup.deduplicated);

        let b1_diff = json!({
            "eventId": "evt_0",
            "name": "ci.build_failed",
            "data": { "repo": "demo", "pr": 2 }
        })
        .to_string();
        let conflict = engine
            .ingest_event(0, b1_diff.as_bytes())
            .await
            .unwrap_err();
        assert_eq!(conflict.status_code(), StatusCode::CONFLICT);

        // Burst 68 more events (> 64 outbox slots) while delivery is blocked.
        let mut total_dropped = 0usize;
        for i in 1..=68 {
            let body = json!({
                "eventId": format!("evt_{i}"),
                "name": "ci.build_failed",
                "data": { "repo": "demo", "pr": i }
            })
            .to_string();
            let res = engine.ingest_event(0, body.as_bytes()).await.unwrap();
            total_dropped += res.dropped_slow.unwrap_or(0);
        }
        assert!(
            total_dropped >= 5,
            "expected tail drops, got {total_dropped}"
        );

        // Subscription must remain active (not suspended).
        let snap = engine.snapshot_state();
        assert_eq!(snap.subscriptions.len(), 1);
        assert!(!snap.subscriptions[0].suspended);
        assert!(!snap.subscriptions[0].pending_truncated_for_refresh);

        gate.notify_waiters();
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn catalog_merge_disallow_arguments_and_passthrough_resolution() {
        let (up_url, up_handle) = spawn_http_mock(move |req| async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&body).unwrap();
            let id = v["id"].clone();
            let resp = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "events": [
                        {
                            "name": "task.exited",
                            "description": "Task exited",
                            "delivery": ["push", "poll"],
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "scope": { "type": "string", "x-mcp-header": "Mcp-Param-Scope" },
                                    "taskId": { "type": "string" }
                                },
                                "required": ["scope"],
                                "additionalProperties": false
                            },
                            "payloadSchema": { "type": "object" }
                        },
                        {
                            "name": "internal.only",
                            "description": "Poll only",
                            "delivery": ["poll"],
                            "inputSchema": { "type": "object", "properties": {} },
                            "payloadSchema": { "type": "object" }
                        }
                    ]
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(resp.to_string())))
                .unwrap()
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Sep3415,
            Some(UpstreamConfig {
                url: up_url.clone(),
                bearer_token: None,
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 5,
                expose_events: vec![ExposeEventConfig {
                    name: "task.exited".into(),
                    disallow_arguments: vec!["scope".into()],
                }],
            }),
            Some(IngestConfig {
                tokens: vec![SecretString::new("ptok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let quotas = test_quotas();
        let engine = HookdEngine::new(cfg, quotas.clone(), MemoryPools::from_quotas(&quotas), None)
            .await
            .unwrap();

        let caller = CallerAuth::StaticSlot(0);
        // Modern sep3415 sees all 3 events sorted lexicographically.
        let p1 = engine
            .list_events(&caller, false, None, Some(2))
            .await
            .unwrap();
        assert_eq!(p1.events.len(), 2);
        assert_eq!(p1.events[0].name, "ci.build_failed");
        assert_eq!(p1.events[1].name, "internal.only");
        assert_eq!(p1.next_cursor.as_deref(), Some("internal.only"));

        let p2 = engine
            .list_events(&caller, false, p1.next_cursor.as_deref(), Some(2))
            .await
            .unwrap();
        assert_eq!(p2.events.len(), 1);
        assert_eq!(p2.events[0].name, "task.exited");
        assert!(p2.events[0].delivery.contains(&"webhook".to_owned()));
        assert!(
            p2.events[0].input_schema["properties"]
                .get("scope")
                .is_none()
        );
        assert_eq!(p2.events[0].input_schema["required"], json!([]));

        // Legacy session only sees webhook events and converges delivery to ["webhook"].
        let legacy = engine.list_events(&caller, true, None, None).await.unwrap();
        assert_eq!(legacy.events.len(), 2);
        for ev in &legacy.events {
            assert_eq!(ev.delivery, vec!["webhook"]);
        }

        // Passthrough resolution checks.
        assert_eq!(
            engine
                .resolve_event_for_passthrough("ci.build_failed", None)
                .await
                .unwrap(),
            PassthroughResolution::IngestUnsupported
        );
        assert_eq!(
            engine
                .resolve_event_for_passthrough("does.not.exist", None)
                .await
                .unwrap(),
            PassthroughResolution::NotFound
        );
        let mut bad_args = Map::new();
        bad_args.insert("scope".into(), json!("all"));
        assert_eq!(
            engine
                .resolve_event_for_passthrough("task.exited", Some(&bad_args))
                .await
                .unwrap(),
            PassthroughResolution::DisallowedArgument("scope".into())
        );
        let mut ok_args = Map::new();
        ok_args.insert("taskId".into(), json!("t1"));
        assert_eq!(
            engine
                .resolve_event_for_passthrough("task.exited", Some(&ok_args))
                .await
                .unwrap(),
            PassthroughResolution::UpstreamAllowed
        );

        engine.shutdown().await.unwrap();
        up_handle.abort();
    }

    #[tokio::test]
    async fn upstream_bridge_poll_fallback_and_gap_watermark_sep3415_vs_chatgpt() {
        for profile in [Profile::Sep3415, Profile::Chatgpt] {
            let poll_seq = Arc::new(AtomicUsize::new(0));
            let ps = Arc::clone(&poll_seq);
            let (up_url, up_handle) = spawn_http_mock(move |req| {
                let ps = Arc::clone(&ps);
                async move {
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    let v: Value = serde_json::from_slice(&body).unwrap();
                    let id = v["id"].clone();
                    let method = v["method"].as_str().unwrap_or("");
                    let resp = match method {
                        "events/list" => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "events": [{
                                    "name": "task.exited",
                                    "description": "Task exited",
                                    "delivery": ["push", "poll"],
                                    "inputSchema": { "type": "object", "properties": {} },
                                    "payloadSchema": { "type": "object" }
                                }]
                            }
                        }),
                        "events/stream" => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32026, "message": "poll only" }
                        }),
                        "events/poll" => {
                            let step = ps.fetch_add(1, Ordering::SeqCst);
                            match step {
                                0 => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "events": [],
                                        "cursor": "c0",
                                        "truncated": false,
                                        "hasMore": false,
                                        "nextPollMs": 20
                                    }
                                }),
                                1 => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "events": [
                                            {
                                                "eventId": "ev_1",
                                                "name": "task.exited",
                                                "timestamp": "2026-11-25T00:00:01Z",
                                                "data": { "n": 1 }
                                            },
                                            {
                                                "eventId": "ev_2",
                                                "name": "task.exited",
                                                "timestamp": "2026-11-25T00:00:02Z",
                                                "data": { "n": 2 }
                                            }
                                        ],
                                        "cursor": "c2",
                                        "truncated": false,
                                        "hasMore": true,
                                        "nextPollMs": 20
                                    }
                                }),
                                2 => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "events": [{
                                            "eventId": "ev_residual_discarded",
                                            "name": "task.exited",
                                            "timestamp": "2026-11-25T00:00:03Z",
                                            "data": { "n": 99 }
                                        }],
                                        "cursor": "c9",
                                        "truncated": true,
                                        "hasMore": false,
                                        "nextPollMs": 500
                                    }
                                }),
                                _ => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "result": {
                                        "events": [],
                                        "cursor": "c9",
                                        "truncated": false,
                                        "hasMore": false,
                                        "nextPollMs": 500
                                    }
                                }),
                            }
                        }
                        _ => json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": { "code": -32601, "message": "not found" }
                        }),
                    };
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(resp.to_string())))
                        .unwrap()
                }
            })
            .await;

            let cb = spawn_tls_callback(move |_headers, body| async move {
                let v: Value = serde_json::from_slice(&body).unwrap();
                if v["type"] == "verification" {
                    let resp = json!({ "challenge": v["challenge"] });
                    (StatusCode::OK, resp.to_string().into_bytes())
                } else {
                    (StatusCode::OK, b"{}".to_vec())
                }
            })
            .await;

            let dir = tempfile::TempDir::new().unwrap();
            let cfg = base_config(
                dir.path().join("subs.json"),
                profile,
                Some(UpstreamConfig {
                    url: up_url,
                    bearer_token: None,
                    passthrough_prefixes: Vec::new(),
                    request_timeout_secs: 5,
                    expose_events: vec![ExposeEventConfig {
                        name: "task.exited".into(),
                        disallow_arguments: Vec::new(),
                    }],
                }),
                None,
                None,
            );
            let quotas = test_quotas();
            let engine = HookdEngine::new(
                cfg,
                quotas.clone(),
                MemoryPools::from_quotas(&quotas),
                Some(loopback_outbound(cb.roots.clone())),
            )
            .await
            .unwrap();

            let caller = CallerAuth::StaticSlot(0);
            let sub_resp = engine
                .subscribe(
                    &caller,
                    SubscribeRequest {
                        event_name: "task.exited".into(),
                        arguments: Map::new(),
                        delivery_mode: "webhook".into(),
                        delivery_url: cb.url.clone(),
                        delivery_secret: test_secret(5),
                        ttl_ms: None,
                        cursor: None,
                        max_age_ms: None,
                    },
                )
                .await
                .unwrap();
            assert_eq!(sub_resp.cursor.as_deref(), Some("c0"));

            let expected_msgs = if profile == Profile::Sep3415 { 4 } else { 3 };
            let captured = wait_for_captured(&cb.captured, expected_msgs).await;
            assert_eq!(captured.len(), expected_msgs);

            let e1: Value = serde_json::from_slice(&captured[1].body).unwrap();
            let e2: Value = serde_json::from_slice(&captured[2].body).unwrap();
            assert_eq!(e1["eventId"], "ev_1");
            assert_eq!(e1["cursor"], "c0");
            assert_eq!(e2["eventId"], "ev_2");
            assert_eq!(e2["cursor"], "c2");

            if profile == Profile::Sep3415 {
                let gap: Value = serde_json::from_slice(&captured[3].body).unwrap();
                assert_eq!(gap["type"], "gap");
                assert_eq!(gap["cursor"], "c9");
            } else {
                // Wait briefly for Gap slot to settle in chatgpt profile.
                for _ in 0..50 {
                    let snap = engine.snapshot_state();
                    if snap.subscriptions[0].safe_cursor.as_deref() == Some("c9") {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let refresh = engine
                    .subscribe(
                        &caller,
                        SubscribeRequest {
                            event_name: "task.exited".into(),
                            arguments: Map::new(),
                            delivery_mode: "webhook".into(),
                            delivery_url: cb.url.clone(),
                            delivery_secret: test_secret(5),
                            ttl_ms: None,
                            cursor: None,
                            max_age_ms: None,
                        },
                    )
                    .await
                    .unwrap();
                assert!(refresh.truncated);
                assert_eq!(refresh.cursor.as_deref(), Some("c9"));

                // Second refresh sees pending_truncated_for_refresh cleared.
                let refresh2 = engine
                    .subscribe(
                        &caller,
                        SubscribeRequest {
                            event_name: "task.exited".into(),
                            arguments: Map::new(),
                            delivery_mode: "webhook".into(),
                            delivery_url: cb.url.clone(),
                            delivery_secret: test_secret(5),
                            ttl_ms: None,
                            cursor: None,
                            max_age_ms: None,
                        },
                    )
                    .await
                    .unwrap();
                assert!(!refresh2.truncated);
            }

            engine.shutdown().await.unwrap();
            up_handle.abort();
        }
    }

    #[tokio::test]
    async fn permanent_drop_410_and_transient_backoff_suspend() {
        let mode = Arc::new(AtomicUsize::new(0)); // 0 = return 410 once then 200; 1 = always 500
        let mode_cb = Arc::clone(&mode);
        let delivered_410 = Arc::new(AtomicUsize::new(0));
        let d410 = Arc::clone(&delivered_410);

        let cb = spawn_tls_callback(move |_headers, body| {
            let mode_cb = Arc::clone(&mode_cb);
            let d410 = Arc::clone(&d410);
            async move {
                let v: Value = serde_json::from_slice(&body).unwrap();
                if v["type"] == "verification" {
                    let resp = json!({ "challenge": v["challenge"] });
                    return (StatusCode::OK, resp.to_string().into_bytes());
                }
                if mode_cb.load(Ordering::SeqCst) == 0 {
                    if v["eventId"] == "evt_drop_410" {
                        d410.fetch_add(1, Ordering::SeqCst);
                        return (StatusCode::GONE, b"{}".to_vec());
                    }
                    return (StatusCode::OK, b"{}".to_vec());
                }
                (StatusCode::INTERNAL_SERVER_ERROR, b"err".to_vec())
            }
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Sep3415,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("prod_tok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let mut quotas = test_quotas();
        quotas.suspend_failure_count = 3;
        quotas.suspend_min_duration_secs = 0;

        let engine = HookdEngine::new(
            cfg,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();

        let caller = CallerAuth::StaticSlot(0);
        engine
            .subscribe(
                &caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: test_secret(9),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();

        // 410 drops single event without retry; next event succeeds.
        let b1 = json!({
            "eventId": "evt_drop_410",
            "name": "ci.build_failed",
            "data": { "repo": "demo" }
        })
        .to_string();
        let b2 = json!({
            "eventId": "evt_ok_after_410",
            "name": "ci.build_failed",
            "data": { "repo": "demo" }
        })
        .to_string();
        engine.ingest_event(0, b1.as_bytes()).await.unwrap();
        engine.ingest_event(0, b2.as_bytes()).await.unwrap();

        let captured = wait_for_captured(&cb.captured, 3).await;
        assert_eq!(delivered_410.load(Ordering::SeqCst), 1);
        let last: Value = serde_json::from_slice(&captured[2].body).unwrap();
        assert_eq!(last["eventId"], "evt_ok_after_410");
        assert!(!engine.snapshot_state().subscriptions[0].suspended);

        // Switch callback to 500 -> triggers suspend after 3 failures.
        mode.store(1, Ordering::SeqCst);
        let b3 = json!({
            "eventId": "evt_500_suspend",
            "name": "ci.build_failed",
            "data": { "repo": "demo" }
        })
        .to_string();
        engine.ingest_event(0, b3.as_bytes()).await.unwrap();

        for _ in 0..100 {
            if engine.snapshot_state().subscriptions[0].suspended {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let snap = engine.snapshot_state();
        assert!(snap.subscriptions[0].suspended);
        assert_eq!(
            snap.subscriptions[0].last_error,
            Some(CallbackErrorReason::Http5xx)
        );

        // Refresh clears suspended and reports active: false in deliveryStatus.
        mode.store(0, Ordering::SeqCst);
        let refreshed = engine
            .subscribe(
                &caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: test_secret(9),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            refreshed.delivery_status,
            Some(DeliveryStatus {
                active: false,
                last_error: Some(CallbackErrorReason::Http5xx)
            })
        );
        assert!(!engine.snapshot_state().subscriptions[0].suspended);

        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn delegated_auth_startup_pruning_and_scope_narrowing() {
        let (check_url, check_handle) = spawn_http_mock(move |req| async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&body).unwrap();
            let resp = match v["ref"].as_str().unwrap_or("") {
                "aref_ok" => json!({
                    "active": true,
                    "principal": "aref_ok",
                    "resource": "https://mcp.example.com/mcp",
                    "scopes": ["events:read", "tools:call"],
                    "expiresAt": unix_now() + 3600
                }),
                _ => json!({ "active": false }),
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(resp.to_string())))
                .unwrap()
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let state_path = dir.path().join("subs.json");
        let (store, _) = StateStore::open(state_path.clone()).unwrap();
        let k_ok = SubscriptionKey::new(
            "aref_ok",
            "https://hooks.example.com/ok",
            "ci.build_failed",
            &Map::new(),
        )
        .unwrap();
        let k_rev = SubscriptionKey::new(
            "aref_revoked",
            "https://hooks.example.com/rev",
            "ci.build_failed",
            &Map::new(),
        )
        .unwrap();
        let persisted = PersistedState {
            version: STATE_VERSION,
            subscriptions: vec![
                PersistedSubscription {
                    id: k_ok.subscription_id(),
                    key: k_ok.clone(),
                    arguments: Map::new(),
                    auth_ref: Some("aref_ok".into()),
                    granted_scopes: vec!["events:read".into()],
                    secret: test_secret(1),
                    prev_secret: None,
                    prev_secret_until: None,
                    refresh_before: unix_now() + 1800,
                    safe_cursor: None,
                    pending_truncated_for_refresh: false,
                    suspended: false,
                    last_error: None,
                },
                PersistedSubscription {
                    id: k_rev.subscription_id(),
                    key: k_rev.clone(),
                    arguments: Map::new(),
                    auth_ref: Some("aref_revoked".into()),
                    granted_scopes: vec!["events:read".into()],
                    secret: test_secret(2),
                    prev_secret: None,
                    prev_secret_until: None,
                    refresh_before: unix_now() + 1800,
                    safe_cursor: None,
                    pending_truncated_for_refresh: false,
                    suspended: false,
                    last_error: None,
                },
            ],
            verified_endpoints: Vec::new(),
        };
        store.save(&persisted).unwrap();

        let cfg = base_config(
            state_path,
            Profile::Sep3415,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("ptok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            Some(AuthContextConfig {
                check_url,
                check_token: SecretString::new("0123456789abcdef_token"),
                expected_resource: "https://mcp.example.com/mcp".into(),
                reverify_secs: 15,
            }),
        );
        let quotas = test_quotas();
        let engine = HookdEngine::new(cfg, quotas.clone(), MemoryPools::from_quotas(&quotas), None)
            .await
            .unwrap();

        // Startup live check pruned aref_revoked and kept aref_ok.
        assert_eq!(engine.active_subscription_count(), 1);

        // Refreshing with narrowed header scopes that do not cover granted_scopes returns Forbidden.
        let narrowed_caller = CallerAuth::Delegated {
            auth_ref: "aref_ok".into(),
            header_scopes: vec!["tools:call".into()],
        };
        let err = engine
            .subscribe(
                &narrowed_caller,
                SubscribeRequest {
                    event_name: "ci.build_failed".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: "https://hooks.example.com/ok".into(),
                    delivery_secret: test_secret(1),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, EngineError::Forbidden(_)));

        engine.shutdown().await.unwrap();
        check_handle.abort();
    }

    #[tokio::test]
    async fn subscribe_bootstrap_keeps_truncation_and_memory_admission_atomic() {
        let (up_url, up_handle) = spawn_http_mock(move |req| async move {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let v: Value = serde_json::from_slice(&body).unwrap();
            let id = v["id"].clone();
            let resp = match v["method"].as_str().unwrap_or("") {
                "events/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "events": [{
                            "name": "task.exited",
                            "description": "Task exited",
                            "delivery": ["poll"],
                            "inputSchema": { "type": "object", "properties": {} },
                            "payloadSchema": { "type": "object" }
                        }]
                    }
                }),
                "events/poll" => {
                    let cur = v["params"].get("cursor").and_then(Value::as_str);
                    if matches!(cur, Some("stale_c" | "budget_c")) {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "events": [{
                                    "eventId": "residual_must_drop",
                                    "name": "task.exited",
                                    "timestamp": "2026-11-25T00:00:01Z",
                                    "data": { "x": 1 }
                                }],
                                "cursor": "c_fresh",
                                "truncated": cur == Some("stale_c"),
                                "hasMore": false,
                                "nextPollMs": 500
                            }
                        })
                    } else {
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "events": [],
                                "cursor": "c_fresh",
                                "truncated": false,
                                "hasMore": false,
                                "nextPollMs": 500
                            }
                        })
                    }
                }
                _ => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "not found" }
                }),
            };
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(resp.to_string())))
                .unwrap()
        })
        .await;

        let cb = spawn_tls_callback(move |_headers, body| async move {
            let v: Value = serde_json::from_slice(&body).unwrap();
            if v["type"] == "verification" {
                let resp = json!({ "challenge": v["challenge"] });
                (StatusCode::OK, resp.to_string().into_bytes())
            } else {
                (StatusCode::OK, b"{}".to_vec())
            }
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Sep3415,
            Some(UpstreamConfig {
                url: up_url,
                bearer_token: None,
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 5,
                expose_events: vec![ExposeEventConfig {
                    name: "task.exited".into(),
                    disallow_arguments: Vec::new(),
                }],
            }),
            None,
            None,
        );
        let cfg_for_budget = Config {
            state_path: dir.path().join("budget.json"),
            ..cfg.clone()
        };
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            cfg,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();

        let resp = engine
            .subscribe(
                &CallerAuth::StaticSlot(0),
                SubscribeRequest {
                    event_name: "task.exited".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: test_secret(11),
                    ttl_ms: None,
                    cursor: Some("stale_c".into()),
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();

        assert!(resp.truncated);
        assert_eq!(resp.cursor.as_deref(), Some("c_fresh"));
        tokio::time::sleep(Duration::from_millis(80)).await;
        // Only the verification challenge should have been sent; residual event was discarded.
        assert_eq!(cb.captured.lock().await.len(), 1);

        engine.shutdown().await.unwrap();

        let mut quotas = test_quotas();
        quotas.outbox_byte_budget = 1;
        let engine = HookdEngine::new(
            cfg_for_budget,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();
        let failure = engine
            .subscribe(
                &CallerAuth::StaticSlot(0),
                SubscribeRequest {
                    event_name: "task.exited".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: test_secret(11),
                    ttl_ms: None,
                    cursor: Some("budget_c".into()),
                    max_age_ms: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(failure, EngineError::ResourceExhausted(_)));
        assert_eq!(engine.active_subscription_count(), 0);
        assert_eq!(engine.pools.outbox.used(), 0);
        assert!(engine.snapshot_state().subscriptions.is_empty());
        engine.shutdown().await.unwrap();
        up_handle.abort();
    }

    fn sample_upstream_sub(url: &str) -> Arc<SubRuntime> {
        let key = SubscriptionKey::new("static:0", url, "task.exited", &Map::new()).unwrap();
        Arc::new(new_sub_runtime(
            PersistedSubscription {
                id: key.subscription_id(),
                key,
                arguments: Map::new(),
                auth_ref: None,
                granted_scopes: Vec::new(),
                secret: test_secret(12),
                prev_secret: None,
                prev_secret_until: None,
                refresh_before: unix_now() + 1800,
                safe_cursor: Some("c0".into()),
                pending_truncated_for_refresh: false,
                suspended: false,
                last_error: None,
            },
            SubSource::Upstream {
                event_name: "task.exited".into(),
                arguments: Map::new(),
            },
            false,
        ))
    }

    fn sample_polled_event(event_id: &str, data: Value) -> UpstreamPolledEvent {
        UpstreamPolledEvent {
            event_id: event_id.into(),
            name: "task.exited".into(),
            timestamp: "2026-11-25T00:00:01Z".into(),
            data,
        }
    }

    #[tokio::test]
    async fn upstream_admission_caps_gaps_and_rejects_cancelled_or_inactive_consumers() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = base_config(
            dir.path().join("subs.json"),
            Profile::Chatgpt,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("ptok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            config,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            None,
        )
        .await
        .unwrap();
        let sub = sample_upstream_sub("https://hooks.example.com/capacity");
        let events = (0..63)
            .map(|i| sample_polled_event(&format!("event_{i}"), json!({})))
            .collect();
        assert!(engine.enqueue_polled_batch(&sub, events, Some("c63".into()), None));
        assert!(engine.enqueue_gap(&sub, "c64".into(), None));
        let bytes = engine.pools.outbox.used();
        assert!(!engine.enqueue_single_upstream_event(
            &sub,
            sample_polled_event("event_65", json!({})),
            Some("c65".into()),
            None,
        ));
        assert!(!engine.advance_idle_cursor(&sub, "c66".into(), None));
        {
            let mut state = sub.state.lock().unwrap();
            assert_eq!(state.outbox.len(), 64);
            assert_eq!(state.ingest_cursor.as_deref(), Some("c64"));
            assert_eq!(engine.pools.outbox.used(), bytes);
            state.outbox.clear();
        }
        assert_eq!(engine.pools.outbox.used(), 0);

        let (cancel, receiver) = watch::channel(false);
        *sub.consumer_cancel.lock().unwrap() = Some(cancel);
        sub.stop_consumer();
        assert!(!engine.enqueue_gap(&sub, "cancelled".into(), Some(&receiver)));
        assert!(!engine.enqueue_single_upstream_event(
            &sub,
            sample_polled_event("late", json!({})),
            Some("late".into()),
            Some(&receiver),
        ));
        for mode in 0..4 {
            {
                let mut state = sub.state.lock().unwrap();
                state.removed = mode == 0;
                state.suspended = mode == 1;
                state.auth_paused = mode == 2;
                state.refresh_before = if mode == 3 { 0 } else { unix_now() + 1800 };
            }
            assert!(!engine.enqueue_gap(&sub, "inactive".into(), None));
        }
        assert_eq!(engine.pools.outbox.used(), 0);
        assert_eq!(
            sub.state.lock().unwrap().ingest_cursor.as_deref(),
            Some("c64")
        );
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn skipped_tails_use_ordered_checkpoints_and_all_cursor_sizes_are_budgeted() {
        let callback =
            spawn_tls_callback(|_headers, _body| async { (StatusCode::OK, b"{}".to_vec()) }).await;
        let dir = tempfile::TempDir::new().unwrap();
        let config = base_config(
            dir.path().join("subs.json"),
            Profile::Chatgpt,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("ptok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let quotas = test_quotas();
        let engine = HookdEngine::new(
            config,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(callback.roots.clone())),
        )
        .await
        .unwrap();
        let sub = sample_upstream_sub(&callback.url);
        engine
            .runtime
            .lock()
            .unwrap()
            .subscriptions
            .insert(sub.key.clone(), Arc::clone(&sub));
        assert!(engine.enqueue_single_upstream_event(
            &sub,
            sample_polled_event("first", json!({})),
            None,
            None,
        ));
        let in_flight = clone_outbox_head(sub.state.lock().unwrap().outbox.front().unwrap());
        assert!(engine.enqueue_single_upstream_event(
            &sub,
            sample_polled_event("boot:42", json!({})),
            Some("c2".into()),
            None,
        ));
        assert!(matches!(
            in_flight,
            HeadAction::Event {
                advance_cursor: None,
                ..
            }
        ));
        {
            let state = sub.state.lock().unwrap();
            assert_eq!(state.outbox.len(), 2);
            assert!(matches!(
                state.outbox.front(),
                Some(OutboxItem::Event {
                    advance_cursor: None,
                    ..
                })
            ));
            assert!(
                matches!(state.outbox.back(), Some(OutboxItem::Checkpoint { cursor, .. }) if cursor == "c2")
            );
        }
        engine.spawn_delivery_worker(Arc::clone(&sub));
        let captured = wait_for_captured(&callback.captured, 1).await;
        assert_eq!(captured.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&captured[0].body).unwrap()["cursor"],
            "c0"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if sub.state.lock().unwrap().safe_cursor.as_deref() == Some("c2") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!sub.state.lock().unwrap().pending_truncated_for_refresh);
        assert_eq!(engine.pools.outbox.used(), 0);
        engine.shutdown().await.unwrap();

        let config = base_config(
            dir.path().join("budget.json"),
            Profile::Chatgpt,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("ptok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        let engine = HookdEngine::new(
            config,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            None,
        )
        .await
        .unwrap();
        let sub = sample_upstream_sub("https://hooks.example.com/cursors");
        let long_cursor = "cursor with \"quoted\" text";
        assert!(engine.enqueue_gap(&sub, long_cursor.into(), None));
        assert!(engine.enqueue_gap(&sub, "c2".into(), None));
        assert!(engine.enqueue_single_upstream_event(
            &sub,
            sample_polled_event("small", json!({})),
            None,
            None,
        ));
        {
            let state = sub.state.lock().unwrap();
            let OutboxItem::Event {
                _lease,
                event_id,
                name,
                timestamp,
                data_json,
                ..
            } = state.outbox.back().unwrap()
            else {
                panic!("event expected")
            };
            assert_eq!(
                _lease.bytes(),
                serialize_event_envelope(event_id, name, timestamp, data_json, Some(long_cursor))
                    .len()
            );
        }
        let base =
            serialize_event_envelope("large", "task.exited", "2026-11-25T00:00:01Z", "\"\"", None)
                .len();
        let event = sample_polled_event(
            "large",
            Value::String("x".repeat(MAX_WEBHOOK_PAYLOAD_BYTES - base - 1)),
        );
        assert!(engine.enqueue_single_upstream_event(&sub, event, Some("c3".into()), None));
        {
            let state = sub.state.lock().unwrap();
            assert_eq!(state.outbox.len(), 4);
            assert!(
                matches!(state.outbox.back(), Some(OutboxItem::Checkpoint { cursor, .. }) if cursor == "c3")
            );
        }
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn enqueue_polled_batch_atomic_byte_lease_all_or_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Sep3415,
            None,
            Some(IngestConfig {
                tokens: vec![SecretString::new("ptok")],
                events: vec![sample_ingest_event_cfg()],
            }),
            None,
        );
        // Budget enough for 1 event (~130 bytes) but too small for 2 events (~260 bytes).
        let mut quotas = test_quotas();
        quotas.outbox_byte_budget = 200;
        let pools = MemoryPools::from_quotas(&quotas);
        let engine = HookdEngine::new(cfg, quotas, pools.clone(), None)
            .await
            .unwrap();

        let key = SubscriptionKey::new(
            "static:0",
            "https://hooks.example.com/atomic",
            "task.exited",
            &Map::new(),
        )
        .unwrap();
        let sub = new_sub_runtime(
            PersistedSubscription {
                id: key.subscription_id(),
                key,
                arguments: Map::new(),
                auth_ref: None,
                granted_scopes: Vec::new(),
                secret: test_secret(12),
                prev_secret: None,
                prev_secret_until: None,
                refresh_before: unix_now() + 1800,
                safe_cursor: Some("c0".into()),
                pending_truncated_for_refresh: false,
                suspended: false,
                last_error: None,
            },
            SubSource::Upstream {
                event_name: "task.exited".into(),
                arguments: Map::new(),
            },
            false,
        );

        let batch = vec![
            UpstreamPolledEvent {
                event_id: "ev_a".into(),
                name: "task.exited".into(),
                timestamp: "2026-11-25T00:00:01Z".into(),
                data: json!({ "payload": "aaaaaaaaaaaaaaaaaaaaaaaa" }),
            },
            UpstreamPolledEvent {
                event_id: "ev_b".into(),
                name: "task.exited".into(),
                timestamp: "2026-11-25T00:00:02Z".into(),
                data: json!({ "payload": "bbbbbbbbbbbbbbbbbbbbbbbb" }),
            },
        ];

        assert!(!engine.enqueue_polled_batch(&sub, batch, Some("c2".into()), None));
        assert_eq!(pools.outbox.used(), 0);
        {
            let st = sub.state.lock().unwrap();
            assert!(st.outbox.is_empty());
            assert_eq!(st.ingest_cursor.as_deref(), Some("c0"));
            assert_eq!(st.safe_cursor.as_deref(), Some("c0"));
        }

        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn upstream_consumer_waits_after_partial_byte_capacity_rejection() {
        let poll_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&poll_count);
        let (url, upstream_task) = spawn_http_mock(move |request| {
            let count = Arc::clone(&count);
            async move {
                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let result = if request["method"] == "events/list" {
                    json!({"events": [{
                        "name": "task.exited", "delivery": ["poll"],
                        "inputSchema": {"type": "object"},
                        "payloadSchema": {"type": "object"}
                    }]})
                } else {
                    count.fetch_add(1, Ordering::SeqCst);
                    json!({
                        "events": [{
                            "eventId": "next", "name": "task.exited",
                            "timestamp": "2026-11-25T00:00:01Z",
                            "data": {"message": "x".repeat(400)}
                        }],
                        "cursor": "c1", "truncated": false, "hasMore": true,
                        "nextPollMs": 20
                    })
                };
                Response::builder()
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(
                        json!({"jsonrpc": "2.0", "id": request["id"], "result": result})
                            .to_string(),
                    )))
                    .unwrap()
            }
        })
        .await;
        let directory = tempfile::TempDir::new().unwrap();
        let config = base_config(
            directory.path().join("subs.json"),
            Profile::Sep3415,
            Some(UpstreamConfig {
                url,
                bearer_token: None,
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 5,
                expose_events: vec![ExposeEventConfig {
                    name: "task.exited".into(),
                    disallow_arguments: Vec::new(),
                }],
            }),
            None,
            None,
        );
        let mut quotas = test_quotas();
        quotas.outbox_byte_budget = 1024;
        let engine = HookdEngine::new(
            config,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            None,
        )
        .await
        .unwrap();
        let other_subscription_bytes = engine.pools.outbox.try_acquire(900).unwrap();
        let sub = sample_upstream_sub("https://hooks.example.com/byte-pressure");
        let (cancel, receiver) = watch::channel(false);
        let worker =
            tokio::spawn(Arc::clone(&engine).run_upstream_consumer(Arc::clone(&sub), receiver));
        tokio::time::timeout(Duration::from_secs(2), async {
            while poll_count.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(poll_count.load(Ordering::SeqCst), 1);
        assert!(sub.state.lock().unwrap().outbox.is_empty());
        assert_eq!(
            sub.state.lock().unwrap().ingest_cursor.as_deref(),
            Some("c0")
        );
        cancel.send_replace(true);
        worker.await.unwrap();
        drop(other_subscription_bytes);
        engine.shutdown().await.unwrap();
        upstream_task.abort();
    }

    #[tokio::test]
    async fn upstream_consumer_half_water_backpressure_hysteresis() {
        let poll_count = Arc::new(AtomicUsize::new(0));
        let pc = Arc::clone(&poll_count);
        let (up_url, up_handle) = spawn_http_mock(move |req| {
            let pc = Arc::clone(&pc);
            async move {
                let body = req.into_body().collect().await.unwrap().to_bytes();
                let v: Value = serde_json::from_slice(&body).unwrap();
                let id = v["id"].clone();
                let resp = match v["method"].as_str().unwrap_or("") {
                    "events/list" => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "events": [{
                                "name": "task.exited",
                                "description": "Task exited",
                                "delivery": ["poll"],
                                "inputSchema": { "type": "object", "properties": {} },
                                "payloadSchema": { "type": "object" }
                            }]
                        }
                    }),
                    "events/poll" => {
                        let step = pc.fetch_add(1, Ordering::SeqCst);
                        match step {
                            0 => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "events": [],
                                    "cursor": "c0",
                                    "truncated": false,
                                    "hasMore": false,
                                    "nextPollMs": 20
                                }
                            }),
                            _ => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "events": [
                                        {
                                            "eventId": format!("ev_{step}_1"),
                                            "name": "task.exited",
                                            "timestamp": "2026-11-25T00:00:01Z",
                                            "data": { "s": step }
                                        },
                                        {
                                            "eventId": format!("ev_{step}_2"),
                                            "name": "task.exited",
                                            "timestamp": "2026-11-25T00:00:02Z",
                                            "data": { "s": step }
                                        }
                                    ],
                                    "cursor": format!("c{step}"),
                                    "truncated": false,
                                    "hasMore": true,
                                    "nextPollMs": 20
                                }
                            }),
                        }
                    }
                    _ => json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32601, "message": "not found" }
                    }),
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(resp.to_string())))
                    .unwrap()
            }
        })
        .await;

        let delivery_permits = Arc::new(Semaphore::new(0));
        let dp = Arc::clone(&delivery_permits);
        let cb = spawn_tls_callback(move |_headers, body| {
            let dp = Arc::clone(&dp);
            async move {
                let v: Value = serde_json::from_slice(&body).unwrap();
                if v["type"] == "verification" {
                    let resp = json!({ "challenge": v["challenge"] });
                    (StatusCode::OK, resp.to_string().into_bytes())
                } else {
                    if let Ok(p) = dp.acquire().await {
                        p.forget();
                    }
                    (StatusCode::OK, b"{}".to_vec())
                }
            }
        })
        .await;

        let dir = tempfile::TempDir::new().unwrap();
        let cfg = base_config(
            dir.path().join("subs.json"),
            Profile::Sep3415,
            Some(UpstreamConfig {
                url: up_url,
                bearer_token: None,
                passthrough_prefixes: Vec::new(),
                request_timeout_secs: 5,
                expose_events: vec![ExposeEventConfig {
                    name: "task.exited".into(),
                    disallow_arguments: Vec::new(),
                }],
            }),
            None,
            None,
        );
        let mut quotas = test_quotas();
        quotas.max_outbox_per_sub = 4; // half-water = 2
        let engine = HookdEngine::new(
            cfg,
            quotas.clone(),
            MemoryPools::from_quotas(&quotas),
            Some(loopback_outbound(cb.roots.clone())),
        )
        .await
        .unwrap();

        engine
            .subscribe(
                &CallerAuth::StaticSlot(0),
                SubscribeRequest {
                    event_name: "task.exited".into(),
                    arguments: Map::new(),
                    delivery_mode: "webhook".into(),
                    delivery_url: cb.url.clone(),
                    delivery_secret: test_secret(13),
                    ttl_ms: None,
                    cursor: None,
                    max_age_ms: None,
                },
            )
            .await
            .unwrap();

        // Wait until consumer fills outbox to 4 (bootstrap + 2 polls of 2 events = 3 total polls).
        for _ in 0..100 {
            if poll_count.load(Ordering::SeqCst) >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        tokio::time::sleep(Duration::from_millis(80)).await;
        let paused_polls = poll_count.load(Ordering::SeqCst);
        assert_eq!(paused_polls, 3);

        // Drain 1 event (len 4 -> 3, still >= half-water 2): consumer must stay paused.
        delivery_permits.add_permits(1);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(poll_count.load(Ordering::SeqCst), paused_polls);

        // Drain 2 more events (len 3 -> 1 < half-water 2): consumer must resume polling.
        delivery_permits.add_permits(2);
        for _ in 0..100 {
            if poll_count.load(Ordering::SeqCst) > paused_polls {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(poll_count.load(Ordering::SeqCst) > paused_polls);

        delivery_permits.add_permits(100);
        engine.shutdown().await.unwrap();
        up_handle.abort();
    }
}
