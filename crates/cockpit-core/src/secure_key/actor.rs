//! Daemon-owned secure-key actor: dedicated OS thread + bounded sync_channel.

use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use tokio::sync::oneshot;

use crate::db::Db;
use crate::db::installation_identity::{InstallationIdentity, ensure_installation_identity_conn};
use crate::db::secure_key::SecureKeyConsumerRef;

use super::consumer::{ConsumerReconciler, FailClosedReconciler};
use super::error::SecureKeyError;
use super::key_material::SecureKeyBytes;
use super::namespace::Namespace;
use super::native_store::NativeKeyStore;
use super::platform::{
    mark_actor_intake_ready, mark_worker_drained, production_native_store,
    set_default_platform_store, unset_default_platform_store,
};
use super::sealed_state::{SealedPayload, SealedStateView};
use super::worker::{NamespaceMetadata, Worker};

/// Bounded queue capacity (acceptance: 32).
pub const SECURE_KEY_QUEUE_CAPACITY: usize = 32;

type Reply<T> = oneshot::Sender<T>;

enum Op {
    CreateOrLoad {
        namespace: Namespace,
        reply: Reply<Result<(i64, SecureKeyBytes), SecureKeyError>>,
    },
    LoadVersion {
        namespace: Namespace,
        version: i64,
        reply: Reply<Result<(i64, SecureKeyBytes), SecureKeyError>>,
    },
    Rotate {
        namespace: Namespace,
        reply: Reply<Result<(i64, SecureKeyBytes), SecureKeyError>>,
    },
    ListMetadata {
        namespace: Namespace,
        reply: Reply<Result<NamespaceMetadata, SecureKeyError>>,
    },
    Reserve {
        reference_id: String,
        namespace: Namespace,
        version: i64,
        consumer_kind: String,
        consumer_id: String,
        reply: Reply<Result<SecureKeyConsumerRef, SecureKeyError>>,
    },
    ActivateRef {
        reference_id: String,
        reply: Reply<Result<(), SecureKeyError>>,
    },
    BeginReleaseRef {
        reference_id: String,
        reply: Reply<Result<(), SecureKeyError>>,
    },
    CompleteReleaseRef {
        reference_id: String,
        reply: Reply<Result<(), SecureKeyError>>,
    },
    Retire {
        namespace: Namespace,
        version: i64,
        reply: Reply<Result<(), SecureKeyError>>,
    },
    Reconcile {
        // std mpsc so constructors and sync tests can wait from a Tokio worker
        // without `oneshot::Receiver::blocking_recv` panicking.
        reply: mpsc::SyncSender<Result<(), SecureKeyError>>,
    },
    CheckConsistency {
        namespace: Namespace,
        reply: Reply<Result<(), SecureKeyError>>,
    },
    SealedCreateOrLoad {
        namespace: Namespace,
        initial: SealedPayload,
        reply: Reply<Result<SealedStateView, SecureKeyError>>,
    },
    SealedLoad {
        namespace: Namespace,
        reply: Reply<Result<SealedStateView, SecureKeyError>>,
    },
    SealedCompareAndSwap {
        namespace: Namespace,
        expected_generation: u64,
        expected_payload_digest: [u8; 32],
        new_payload: SealedPayload,
        reply: Reply<Result<SealedStateView, SecureKeyError>>,
    },
    Shutdown {
        reply: Reply<()>,
    },
}

/// Handle for async (and sync test) callers.
#[derive(Clone)]
pub struct SecureKeyHandle {
    tx: SyncSender<Op>,
}

impl SecureKeyHandle {
    fn enqueue(&self, op: Op) -> Result<(), SecureKeyError> {
        match self.tx.try_send(op) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(SecureKeyError::Busy),
            Err(TrySendError::Disconnected(_)) => {
                Err(SecureKeyError::Internal("secure key actor stopped".into()))
            }
        }
    }

    async fn await_reply<T: Send + 'static>(rx: oneshot::Receiver<T>) -> Result<T, SecureKeyError> {
        // Pure async wait — no Tokio blocking/core-pool worker.
        rx.await
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))
    }

    pub async fn create_or_load(
        &self,
        namespace: &str,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CreateOrLoad { namespace, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn load_version(
        &self,
        namespace: &str,
        version: i64,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::LoadVersion {
            namespace,
            version,
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    pub async fn rotate(&self, namespace: &str) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Rotate { namespace, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn list_metadata(
        &self,
        namespace: &str,
    ) -> Result<NamespaceMetadata, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::ListMetadata { namespace, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn reserve(
        &self,
        reference_id: &str,
        namespace: &str,
        version: i64,
        consumer_kind: &str,
        consumer_id: &str,
    ) -> Result<SecureKeyConsumerRef, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Reserve {
            reference_id: reference_id.to_owned(),
            namespace,
            version,
            consumer_kind: consumer_kind.to_owned(),
            consumer_id: consumer_id.to_owned(),
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    /// Prefer [`super::consumer::activate_ref_in_tx`] for atomic composition with
    /// consumer ciphertext reachability. Actor-mediated activate is restricted
    /// to reconciliation / tests (`pub(crate)`).
    #[allow(dead_code)] // async twin of activate_ref_blocking for future async consumers
    pub(crate) async fn activate_ref(&self, reference_id: &str) -> Result<(), SecureKeyError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::ActivateRef {
            reference_id: reference_id.to_owned(),
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    /// Prefer [`super::consumer::begin_release_in_tx`] for atomic composition.
    #[allow(dead_code)] // async twin of begin_release_ref_blocking
    pub(crate) async fn begin_release_ref(&self, reference_id: &str) -> Result<(), SecureKeyError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::BeginReleaseRef {
            reference_id: reference_id.to_owned(),
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    #[allow(dead_code)] // async twin of complete_release_ref_blocking
    pub(crate) async fn complete_release_ref(
        &self,
        reference_id: &str,
    ) -> Result<(), SecureKeyError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CompleteReleaseRef {
            reference_id: reference_id.to_owned(),
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    pub async fn retire(&self, namespace: &str, version: i64) -> Result<(), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Retire {
            namespace,
            version,
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    pub async fn reconcile(&self) -> Result<(), SecureKeyError> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.enqueue(Op::Reconcile { reply })?;
        match tokio::task::spawn_blocking(move || rx.recv()).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(SecureKeyError::Internal("actor dropped reply".into())),
            Err(error) => Err(SecureKeyError::Internal(error.to_string())),
        }
    }

    pub async fn check_consistency(&self, namespace: &str) -> Result<(), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CheckConsistency { namespace, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn sealed_create_or_load(
        &self,
        namespace: &str,
        initial: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SealedCreateOrLoad {
            namespace,
            initial,
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    pub async fn sealed_load(&self, namespace: &str) -> Result<SealedStateView, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SealedLoad { namespace, reply })?;
        Self::await_reply(rx).await?
    }

    pub async fn sealed_compare_and_swap(
        &self,
        namespace: &str,
        expected_generation: u64,
        expected_payload_digest: [u8; 32],
        new_payload: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SealedCompareAndSwap {
            namespace,
            expected_generation,
            expected_payload_digest,
            new_payload,
            reply,
        })?;
        Self::await_reply(rx).await?
    }

    /// Sync call for tests that are not on an async runtime.
    pub fn create_or_load_blocking(
        &self,
        namespace: &str,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CreateOrLoad { namespace, reply })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn rotate_blocking(
        &self,
        namespace: &str,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Rotate { namespace, reply })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn retire_blocking(&self, namespace: &str, version: i64) -> Result<(), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Retire {
            namespace,
            version,
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn load_version_blocking(
        &self,
        namespace: &str,
        version: i64,
    ) -> Result<(i64, SecureKeyBytes), SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::LoadVersion {
            namespace,
            version,
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn reserve_blocking(
        &self,
        reference_id: &str,
        namespace: &str,
        version: i64,
        consumer_kind: &str,
        consumer_id: &str,
    ) -> Result<SecureKeyConsumerRef, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::Reserve {
            reference_id: reference_id.to_owned(),
            namespace,
            version,
            consumer_kind: consumer_kind.to_owned(),
            consumer_id: consumer_id.to_owned(),
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn list_metadata_blocking(
        &self,
        namespace: &str,
    ) -> Result<NamespaceMetadata, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::ListMetadata { namespace, reply })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn sealed_create_or_load_blocking(
        &self,
        namespace: &str,
        initial: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SealedCreateOrLoad {
            namespace,
            initial,
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn sealed_load_blocking(&self, namespace: &str) -> Result<SealedStateView, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SealedLoad { namespace, reply })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn sealed_compare_and_swap_blocking(
        &self,
        namespace: &str,
        expected_generation: u64,
        expected_payload_digest: [u8; 32],
        new_payload: SealedPayload,
    ) -> Result<SealedStateView, SecureKeyError> {
        let namespace = Namespace::parse(namespace)?;
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::SealedCompareAndSwap {
            namespace,
            expected_generation,
            expected_payload_digest,
            new_payload,
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn reconcile_blocking(&self) -> Result<(), SecureKeyError> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.enqueue(Op::Reconcile { reply })?;
        rx.recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    #[allow(dead_code)] // exercised by unit tests; reserved for async consumers' sync tests
    pub(crate) fn begin_release_ref_blocking(
        &self,
        reference_id: &str,
    ) -> Result<(), SecureKeyError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::BeginReleaseRef {
            reference_id: reference_id.to_owned(),
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    #[allow(dead_code)] // exercised by unit tests
    pub(crate) fn complete_release_ref_blocking(
        &self,
        reference_id: &str,
    ) -> Result<(), SecureKeyError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::CompleteReleaseRef {
            reference_id: reference_id.to_owned(),
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    #[allow(dead_code)] // exercised by unit tests
    pub(crate) fn activate_ref_blocking(&self, reference_id: &str) -> Result<(), SecureKeyError> {
        let (reply, rx) = oneshot::channel();
        self.enqueue(Op::ActivateRef {
            reference_id: reference_id.to_owned(),
            reply,
        })?;
        rx.blocking_recv()
            .map_err(|_| SecureKeyError::Internal("actor dropped reply".into()))?
    }

    pub fn enqueue_raw_for_busy_test(&self) -> Result<(), SecureKeyError> {
        let (reply, _rx) = mpsc::sync_channel(1);
        self.enqueue(Op::Reconcile { reply })
    }
}

/// Owns the actor thread and optional process-global keyring registration.
pub struct SecureKeyActor {
    handle: SecureKeyHandle,
    join: Mutex<Option<JoinHandle<()>>>,
    owns_default_store: bool,
    /// Keep a sender alive only for Drop shutdown.
    shutdown_tx: SyncSender<Op>,
}

impl SecureKeyActor {
    /// Production composition: resolve KEK placement (first-run is keyring
    /// when the probe is available, otherwise database), start the wrap-key
    /// vault, then spawn the dedicated actor thread. Call under the daemon
    /// single-instance lock.
    pub fn start_production(db: Db) -> Result<Self, SecureKeyError> {
        Self::start_production_with_reconciler(db, Arc::new(FailClosedReconciler))
    }

    /// Production composition with a reconciler that knows the consumer kinds
    /// this build actually registers.
    ///
    /// `start_production` is fail-closed for every kind, which is correct while
    /// no consumer exists but would leave a real consumer's references
    /// permanently unreconcilable. Composition points pass a reconciler that
    /// resolves the kinds they own and delegates the rest, so fail-closed stays
    /// the default for anything unregistered.
    pub fn start_production_with_reconciler(
        db: Db,
        reconciler: Arc<dyn ConsumerReconciler>,
    ) -> Result<Self, SecureKeyError> {
        Self::start_production_resolved(
            db,
            reconciler,
            &super::platform::probe_platform_keyring(),
            None,
            super::resolve::SecretStoreInjected::default(),
        )
    }

    /// Shared boot path for daemon and `cockpit ask`. First-run persists
    /// keyring when the probe is available, otherwise database. Does not
    /// construct the platform store a second time.
    pub fn start_production_resolved(
        db: Db,
        reconciler: Arc<dyn ConsumerReconciler>,
        keyring_probe: &super::platform::KeyringProbeResult,
        kek_dir: Option<std::path::PathBuf>,
        injected: super::resolve::SecretStoreInjected,
    ) -> Result<Self, SecureKeyError> {
        let kek_dir = match kek_dir {
            Some(dir) => dir,
            None => super::resolve::kek_dir_for_db(&db)?,
        };
        let effective =
            super::resolve::ensure_secret_vault(&db, keyring_probe, &kek_dir, injected)?;
        let owns_default_store =
            effective.placement == cockpit_proto::SecretStorePlacement::Keyring;
        Self::start_inner(
            db,
            Some(Box::new(super::vault_store::VaultNativeStore::new(
                effective.vault,
            ))),
            reconciler,
            owns_default_store,
        )
    }

    /// Test/injection path: never registers or unsets the process-global default store.
    /// Ownership of `set_default_store` is exclusive to [`Self::start_production`].
    pub fn start_with_store(
        db: Db,
        store: Box<dyn NativeKeyStore>,
        reconciler: Arc<dyn ConsumerReconciler>,
    ) -> Result<Self, SecureKeyError> {
        Self::start_inner(db, Some(store), reconciler, false)
    }

    fn start_inner(
        db: Db,
        injected_store: Option<Box<dyn NativeKeyStore>>,
        reconciler: Arc<dyn ConsumerReconciler>,
        owns_default_store: bool,
    ) -> Result<Self, SecureKeyError> {
        let installation = db
            .blocking_write_for_sync_maintenance(|conn| {
                conn.execute_batch("BEGIN IMMEDIATE;")?;
                let result = ensure_installation_identity_conn(conn);
                match &result {
                    Ok(_) => {
                        conn.execute_batch("COMMIT;")?;
                    }
                    Err(_) => {
                        let _ = conn.execute_batch("ROLLBACK;");
                    }
                }
                result
            })
            .map_err(|e| SecureKeyError::Internal(e.to_string()))?;

        let (tx, rx) = mpsc::sync_channel::<Op>(SECURE_KEY_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), SecureKeyError>>(1);
        let register_on_thread = owns_default_store && injected_store.is_none();
        let join = thread::Builder::new()
            .name("cockpit-secure-key".into())
            .spawn(move || {
                let store_result: Result<Box<dyn NativeKeyStore>, SecureKeyError> =
                    if register_on_thread {
                        match set_default_platform_store() {
                            Ok(()) => Ok(production_native_store()),
                            Err(e) => Err(e),
                        }
                    } else if let Some(s) = injected_store {
                        Ok(s)
                    } else {
                        Ok(production_native_store())
                    };
                let store = match store_result {
                    Ok(s) => {
                        let _ = ready_tx.send(Ok(()));
                        s
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                actor_loop(db, store, installation, reconciler, rx);
            })
            .map_err(|e| SecureKeyError::Internal(format!("spawn secure-key thread: {e}")))?;

        // Wait for actor-thread registration/construct before enqueueing.
        // Use a std channel so this constructor can run from a Tokio worker
        // (daemon boot and #[tokio::test]) without oneshot::blocking_recv.
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let _ = join.join();
                if register_on_thread {
                    unset_default_platform_store();
                }
                return Err(e);
            }
            Err(_) => {
                let _ = join.join();
                if register_on_thread {
                    unset_default_platform_store();
                }
                return Err(SecureKeyError::Internal(
                    "actor thread died before ready".into(),
                ));
            }
        }

        let handle = SecureKeyHandle { tx: tx.clone() };
        let (reply, rx_ack) = mpsc::sync_channel(1);
        if handle.enqueue(Op::Reconcile { reply }).is_err() {
            return Self::fail_after_registration(
                register_on_thread,
                &tx,
                join,
                SecureKeyError::Internal("failed to enqueue startup reconcile".into()),
            );
        }
        match rx_ack.recv() {
            Ok(Ok(())) => {
                if owns_default_store {
                    mark_actor_intake_ready();
                }
            }
            Ok(Err(e)) => {
                return Self::fail_after_registration(register_on_thread, &tx, join, e);
            }
            Err(_) => {
                return Self::fail_after_registration(
                    register_on_thread,
                    &tx,
                    join,
                    SecureKeyError::Internal("startup reconcile dropped".into()),
                );
            }
        }

        Ok(Self {
            handle,
            join: Mutex::new(Some(join)),
            owns_default_store,
            shutdown_tx: tx,
        })
    }

    /// Drain actor thread and release process-global store if production
    /// registration already succeeded but startup cannot complete.
    fn fail_after_registration(
        register_on_thread: bool,
        tx: &SyncSender<Op>,
        join: JoinHandle<()>,
        err: SecureKeyError,
    ) -> Result<Self, SecureKeyError> {
        let (sreply, srx) = oneshot::channel();
        let _ = tx.send(Op::Shutdown { reply: sreply });
        let _ = srx.blocking_recv();
        let _ = join.join();
        if register_on_thread {
            mark_worker_drained();
            unset_default_platform_store();
        }
        Err(err)
    }

    pub fn handle(&self) -> SecureKeyHandle {
        self.handle.clone()
    }

    /// Drain worker then unset default store if owned.
    pub fn shutdown(mut self) {
        let (reply, rx) = oneshot::channel();
        let _ = self.shutdown_tx.send(Op::Shutdown { reply });
        let _ = rx.blocking_recv();
        if let Ok(mut g) = self.join.lock()
            && let Some(j) = g.take()
        {
            let _ = j.join();
        }
        if self.owns_default_store {
            mark_worker_drained();
            unset_default_platform_store();
            self.owns_default_store = false;
        }
        // Drop only sees join=None and owns_default_store=false.
    }
}

impl Drop for SecureKeyActor {
    fn drop(&mut self) {
        let (reply, rx) = oneshot::channel();
        let _ = self.shutdown_tx.send(Op::Shutdown { reply });
        if tokio::runtime::Handle::try_current().is_ok() {
            let _ = std::thread::Builder::new()
                .name("cockpit-secure-key-drop".into())
                .spawn(move || {
                    let _ = rx.blocking_recv();
                });
            if let Ok(mut g) = self.join.lock()
                && let Some(j) = g.take()
            {
                let _ = j.join();
            }
            if self.owns_default_store {
                mark_worker_drained();
                unset_default_platform_store();
                self.owns_default_store = false;
            }
            return;
        }
        let _ = rx.blocking_recv();
        if let Ok(mut g) = self.join.lock()
            && let Some(j) = g.take()
        {
            let _ = j.join();
        }
        if self.owns_default_store {
            mark_worker_drained();
            unset_default_platform_store();
            self.owns_default_store = false;
        }
    }
}

fn actor_loop(
    db: Db,
    store: Box<dyn NativeKeyStore>,
    installation: InstallationIdentity,
    reconciler: Arc<dyn ConsumerReconciler>,
    rx: Receiver<Op>,
) {
    while let Ok(op) = rx.recv() {
        let worker = Worker {
            db: &db,
            store: store.as_ref(),
            installation: &installation,
            reconciler: reconciler.as_ref(),
        };
        match op {
            Op::CreateOrLoad { namespace, reply } => {
                let _ = reply.send(worker.create_or_load(&namespace));
            }
            Op::LoadVersion {
                namespace,
                version,
                reply,
            } => {
                let _ = reply.send(worker.load_version(&namespace, version));
            }
            Op::Rotate { namespace, reply } => {
                let _ = reply.send(worker.rotate(&namespace));
            }
            Op::ListMetadata { namespace, reply } => {
                let _ = reply.send(worker.list_metadata(&namespace));
            }
            Op::Reserve {
                reference_id,
                namespace,
                version,
                consumer_kind,
                consumer_id,
                reply,
            } => {
                let _ = reply.send(worker.reserve(
                    &reference_id,
                    &namespace,
                    version,
                    &consumer_kind,
                    &consumer_id,
                ));
            }
            Op::ActivateRef {
                reference_id,
                reply,
            } => {
                let _ = reply.send(worker.activate_ref(&reference_id));
            }
            Op::BeginReleaseRef {
                reference_id,
                reply,
            } => {
                let _ = reply.send(worker.begin_release_ref(&reference_id));
            }
            Op::CompleteReleaseRef {
                reference_id,
                reply,
            } => {
                let _ = reply.send(worker.complete_release_ref(&reference_id));
            }
            Op::Retire {
                namespace,
                version,
                reply,
            } => {
                let _ = reply.send(worker.retire(&namespace, version));
            }
            Op::Reconcile { reply } => {
                let _ = reply.send(worker.startup_reconcile());
            }
            Op::CheckConsistency { namespace, reply } => {
                let _ = reply.send(worker.check_consistency(&namespace));
            }
            Op::SealedCreateOrLoad {
                namespace,
                initial,
                reply,
            } => {
                let _ = reply.send(worker.sealed_create_or_load(&namespace, initial));
            }
            Op::SealedLoad { namespace, reply } => {
                let _ = reply.send(worker.sealed_load(&namespace));
            }
            Op::SealedCompareAndSwap {
                namespace,
                expected_generation,
                expected_payload_digest,
                new_payload,
                reply,
            } => {
                let _ = reply.send(worker.sealed_compare_and_swap(
                    &namespace,
                    expected_generation,
                    expected_payload_digest,
                    new_payload,
                ));
            }
            Op::Shutdown { reply } => {
                let _ = reply.send(());
                break;
            }
        }
    }
}
