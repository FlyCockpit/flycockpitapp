//! In-memory native store for tests. Never touches real OS keyrings.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use super::error::SecureKeyError;
use super::key_material::TempSecret;
use super::native_store::NativeKeyStore;

/// Barrier: hang-entered flag + condvar for deterministic waiters.
type HangEnteredBarrier = Arc<(Mutex<bool>, Condvar)>;

/// Fault injection points aligned to saga boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    BeforeSet,
    AfterSet,
    BeforeGet,
    AfterGet,
    BeforeDelete,
    AfterDelete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedFault {
    Error(FaultKind),
    /// Block the calling thread until `release` is signaled (stuck store).
    Hang,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    Locked,
    Denied,
    Unavailable,
    Corrupt,
    NotFound,
}

impl FaultKind {
    fn into_error(self) -> SecureKeyError {
        match self {
            Self::Locked => SecureKeyError::Locked("injected".into()),
            Self::Denied => SecureKeyError::Denied("injected".into()),
            Self::Unavailable => SecureKeyError::Unavailable("injected".into()),
            Self::Corrupt => SecureKeyError::Corrupt("injected".into()),
            Self::NotFound => SecureKeyError::NotFound("injected".into()),
        }
    }
}

struct IndexedFault {
    /// 1-based call index that should fire.
    at_count: usize,
    point: FaultPoint,
    fault: InjectedFault,
    used: bool,
}

struct FakeState {
    items: HashMap<(String, String), Vec<u8>>,
    faults: HashMap<FaultPoint, InjectedFault>,
    /// One-shot fault counters: decrement each use; remove at zero.
    fault_remaining: HashMap<FaultPoint, usize>,
    /// Fire only when set/get/delete cumulative count matches.
    indexed: Vec<IndexedFault>,
    hang_release: Option<Arc<Mutex<()>>>,
    hang_entered: Option<HangEnteredBarrier>,
    set_calls: usize,
    get_calls: usize,
    delete_calls: usize,
    /// Optional drop probe invoked when TempSecret would be created (get path).
    get_drop_probe: Option<Arc<AtomicUsize>>,
}

/// Shared fake native store.
#[derive(Clone)]
pub struct FakeNativeStore {
    inner: Arc<Mutex<FakeState>>,
    pub thread_ids: Arc<Mutex<Vec<thread::ThreadId>>>,
    pub drop_probe_hits: Arc<AtomicUsize>,
    hang_entered_slot: Arc<Mutex<Option<HangEnteredBarrier>>>,
}

impl Default for FakeNativeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeNativeStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeState {
                items: HashMap::new(),
                faults: HashMap::new(),
                fault_remaining: HashMap::new(),
                indexed: Vec::new(),
                hang_release: None,
                hang_entered: None,
                set_calls: 0,
                get_calls: 0,
                delete_calls: 0,
                get_drop_probe: None,
            })),
            thread_ids: Arc::new(Mutex::new(Vec::new())),
            drop_probe_hits: Arc::new(AtomicUsize::new(0)),
            hang_entered_slot: Arc::new(Mutex::new(None)),
        }
    }

    pub fn inject(&self, point: FaultPoint, fault: InjectedFault) {
        self.inject_times(point, fault, usize::MAX);
    }

    pub fn inject_once(&self, point: FaultPoint, fault: InjectedFault) {
        self.inject_times(point, fault, 1);
    }

    pub fn inject_times(&self, point: FaultPoint, fault: InjectedFault, times: usize) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.faults.insert(point, fault);
        g.fault_remaining.insert(point, times);
    }

    /// Fire a fault only on the Nth set/get/delete call (1-based), at Before/After point.
    pub fn inject_at_call_count(&self, point: FaultPoint, at_count: usize, fault: InjectedFault) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.indexed.push(IndexedFault {
            at_count,
            point,
            fault,
            used: false,
        });
    }

    pub fn clear_faults(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.faults.clear();
        g.fault_remaining.clear();
        g.indexed.clear();
        g.hang_release = None;
        g.hang_entered = None;
        drop(g);
        *self.hang_entered_slot.lock().unwrap() = None;
    }

    /// Install a hang that holds until the returned release mutex is unlocked.
    /// Also arms a hang-entered barrier for deterministic cancellation tests.
    pub fn arm_hang(&self, point: FaultPoint) -> Arc<Mutex<()>> {
        let release = Arc::new(Mutex::new(()));
        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.hang_release = Some(release.clone());
            g.hang_entered = Some(entered.clone());
            g.faults.insert(point, InjectedFault::Hang);
            g.fault_remaining.insert(point, 1);
        }
        // Stash entered barrier on the store for wait_for_hang_entered.
        *self.hang_entered_slot.lock().unwrap() = Some(entered);
        release
    }

    /// Wait until the armed hang has been entered (worker blocked at FaultPoint).
    pub fn wait_for_hang_entered(&self, timeout: Duration) -> bool {
        let slot = self.hang_entered_slot.lock().unwrap().clone();
        let Some(entered) = slot else {
            return false;
        };
        let (lock, cv) = &*entered;
        let mut g = lock.lock().unwrap();
        let deadline = std::time::Instant::now() + timeout;
        while !*g {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let (gg, timeout_result) = cv.wait_timeout(g, deadline - now).unwrap();
            g = gg;
            if timeout_result.timed_out() && !*g {
                return false;
            }
        }
        true
    }

    pub fn item_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .items
            .len()
    }

    pub fn contains(&self, service: &str, account: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .items
            .contains_key(&(service.to_owned(), account.to_owned()))
    }

    pub fn put_raw(&self, service: &str, account: &str, bytes: Vec<u8>) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.items
            .insert((service.to_owned(), account.to_owned()), bytes);
    }

    pub fn get_raw(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .items
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
    }

    pub fn remove_raw(&self, service: &str, account: &str) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.items
            .remove(&(service.to_owned(), account.to_owned()))
            .is_some()
    }

    pub fn call_counts(&self) -> (usize, usize, usize) {
        let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        (g.set_calls, g.get_calls, g.delete_calls)
    }

    pub fn arm_get_drop_probe(&self, counter: Arc<AtomicUsize>) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.get_drop_probe = Some(counter);
    }

    fn note_thread(&self) {
        let id = thread::current().id();
        let mut ids = self.thread_ids.lock().unwrap_or_else(|p| p.into_inner());
        if !ids.contains(&id) {
            ids.push(id);
        }
    }

    fn check_fault_at(&self, point: FaultPoint, count_after: usize) -> Result<(), SecureKeyError> {
        // Indexed faults first (exact call count).
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            for slot in g.indexed.iter_mut() {
                if !slot.used && slot.point == point && slot.at_count == count_after {
                    slot.used = true;
                    let fault = slot.fault;
                    let hang_release = g.hang_release.clone();
                    let hang_entered = g.hang_entered.clone();
                    drop(g);
                    return Self::apply_fault(fault, hang_release, hang_entered);
                }
            }
        }
        self.check_fault(point)
    }

    fn check_fault(&self, point: FaultPoint) -> Result<(), SecureKeyError> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let remaining = g.fault_remaining.get(&point).copied().unwrap_or(0);
        if remaining == 0 {
            return Ok(());
        }
        let fault = match g.faults.get(&point).copied() {
            Some(f) => f,
            None => return Ok(()),
        };
        if remaining != usize::MAX {
            let left = remaining - 1;
            if left == 0 {
                g.fault_remaining.remove(&point);
                g.faults.remove(&point);
            } else {
                g.fault_remaining.insert(point, left);
            }
        }
        let hang_release = g.hang_release.clone();
        let hang_entered = g.hang_entered.clone();
        drop(g);
        Self::apply_fault(fault, hang_release, hang_entered)
    }

    fn apply_fault(
        fault: InjectedFault,
        hang_release: Option<Arc<Mutex<()>>>,
        hang_entered: Option<HangEnteredBarrier>,
    ) -> Result<(), SecureKeyError> {
        match fault {
            InjectedFault::Error(kind) => Err(kind.into_error()),
            InjectedFault::Hang => {
                // Signal that the worker has reached the hang point before blocking.
                if let Some(entered) = &hang_entered {
                    let (lock, cv) = &**entered;
                    let mut g = lock.lock().unwrap_or_else(|p| p.into_inner());
                    *g = true;
                    cv.notify_all();
                }
                if let Some(lock) = hang_release {
                    let guard = lock.lock().unwrap_or_else(|p| p.into_inner());
                    drop(guard);
                } else {
                    thread::sleep(Duration::from_secs(60));
                }
                Ok(())
            }
        }
    }
}

impl NativeKeyStore for FakeNativeStore {
    fn set_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SecureKeyError> {
        self.note_thread();
        let next = {
            let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.set_calls + 1
        };
        self.check_fault_at(FaultPoint::BeforeSet, next)?;
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.set_calls += 1;
            g.items
                .insert((service.to_owned(), account.to_owned()), secret.to_vec());
        }
        self.check_fault_at(FaultPoint::AfterSet, next)?;
        Ok(())
    }

    fn get_secret(&self, service: &str, account: &str) -> Result<TempSecret, SecureKeyError> {
        self.note_thread();
        let next = {
            let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.get_calls + 1
        };
        self.check_fault_at(FaultPoint::BeforeGet, next)?;
        let (bytes, probe) = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.get_calls += 1;
            let bytes = g
                .items
                .get(&(service.to_owned(), account.to_owned()))
                .cloned()
                .ok_or_else(|| SecureKeyError::NotFound("fake missing".into()))?;
            (bytes, g.get_drop_probe.clone())
        };
        self.check_fault_at(FaultPoint::AfterGet, next)?;
        if let Some(p) = probe {
            // Count that a temporary secret buffer was produced (zeroized via TempSecret Drop).
            p.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        self.drop_probe_hits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(TempSecret::from_vec(bytes))
    }

    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SecureKeyError> {
        self.note_thread();
        let next = {
            let g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.delete_calls + 1
        };
        self.check_fault_at(FaultPoint::BeforeDelete, next)?;
        {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            g.delete_calls += 1;
            g.items.remove(&(service.to_owned(), account.to_owned()));
        }
        self.check_fault_at(FaultPoint::AfterDelete, next)?;
        Ok(())
    }
}
