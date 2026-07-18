//! Synchronization helpers for long-lived daemon state.

use std::sync::{Mutex, MutexGuard};

pub fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| {
        tracing::error!(
            "recovering from poisoned mutex; daemon state may be inconsistent and restart is recommended"
        );
        err.into_inner()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn poisoned_mutex_recovers_on_next_lock() {
        let mutex = Arc::new(Mutex::new(41));
        let poisoned = mutex.clone();
        let _ = std::thread::spawn(move || {
            let mut guard = poisoned.lock().unwrap();
            *guard = 42;
            panic!("poison test");
        })
        .join();

        let mut guard = lock_or_recover(&mutex);
        assert_eq!(*guard, 42);
        *guard = 43;
        drop(guard);

        assert_eq!(*lock_or_recover(&mutex), 43);
    }
}
