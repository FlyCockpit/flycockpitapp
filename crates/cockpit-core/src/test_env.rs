pub use cockpit_test_support::TestEnvGuard;

pub fn lock() -> TestEnvGuard {
    TestEnvGuard::blocking_lock()
}

pub async fn lock_async() -> TestEnvGuard {
    TestEnvGuard::lock().await
}
