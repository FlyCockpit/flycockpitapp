pub(crate) use cockpit_test_support::TestEnvGuard;

pub(crate) fn lock() -> TestEnvGuard {
    TestEnvGuard::blocking_lock()
}

pub(crate) async fn lock_async() -> TestEnvGuard {
    TestEnvGuard::lock().await
}
