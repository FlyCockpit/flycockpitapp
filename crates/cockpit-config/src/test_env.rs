pub(crate) use cockpit_test_support::TestEnvGuard;

pub(crate) fn lock() -> TestEnvGuard {
    TestEnvGuard::blocking_lock()
}
