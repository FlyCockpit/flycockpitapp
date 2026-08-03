pub use cockpit_test_support::TestEnvGuard;

const LARGE_ASYNC_TEST_STACK: usize = 8 * 1024 * 1024;

/// Run a deeply nested async engine test on the same stack size used by
/// Cockpit CLI Tokio workers. Constructing the future inside the spawned
/// thread is intentional: the default libtest worker stack is only 2 MiB.
pub fn run_async_with_large_stack<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    let join = std::thread::Builder::new()
        .name("cockpit-large-stack-test".to_string())
        .stack_size(LARGE_ASYNC_TEST_STACK)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build large-stack test runtime")
                .block_on(test());
        })
        .expect("spawn large-stack test thread")
        .join();
    if let Err(panic) = join {
        std::panic::resume_unwind(panic);
    }
}

pub fn lock() -> TestEnvGuard {
    TestEnvGuard::blocking_lock()
}

pub async fn lock_async() -> TestEnvGuard {
    TestEnvGuard::lock().await
}
