use killswitch_kernel_patcher::privilege::is_elevated;

#[test]
fn test_is_elevated_execution_safety() {
    // 1. Facade delegation invariant: is_elevated() must strictly match the OS platform module output
    let facade_val = is_elevated();

    #[cfg(windows)]
    {
        let platform_val =
            killswitch_kernel_patcher::privilege::windows::is_current_process_elevated();
        assert_eq!(
            facade_val, platform_val,
            "Facade is_elevated() must be identical to Win32 platform implementation"
        );
    }

    #[cfg(unix)]
    {
        let platform_val =
            killswitch_kernel_patcher::privilege::unix::is_current_process_elevated();
        assert_eq!(
            facade_val, platform_val,
            "Facade is_elevated() must be identical to POSIX platform implementation"
        );
    }

    // 2. Sequential stability: multiple invocations must remain consistent without leaking or corrupting token handles
    for _ in 0..10 {
        assert_eq!(
            is_elevated(),
            facade_val,
            "is_elevated() must remain invariant across repeated sequential invocations"
        );
    }
}

#[test]
fn test_is_elevated_thread_safety() {
    let handles: Vec<_> = (0..16).map(|_| std::thread::spawn(is_elevated)).collect();

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.join().expect("thread join failed"));
    }

    let first = results[0];
    for res in results {
        assert_eq!(
            res, first,
            "Concurrent is_elevated calls must be idempotent"
        );
    }
}

#[test]
fn test_is_elevated_idempotency() {
    let r1 = is_elevated();
    let r2 = is_elevated();
    let r3 = is_elevated();
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}
