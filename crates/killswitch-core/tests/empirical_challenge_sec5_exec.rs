//! Empirical Adversarial Challenge SEC-5-2 (Part 2):
//! Zero-Polling Kernel Exec Sensor Flood, 32-Thread Concurrency, Lock-Drop Subscriber & FIFO Eviction.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use killswitch_core::exec_sensor::{
    clear_exec_events, get_recent_exec_events, record_exec_event, ExecEvent, ExecSensorBuffer,
    EXEC_SENSOR_DEFAULT_CAPACITY,
};

/// Global test synchronization lock to serialize access to the global singleton
/// `EXEC_SENSOR_BUFFER` across concurrent test runner threads in this integration test binary.
static EXEC_SENSOR_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_exec_sensor_32_thread_concurrent_flood() {
    let _guard = EXEC_SENSOR_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_exec_events();
    let thread_count = 32;
    let events_per_thread = 100; // Total 3,200 events, exceeding default 2048 capacity
    let mut handles = Vec::with_capacity(thread_count);

    let start_barrier = Arc::new(AtomicBool::new(false));

    for t in 0..thread_count {
        let barrier = Arc::clone(&start_barrier);
        handles.push(thread::spawn(move || {
            // Spin until all threads are ready
            while !barrier.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }

            for i in 0..events_per_thread {
                let pid = (t * 1000 + i + 1) as u32;
                let event = ExecEvent::new_start(
                    pid,
                    t as u32,
                    format!("C:\\Windows\\System32\\worker_{t}.exe"),
                    format!("worker_{t}.exe --task {i}"),
                    Some(1000),
                    Some(0),
                );
                record_exec_event(event);
            }
        }));
    }

    let start_time = Instant::now();
    start_barrier.store(true, Ordering::Release);

    for h in handles {
        h.join().expect("thread join without panics");
    }
    let elapsed = start_time.elapsed();

    // Verify completion speed under full 32-thread contention
    assert!(
        elapsed.as_millis() < 2000,
        "32-thread flood must complete within 2000ms, actual: {:?}",
        elapsed
    );

    // Buffer capacity must be strictly capped at 2048
    let recent = get_recent_exec_events(3000);
    assert_eq!(
        recent.len(),
        EXEC_SENSOR_DEFAULT_CAPACITY,
        "Buffer length must equal EXEC_SENSOR_DEFAULT_CAPACITY (2048)"
    );

    // Verify all returned events have valid metadata (no data corruption or races)
    for ev in &recent {
        assert!(ev.pid > 0);
        assert!(!ev.image_path.is_empty());
        assert!(ev.timestamp_ns > 0);
    }

    clear_exec_events();
}

#[test]
fn test_exec_sensor_fifo_exactness_under_pressure() {
    let capacity = 500;
    let buffer = ExecSensorBuffer::new(capacity);
    let total_events = 2500;

    for i in 0..total_events {
        let ev = ExecEvent::new_start(
            i as u32,
            1,
            format!("/usr/bin/proc_{i}"),
            format!("proc_{i} -arg"),
            None,
            None,
        );
        buffer.push(ev);
    }

    assert_eq!(buffer.len(), capacity);
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.len(), capacity);

    // Oldest retained event should be: total_events - capacity = 2500 - 500 = 2000
    assert_eq!(snapshot.first().unwrap().pid, 2000);
    // Newest retained event should be: 2499
    assert_eq!(snapshot.last().unwrap().pid, 2499);

    // Reverse chronological snapshot
    let recent_10 = buffer.snapshot_recent(10);
    assert_eq!(recent_10.len(), 10);
    for (idx, ev) in recent_10.iter().enumerate() {
        assert_eq!(ev.pid, (2499 - idx) as u32);
    }
}

#[test]
fn test_exec_sensor_slow_subscriber_lock_drop_non_blocking() {
    let capacity = 100;
    let buffer = Arc::new(ExecSensorBuffer::new(capacity));
    let slow_subscriber_received = Arc::new(AtomicUsize::new(0));

    // Register a subscriber that simulates slow downstream processing (2ms per event)
    let slow_sub_counter = Arc::clone(&slow_subscriber_received);
    buffer.subscribe(Arc::new(move |_ev| {
        slow_sub_counter.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(1));
    }));

    // Register a fast subscriber that simply counts events
    let fast_counter = Arc::new(AtomicUsize::new(0));
    let fast_sub = Arc::clone(&fast_counter);
    buffer.subscribe(Arc::new(move |_ev| {
        fast_sub.fetch_add(1, Ordering::SeqCst);
    }));

    let num_events = 20;
    let push_start = Instant::now();

    // Pushing 20 events with lock-drop pattern
    for i in 0..num_events {
        let ev = ExecEvent::new_start(i, 1, "test".into(), "test".into(), None, None);
        buffer.push(ev);
    }

    let push_elapsed = push_start.elapsed();
    // Fast subscriber must have received all 20 events
    assert_eq!(fast_counter.load(Ordering::SeqCst), num_events as usize);
    assert_eq!(
        slow_subscriber_received.load(Ordering::SeqCst),
        num_events as usize
    );

    // Even with 1ms delay in slow subscriber, lock-drop allows concurrent buffer snapshots
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.len(), num_events as usize);
    assert!(push_elapsed.as_millis() < 500);
}

#[test]
fn test_exec_sensor_panicking_subscriber_isolation() {
    let buffer = ExecSensorBuffer::new(50);
    let counter_a = Arc::new(AtomicUsize::new(0));
    let counter_c = Arc::new(AtomicUsize::new(0));

    // Subscriber A: normal counter
    let a_clone = Arc::clone(&counter_a);
    buffer.subscribe(Arc::new(move |_| {
        a_clone.fetch_add(1, Ordering::SeqCst);
    }));

    // Subscriber B: intentionally panics
    buffer.subscribe(Arc::new(|_| {
        panic!("Adversarial subscriber deliberate crash!");
    }));

    // Subscriber C: subsequent subscriber
    let c_clone = Arc::clone(&counter_c);
    buffer.subscribe(Arc::new(move |_| {
        c_clone.fetch_add(1, Ordering::SeqCst);
    }));

    // Push 50 events through buffer containing a crashing subscriber
    for i in 0..50 {
        let ev = ExecEvent::new_start(i, 1, "test".into(), "test".into(), None, None);
        buffer.push(ev);
    }

    // Both non-crashing subscribers must have received all 50 events
    assert_eq!(counter_a.load(Ordering::SeqCst), 50);
    assert_eq!(counter_c.load(Ordering::SeqCst), 50);

    // Buffer itself must contain all 50 events without lock poisoning
    assert_eq!(buffer.len(), 50);
}

#[test]
fn test_micro_process_lifecycle_start_and_exit_correlation() {
    let _guard = EXEC_SENSOR_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_exec_events();

    // Simulate 50 ephemeral micro-processes that spawn and terminate in <5ms
    for i in 1..=50 {
        let pid = 10000 + i;
        let start_ev = ExecEvent::new_start(
            pid,
            500,
            "/bin/ephemeral_worker".into(),
            format!("ephemeral_worker --id {i}"),
            Some(1000),
            Some(1000),
        );
        assert!(start_ev.is_start());
        assert!(!start_ev.is_exit());
        record_exec_event(start_ev);

        // Process terminates after quick task
        let exit_ev = ExecEvent::new_exit(
            pid,
            500,
            "/bin/ephemeral_worker".into(),
            format!("ephemeral_worker --id {i}"),
            0,
        );
        assert!(exit_ev.is_exit());
        assert!(!exit_ev.is_start());
        assert_eq!(exit_ev.exit_code, Some(0));
        record_exec_event(exit_ev);
    }

    let events = get_recent_exec_events(100);
    assert_eq!(events.len(), 100);

    // Verify interleaved start and exit events
    let newest = &events[0];
    assert!(newest.is_exit());
    assert_eq!(newest.pid, 10050);

    let second_newest = &events[1];
    assert!(second_newest.is_start());
    assert_eq!(second_newest.pid, 10050);

    clear_exec_events();
}
