use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use killswitch_core::exec_sensor::{
    clear_exec_events, default_process_sensor, get_recent_exec_events,
    simulate_exec_event, ExecEvent, ExecSensorBuffer, NativeProcessSensor,
    SimulatedProcessSensor,
};

#[test]
fn test_exec_event_construction_and_serde() {
    let start_event = ExecEvent::new_start(
        1234,
        5678,
        "C:\\Windows\\System32\\cmd.exe".into(),
        "cmd.exe /c whoami".into(),
        Some(1000),
        Some(0),
    );

    assert!(start_event.is_start());
    assert!(!start_event.is_exit());
    assert_eq!(start_event.pid, 1234);
    assert_eq!(start_event.ppid, 5678);
    assert!(start_event.timestamp_ns > 0);

    let serialized = serde_json::to_string(&start_event).expect("json serialize");
    let deserialized: ExecEvent = serde_json::from_str(&serialized).expect("json deserialize");
    assert_eq!(start_event, deserialized);

    let exit_event = ExecEvent::new_exit(
        1234,
        5678,
        "C:\\Windows\\System32\\cmd.exe".into(),
        "cmd.exe /c whoami".into(),
        1,
    );
    assert!(exit_event.is_exit());
    assert!(!exit_event.is_start());
    assert_eq!(exit_event.exit_code, Some(1));
}

#[test]
fn test_exec_sensor_buffer_fifo_eviction() {
    let capacity = 10;
    let buffer = ExecSensorBuffer::new(capacity);

    for i in 0..25 {
        let event = ExecEvent::new_start(
            i,
            1,
            format!("/bin/proc_{i}"),
            format!("proc_{i}"),
            None,
            None,
        );
        buffer.push(event);
    }

    assert_eq!(buffer.len(), 10);
    let snapshot = buffer.snapshot();
    assert_eq!(snapshot.len(), 10);
    // Oldest surviving should be 15, newest 24
    assert_eq!(snapshot.first().unwrap().pid, 15);
    assert_eq!(snapshot.last().unwrap().pid, 24);

    let recent = buffer.snapshot_recent(3);
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].pid, 24);
    assert_eq!(recent[1].pid, 23);
    assert_eq!(recent[2].pid, 22);
}

#[test]
fn test_exec_sensor_subscriber_lock_drop_and_panic_safety() {
    let buffer = ExecSensorBuffer::new(50);
    let counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&counter);

    // Subscriber 1: normal counter
    buffer.subscribe(Arc::new(move |_event| {
        counter_clone.fetch_add(1, Ordering::SeqCst);
    }));

    // Subscriber 2: intentional panic to test catch_unwind isolation
    buffer.subscribe(Arc::new(|_event| {
        panic!("simulated subscriber panic");
    }));

    // Subscriber 3: another counter after panicking subscriber
    let counter2 = Arc::new(AtomicUsize::new(0));
    let counter2_clone = Arc::clone(&counter2);
    buffer.subscribe(Arc::new(move |_event| {
        counter2_clone.fetch_add(1, Ordering::SeqCst);
    }));

    let event = ExecEvent::new_start(100, 1, "test".into(), "test".into(), None, None);
    buffer.push(event);

    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(counter2.load(Ordering::SeqCst), 1);
}

#[test]
fn test_exec_sensor_multithreaded_concurrent_flood() {
    let buffer = Arc::new(ExecSensorBuffer::new(500));
    let mut handles = Vec::new();

    for t in 0..8 {
        let buf = Arc::clone(&buffer);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let pid = (t * 1000 + i) as u32;
                let event = ExecEvent::new_start(
                    pid,
                    t as u32,
                    format!("/usr/bin/worker_{t}"),
                    format!("worker_{t} run {i}"),
                    None,
                    None,
                );
                buf.push(event);
            }
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    assert_eq!(buffer.len(), 500);
}

#[test]
fn test_global_singleton_and_simulation_hook() {
    clear_exec_events();
    assert_eq!(get_recent_exec_events(10).len(), 0);

    let test_event = ExecEvent::new_start(
        9999,
        8888,
        "/usr/local/bin/claude".into(),
        "claude -p 'analyze'".into(),
        Some(1000),
        Some(1000),
    );

    simulate_exec_event(test_event.clone());
    let recent = get_recent_exec_events(5);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].pid, 9999);
    assert_eq!(recent[0].image_path, "/usr/local/bin/claude");

    clear_exec_events();
    assert_eq!(get_recent_exec_events(10).len(), 0);
}

#[test]
fn test_sensor_lifecycle() {
    let sensor = SimulatedProcessSensor::new();
    assert!(!sensor.is_running());
    sensor.start().expect("sensor start");
    assert!(sensor.is_running());
    sensor.stop();
    assert!(!sensor.is_running());

    let default_sensor = default_process_sensor();
    // Default sensor should be instantiable without error
    assert!(!default_sensor.is_running());
}
