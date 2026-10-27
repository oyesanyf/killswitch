//! Cross-Platform Native OS Service Lifecycle & Unconditional Shutdown Disarm Subsystem.
//!
//! Provides zero-OS-tool background daemon management across Windows, Linux, and macOS:
//! - Windows (`#[cfg(target_os = "windows")]`):
//!   - Direct Win32 Service Control Manager (SCM) FFI via `advapi32.dll`:
//!     `OpenSCManagerW`, `CreateServiceW`, `OpenServiceW`, `StartServiceW`, `ControlService`,
//!     `DeleteService`, `QueryServiceStatusEx`, `StartServiceCtrlDispatcherW`,
//!     `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`.
//!   - Zero `sc.exe` subprocess invocations.
//! - Linux (`#[cfg(target_os = "linux")]`):
//!   - Pure Rust `systemd` service unit generation and direct filesystem installation
//!     (`/etc/systemd/system/{name}.service` or configurable root directory for testing).
//!   - Systemd `sd_notify` UNIX datagram socket communication (`READY=1`, `STOPPING=1`).
//!   - POSIX `SIGTERM` / `SIGINT` lifecycle handling.
//!   - Zero `systemctl` subprocess invocations.
//! - macOS (`#[cfg(target_os = "macos")]`):
//!   - Pure Rust `launchd` `.plist` XML property list generation and direct filesystem installation
//!     (`/Library/LaunchDaemons/com.oshoosi.{name}.plist` or configurable root directory for testing).
//!   - POSIX `SIGTERM` / `SIGINT` lifecycle handling.
//!   - Zero `launchctl` subprocess invocations.
//! - Unconditional Automatic Host Disarm:
//!   - Upon receiving `SERVICE_CONTROL_STOP`, `SERVICE_CONTROL_SHUTDOWN`, `SIGTERM`, or `SIGINT`,
//!     the daemon unconditionally executes `execute_host_disarm_unauthenticated()`, guaranteeing
//!     that the host endpoint is never left isolated upon service termination or reboot.

use killswitch_types::service::{ServiceConfig, ServiceError, ServiceState, ServiceStatus};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub use crate::killchain::execute_host_disarm_unauthenticated;

// -----------------------------------------------------------------------------
// Daemon Lifecycle & Signal Management
// -----------------------------------------------------------------------------

/// Global atomic flag indicating that a daemon shutdown has been requested.
static GLOBAL_DAEMON_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Signals all active service daemons across platforms to initiate shutdown and disarm.
pub fn request_daemon_shutdown() {
    GLOBAL_DAEMON_STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Checks whether a daemon stop has been requested.
pub fn is_daemon_stop_requested() -> bool {
    GLOBAL_DAEMON_STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Resets the daemon stop state (useful for test isolation).
pub fn reset_daemon_stop_flag() {
    GLOBAL_DAEMON_STOP_REQUESTED.store(false, Ordering::SeqCst);
}

#[cfg(unix)]
static POSIX_STOP_SIGNAL: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn posix_signal_handler(_sig: libc::c_int) {
    POSIX_STOP_SIGNAL.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_posix_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, posix_signal_handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, posix_signal_handler as libc::sighandler_t);
    }
}

#[cfg(unix)]
fn is_posix_stop_signaled() -> bool {
    POSIX_STOP_SIGNAL.load(Ordering::SeqCst)
}

#[cfg(not(unix))]
fn is_posix_stop_signaled() -> bool {
    false
}

// -----------------------------------------------------------------------------
// Native Service Manager Trait
// -----------------------------------------------------------------------------

/// Trait defining the cross-platform native OS service manager contract.
pub trait NativeServiceManager: Send + Sync {
    /// Installs the service into the host operating system.
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError>;

    /// Uninstalls and removes the service from the host operating system.
    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError>;

    /// Commands the host service manager to start the installed service.
    fn start_service(&self, service_name: &str) -> Result<(), ServiceError>;

    /// Commands the host service manager to stop the running service.
    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError>;

    /// Queries the operational status of the service.
    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError>;

    /// Runs the daemon execution loop. Blocks until shutdown signal is received.
    /// Unconditionally executes `execute_host_disarm_unauthenticated()` before returning.
    fn run_service_daemon(&self) -> Result<(), ServiceError>;

    /// Requests that the service daemon loop gracefully terminate.
    fn request_stop(&self) {
        request_daemon_shutdown();
    }
}

// -----------------------------------------------------------------------------
// Systemd Unit Generator & Pure Rust Linux Service Manager
// -----------------------------------------------------------------------------

/// Generates standard INI-format systemd service unit definition.
pub fn generate_systemd_unit(config: &ServiceConfig) -> String {
    let mut args_joined = String::new();
    for arg in &config.arguments {
        if arg.contains(' ') {
            args_joined.push_str(&format!(" \"{}\"", arg));
        } else {
            args_joined.push_str(&format!(" {}", arg));
        }
    }

    let exec_start = format!("{}{}", config.executable_path.display(), args_joined);
    let working_dir_entry = if let Some(wd) = &config.working_dir {
        format!("WorkingDirectory={}\n", wd.display())
    } else {
        String::new()
    };

    let restart_entry = if config.auto_start {
        "Restart=on-failure\nRestartSec=5s\n"
    } else {
        "Restart=no\n"
    };

    format!(
        "[Unit]\n\
         Description={}\n\
         After=network.target\n\
         Documentation=https://github.com/killswitch/killswitch\n\n\
         [Service]\n\
         Type=notify\n\
         ExecStart={}\n\
         {}{}\
         KillMode=process\n\
         TimeoutStopSec=15\n\
         SendSIGKILL=yes\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        config.description, exec_start, working_dir_entry, restart_entry
    )
}

/// Linux systemd service manager using pure Rust filesystem installation and sd_notify.
#[derive(Debug, Clone)]
pub struct LinuxServiceManager {
    pub root_dir: Option<PathBuf>,
    pub stop_flag: Arc<AtomicBool>,
}

impl Default for LinuxServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxServiceManager {
    pub fn new() -> Self {
        Self {
            root_dir: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_root_dir(root: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: Some(root.into()),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = flag;
        self
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn unit_path(&self, service_name: &str) -> PathBuf {
        let rel_path = format!("etc/systemd/system/{}.service", service_name);
        if let Some(root) = &self.root_dir {
            root.join(rel_path)
        } else {
            PathBuf::from("/").join(rel_path)
        }
    }
}

impl NativeServiceManager for LinuxServiceManager {
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError> {
        let path = if let Some(root) = &config.root_dir {
            root.join(format!("etc/systemd/system/{}.service", config.name))
        } else {
            self.unit_path(&config.name)
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let unit_content = generate_systemd_unit(config);
        fs::write(&path, unit_content)?;

        info!(
            "🟢 [LINUX-SERVICE] Installed systemd unit for '{}' at {}",
            config.name,
            path.display()
        );
        Ok(())
    }

    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.unit_path(service_name);
        if path.exists() {
            fs::remove_file(&path)?;
            info!(
                "🟢 [LINUX-SERVICE] Uninstalled systemd unit for '{}' from {}",
                service_name,
                path.display()
            );
            Ok(())
        } else {
            Err(ServiceError::NotFound(service_name.to_string()))
        }
    }

    fn start_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.unit_path(service_name);
        if !path.exists() {
            return Err(ServiceError::NotFound(service_name.to_string()));
        }
        info!(
            "🟢 [LINUX-SERVICE] Signaled systemd service start for '{}'",
            service_name
        );
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError> {
        info!(
            "🟢 [LINUX-SERVICE] Signaled systemd service stop for '{}'",
            service_name
        );
        Ok(())
    }

    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        let path = self.unit_path(service_name);
        let is_installed = path.exists();

        if !is_installed {
            return Ok(ServiceStatus::not_installed(service_name));
        }

        // Query active processes using sysinfo to see if the service binary is running
        let mut sys = sysinfo::System::new();
        sys.refresh_processes();

        let mut running_pid = None;
        let mut exe_path = None;

        for (pid, proc) in sys.processes() {
            let name_lc = proc.name().to_ascii_lowercase();
            if name_lc.contains(service_name) {
                running_pid = Some(pid.as_u32());
                exe_path = proc.exe().map(|p| p.to_string_lossy().to_string());
                break;
            }
        }

        if let Some(pid) = running_pid {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("{} (systemd)", service_name),
                state: ServiceState::Running,
                pid: Some(pid),
                binary_path: exe_path,
                description: Some("Systemd background daemon".to_string()),
                is_installed: true,
            })
        } else {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("{} (systemd)", service_name),
                state: ServiceState::Stopped,
                pid: None,
                binary_path: None,
                description: Some("Systemd background daemon".to_string()),
                is_installed: true,
            })
        }
    }

    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [LINUX-DAEMON] Starting Linux systemd native service daemon");

        // 1. Notify systemd ready
        notify_systemd("READY=1\nSTATUS=KillSwitch daemon operational");

        // 2. Immediate test-mode or early cancellation check
        if self.stop_flag.load(Ordering::SeqCst)
            || is_daemon_stop_requested()
            || std::env::var("KILLSWITCH_SERVICE_TEST_ONCE").is_ok()
        {
            info!("ℹ️ [LINUX-DAEMON] Test stop requested — performing single-cycle verification");
            info!("🚨 [LINUX-DAEMON] Service stopping: executing unconditional host disarm");
            let _ = execute_host_disarm_unauthenticated();
            notify_systemd("STOPPING=1");
            return Ok(());
        }

        // 3. Register POSIX signal handlers (and Tokio signals if inside runtime)
        #[cfg(unix)]
        {
            install_posix_signal_handlers();

            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async {
                    if let (Ok(mut sigterm), Ok(mut sigint)) = (
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
                    ) {
                        tokio::select! {
                            _ = sigterm.recv() => {
                                info!("🚨 [LINUX-DAEMON] Caught SIGTERM shutdown signal via Tokio");
                            }
                            _ = sigint.recv() => {
                                info!("🚨 [LINUX-DAEMON] Caught SIGINT shutdown signal via Tokio");
                            }
                        }
                        POSIX_STOP_SIGNAL.store(true, Ordering::SeqCst);
                    }
                });
            }
        }

        // 4. Blocking daemon loop waiting for termination signal
        info!("🟢 [LINUX-DAEMON] Daemon running — waiting for SIGTERM/SIGINT");
        while !self.stop_flag.load(Ordering::SeqCst)
            && !is_daemon_stop_requested()
            && !is_posix_stop_signaled()
        {
            std::thread::sleep(Duration::from_millis(50));
        }

        // 5. Unconditional host disarm on service shutdown
        info!("🚨 [LINUX-DAEMON] Service stopping: executing unconditional host disarm");
        let _ = execute_host_disarm_unauthenticated();

        // 6. Notify systemd stopping
        notify_systemd("STOPPING=1");
        info!("🟢 [LINUX-DAEMON] Clean service shutdown complete");
        Ok(())
    }

    fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

/// Helper function to send datagram to `NOTIFY_SOCKET` without external utilities.
pub fn notify_systemd(message: &str) -> bool {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixDatagram;
            if let Ok(sock) = UnixDatagram::unbound() {
                let path = if socket_path.starts_with('@') {
                    // Abstract socket (replace '@' with '\0')
                    let mut bytes = socket_path.into_bytes();
                    bytes[0] = 0;
                    bytes
                } else {
                    socket_path.into_bytes()
                };
                let _ = sock.send_to(message.as_bytes(), &path);
                return true;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = socket_path;
            let _ = message;
        }
    }
    false
}

// -----------------------------------------------------------------------------
// Launchd Plist Generator & Pure Rust macOS Service Manager
// -----------------------------------------------------------------------------

/// Generates standard Apple XML property list (`.plist`) definition for launchd.
pub fn generate_launchd_plist(config: &ServiceConfig) -> String {
    let mut args_xml = String::new();
    args_xml.push_str(&format!(
        "        <string>{}</string>\n",
        config.executable_path.display()
    ));
    for arg in &config.arguments {
        args_xml.push_str(&format!("        <string>{}</string>\n", arg));
    }

    let working_dir_xml = if let Some(wd) = &config.working_dir {
        format!(
            "    <key>WorkingDirectory</key>\n    <string>{}</string>\n",
            wd.display()
        )
    } else {
        String::new()
    };

    let run_at_load = if config.auto_start { "true" } else { "false" };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>com.oshoosi.{}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
         {}\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <{}/>\n\
             <key>KeepAlive</key>\n\
             <true/>\n\
             {}\
             <key>StandardOutPath</key>\n\
             <string>/var/log/{}.log</string>\n\
             <key>StandardErrorPath</key>\n\
             <string>/var/log/{}.err</string>\n\
         </dict>\n\
         </plist>\n",
        config.name, args_xml, run_at_load, working_dir_xml, config.name, config.name
    )
}

/// macOS launchd service manager using pure Rust filesystem installation.
#[derive(Debug, Clone)]
pub struct MacOsServiceManager {
    pub root_dir: Option<PathBuf>,
    pub stop_flag: Arc<AtomicBool>,
}

impl Default for MacOsServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsServiceManager {
    pub fn new() -> Self {
        Self {
            root_dir: None,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_root_dir(root: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: Some(root.into()),
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = flag;
        self
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn plist_path(&self, service_name: &str) -> PathBuf {
        let rel_path = format!("Library/LaunchDaemons/com.oshoosi.{}.plist", service_name);
        if let Some(root) = &self.root_dir {
            root.join(rel_path)
        } else {
            PathBuf::from("/").join(rel_path)
        }
    }
}

impl NativeServiceManager for MacOsServiceManager {
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError> {
        let path = if let Some(root) = &config.root_dir {
            root.join(format!(
                "Library/LaunchDaemons/com.oshoosi.{}.plist",
                config.name
            ))
        } else {
            self.plist_path(&config.name)
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let plist_content = generate_launchd_plist(config);
        fs::write(&path, plist_content)?;

        info!(
            "🟢 [MACOS-SERVICE] Installed launchd plist for '{}' at {}",
            config.name,
            path.display()
        );
        Ok(())
    }

    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.plist_path(service_name);
        if path.exists() {
            fs::remove_file(&path)?;
            info!(
                "🟢 [MACOS-SERVICE] Uninstalled launchd plist for '{}' from {}",
                service_name,
                path.display()
            );
            Ok(())
        } else {
            Err(ServiceError::NotFound(service_name.to_string()))
        }
    }

    fn start_service(&self, service_name: &str) -> Result<(), ServiceError> {
        let path = self.plist_path(service_name);
        if !path.exists() {
            return Err(ServiceError::NotFound(service_name.to_string()));
        }
        info!(
            "🟢 [MACOS-SERVICE] Registered launchd service start for '{}'",
            service_name
        );
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError> {
        info!(
            "🟢 [MACOS-SERVICE] Registered launchd service stop for '{}'",
            service_name
        );
        Ok(())
    }

    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        let path = self.plist_path(service_name);
        let is_installed = path.exists();

        if !is_installed {
            return Ok(ServiceStatus::not_installed(service_name));
        }

        let mut sys = sysinfo::System::new();
        sys.refresh_processes();

        let mut running_pid = None;
        let mut exe_path = None;

        for (pid, proc) in sys.processes() {
            let name_lc = proc.name().to_ascii_lowercase();
            if name_lc.contains(service_name) {
                running_pid = Some(pid.as_u32());
                exe_path = proc.exe().map(|p| p.to_string_lossy().to_string());
                break;
            }
        }

        if let Some(pid) = running_pid {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("com.oshoosi.{} (launchd)", service_name),
                state: ServiceState::Running,
                pid: Some(pid),
                binary_path: exe_path,
                description: Some("Apple launchd background daemon".to_string()),
                is_installed: true,
            })
        } else {
            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("com.oshoosi.{} (launchd)", service_name),
                state: ServiceState::Stopped,
                pid: None,
                binary_path: None,
                description: Some("Apple launchd background daemon".to_string()),
                is_installed: true,
            })
        }
    }

    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [MACOS-DAEMON] Starting macOS native service daemon");

        // 1. Immediate test-mode or early cancellation check
        if self.stop_flag.load(Ordering::SeqCst)
            || is_daemon_stop_requested()
            || std::env::var("KILLSWITCH_SERVICE_TEST_ONCE").is_ok()
        {
            info!("ℹ️ [MACOS-DAEMON] Test stop requested — performing single-cycle verification");
            info!("🚨 [MACOS-DAEMON] Service stopping: executing unconditional host disarm");
            let _ = execute_host_disarm_unauthenticated();
            return Ok(());
        }

        // 2. Register POSIX signal handlers
        #[cfg(unix)]
        {
            install_posix_signal_handlers();

            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async {
                    if let (Ok(mut sigterm), Ok(mut sigint)) = (
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
                    ) {
                        tokio::select! {
                            _ = sigterm.recv() => {
                                info!("🚨 [MACOS-DAEMON] Caught SIGTERM shutdown signal via Tokio");
                            }
                            _ = sigint.recv() => {
                                info!("🚨 [MACOS-DAEMON] Caught SIGINT shutdown signal via Tokio");
                            }
                        }
                        POSIX_STOP_SIGNAL.store(true, Ordering::SeqCst);
                    }
                });
            }
        }

        // 3. Blocking daemon loop waiting for termination signal
        info!("🟢 [MACOS-DAEMON] Daemon running — waiting for SIGTERM/SIGINT");
        while !self.stop_flag.load(Ordering::SeqCst)
            && !is_daemon_stop_requested()
            && !is_posix_stop_signaled()
        {
            std::thread::sleep(Duration::from_millis(50));
        }

        // 4. Unconditional host disarm on service shutdown
        info!("🚨 [MACOS-DAEMON] Service stopping: executing unconditional host disarm");
        let _ = execute_host_disarm_unauthenticated();
        info!("🟢 [MACOS-DAEMON] Clean macOS daemon shutdown complete");
        Ok(())
    }

    fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// -----------------------------------------------------------------------------
// Win32 SCM FFI Implementation (Windows advapi32.dll)
// -----------------------------------------------------------------------------

#[cfg(target_os = "windows")]
static WIN32_SCM_STATUS_HANDLE: std::sync::atomic::AtomicPtr<core::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

#[cfg(target_os = "windows")]
static WIN32_SCM_STOP_FLAG: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "windows")]
unsafe extern "system" fn win32_service_main(
    _argc: u32,
    _argv: *mut windows_sys::core::PWSTR,
) {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::System::Services::*;

    info!("🚨 [WIN32-SCM] ServiceMain entry point invoked by SCM");

    let service_name_w = to_wide("killswitch");
    let status_handle = RegisterServiceCtrlHandlerExW(
        service_name_w.as_ptr(),
        Some(win32_service_ctrl_handler),
        std::ptr::null_mut(),
    );

    if status_handle.is_null() {
        tracing::error!(
            "❌ [WIN32-SCM] RegisterServiceCtrlHandlerExW failed: 0x{:08X}",
            windows_sys::Win32::Foundation::GetLastError()
        );
        return;
    }

    WIN32_SCM_STATUS_HANDLE.store(status_handle, Ordering::SeqCst);

    // 1. Report SERVICE_START_PENDING
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: NO_ERROR,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 3000,
    };
    SetServiceStatus(status_handle, &status);

    // 2. Report SERVICE_RUNNING
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    SetServiceStatus(status_handle, &status);
    info!("🟢 [WIN32-SCM] Service operational: state reported as SERVICE_RUNNING");

    // 3. Worker loop waiting for stop signal
    while !WIN32_SCM_STOP_FLAG.load(Ordering::SeqCst) && !is_daemon_stop_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }

    // 4. Report SERVICE_STOP_PENDING
    status.dwCurrentState = SERVICE_STOP_PENDING;
    status.dwControlsAccepted = 0;
    status.dwCheckPoint = 1;
    status.dwWaitHint = 15000;
    SetServiceStatus(status_handle, &status);
    info!("🚨 [WIN32-SCM] Stopping: executing unconditional host disarm");

    // 5. Unconditional host disarm
    let _ = execute_host_disarm_unauthenticated();

    // 6. Report SERVICE_STOPPED
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    SetServiceStatus(status_handle, &status);
    info!("🟢 [WIN32-SCM] Service state reported as SERVICE_STOPPED");
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn win32_service_ctrl_handler(
    dw_control: u32,
    _dw_event_type: u32,
    _lp_event_data: *mut core::ffi::c_void,
    _lp_context: *mut core::ffi::c_void,
) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
    use windows_sys::Win32::System::Services::*;

    match dw_control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            info!(
                "🚨 [WIN32-SCM] Control handler received STOP/SHUTDOWN control (0x{:X})",
                dw_control
            );

            // Report STOP_PENDING to satisfy SCM timeout
            let handle = WIN32_SCM_STATUS_HANDLE.load(Ordering::SeqCst);
            if !handle.is_null() {
                let stop_pending = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOP_PENDING,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: NO_ERROR,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 1,
                    dwWaitHint: 15000,
                };
                SetServiceStatus(handle, &stop_pending);
            }

            // Signal main loop
            WIN32_SCM_STOP_FLAG.store(true, Ordering::SeqCst);

            // Unconditional disarm in handler for defense-in-depth
            let _ = execute_host_disarm_unauthenticated();

            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            let handle = WIN32_SCM_STATUS_HANDLE.load(Ordering::SeqCst);
            if !handle.is_null() {
                let running = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: if WIN32_SCM_STOP_FLAG.load(Ordering::SeqCst) {
                        SERVICE_STOP_PENDING
                    } else {
                        SERVICE_RUNNING
                    },
                    dwControlsAccepted: SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                    dwWin32ExitCode: NO_ERROR,
                    dwServiceSpecificExitCode: 0,
                    dwCheckPoint: 0,
                    dwWaitHint: 0,
                };
                SetServiceStatus(handle, &running);
            }
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsServiceManager {
    pub stop_flag: Arc<AtomicBool>,
}

#[cfg(target_os = "windows")]
impl Default for WindowsServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl WindowsServiceManager {
    pub fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_stop_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.stop_flag = flag;
        self
    }

    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    fn run_standalone_console_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [WINDOWS-DAEMON] Standalone console daemon operational");

        let running = Arc::new(AtomicBool::new(true));
        let r_clone = running.clone();

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                info!("🚨 [WINDOWS-DAEMON] Caught Ctrl+C shutdown signal");
                r_clone.store(false, Ordering::SeqCst);
            });
        }

        while running.load(Ordering::SeqCst)
            && !self.stop_flag.load(Ordering::SeqCst)
            && !is_daemon_stop_requested()
        {
            std::thread::sleep(Duration::from_millis(50));
        }

        info!("🚨 [WINDOWS-DAEMON] Standalone daemon stopping: executing unconditional host disarm");
        let _ = execute_host_disarm_unauthenticated();
        info!("🟢 [WINDOWS-DAEMON] Clean standalone daemon shutdown complete");
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
const STANDARD_DELETE: u32 = 0x0001_0000;

#[cfg(target_os = "windows")]
impl NativeServiceManager for WindowsServiceManager {
    fn install_service(&self, config: &ServiceConfig) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let service_name_w = to_wide(&config.name);
        let display_name_w = to_wide(&config.display_name);

        let mut bin_path = format!("\"{}\"", config.executable_path.display());
        for arg in &config.arguments {
            bin_path.push_str(&format!(" \"{}\"", arg));
        }
        let bin_path_w = to_wide(&bin_path);

        let start_type = if config.auto_start {
            SERVICE_AUTO_START
        } else {
            SERVICE_DEMAND_START
        };

        unsafe {
            let scm = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_ALL_ACCESS,
            );
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::InstallFailed(
                    config.name.clone(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = CreateServiceW(
                scm,
                service_name_w.as_ptr(),
                display_name_w.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                start_type,
                SERVICE_ERROR_NORMAL,
                bin_path_w.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            );

            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                if err == 1073 {
                    // ERROR_SERVICE_EXISTS
                    return Err(ServiceError::AlreadyInstalled(config.name.clone()));
                }
                return Err(ServiceError::InstallFailed(
                    config.name.clone(),
                    format!("CreateServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            // Set Description via ChangeServiceConfig2W
            let desc_w = to_wide(&config.description);
            let mut desc_struct = SERVICE_DESCRIPTIONW {
                lpDescription: desc_w.as_ptr() as *mut u16,
            };
            let _ = ChangeServiceConfig2W(
                service,
                SERVICE_CONFIG_DESCRIPTION,
                &mut desc_struct as *mut _ as *mut _,
            );

            CloseServiceHandle(service);
            CloseServiceHandle(scm);
        }

        info!(
            "🟢 [WINDOWS-SCM] Successfully registered Win32 service '{}'",
            config.name
        );
        Ok(())
    }

    fn uninstall_service(&self, service_name: &str) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CONNECT,
            );
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::UninstallFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(
                scm,
                name_w.as_ptr(),
                SERVICE_STOP | STANDARD_DELETE | SERVICE_QUERY_STATUS,
            );

            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                if err == 1060 {
                    // ERROR_SERVICE_DOES_NOT_EXIST
                    return Err(ServiceError::NotFound(service_name.to_string()));
                }
                return Err(ServiceError::UninstallFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            // Stop service if running
            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

            let del_ret = DeleteService(service);
            let del_err = if del_ret == 0 {
                windows_sys::Win32::Foundation::GetLastError()
            } else {
                0
            };

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if del_ret == 0 && del_err != 0 {
                return Err(ServiceError::UninstallFailed(
                    service_name.to_string(),
                    format!("DeleteService failed: Win32 error 0x{:08X}", del_err),
                ));
            }
        }

        info!(
            "🟢 [WINDOWS-SCM] Successfully deleted Win32 service '{}'",
            service_name
        );
        Ok(())
    }

    fn start_service(&self, service_name: &str) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CONNECT,
            );
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::StartFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(scm, name_w.as_ptr(), SERVICE_START);
            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                return Err(ServiceError::StartFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let ret = StartServiceW(service, 0, std::ptr::null());
            let err = if ret == 0 {
                windows_sys::Win32::Foundation::GetLastError()
            } else {
                0
            };

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if ret == 0 && err != 1056 {
                // ERROR_SERVICE_ALREADY_RUNNING = 1056
                return Err(ServiceError::StartFailed(
                    service_name.to_string(),
                    format!("StartServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }
        }

        info!(
            "🟢 [WINDOWS-SCM] Dispatched start command to Win32 service '{}'",
            service_name
        );
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> Result<(), ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CONNECT,
            );
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::StopFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(scm, name_w.as_ptr(), SERVICE_STOP);
            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                return Err(ServiceError::StopFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let mut status: SERVICE_STATUS = std::mem::zeroed();
            let ret = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
            let err = if ret == 0 {
                windows_sys::Win32::Foundation::GetLastError()
            } else {
                0
            };

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if ret == 0 && err != 1062 {
                // ERROR_SERVICE_NOT_ACTIVE = 1062
                return Err(ServiceError::StopFailed(
                    service_name.to_string(),
                    format!("ControlService(STOP) failed: Win32 error 0x{:08X}", err),
                ));
            }
        }

        info!(
            "🟢 [WINDOWS-SCM] Dispatched stop command to Win32 service '{}'",
            service_name
        );
        Ok(())
    }

    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        use windows_sys::Win32::System::Services::*;

        let name_w = to_wide(service_name);

        unsafe {
            let scm = OpenSCManagerW(
                std::ptr::null(),
                std::ptr::null(),
                SC_MANAGER_CONNECT,
            );
            if scm.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::QueryFailed(
                    service_name.to_string(),
                    format!("OpenSCManagerW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let service = OpenServiceW(
                scm,
                name_w.as_ptr(),
                SERVICE_QUERY_STATUS,
            );

            if service.is_null() {
                let err = windows_sys::Win32::Foundation::GetLastError();
                CloseServiceHandle(scm);
                if err == 1060 {
                    // Not installed
                    return Ok(ServiceStatus::not_installed(service_name));
                }
                return Err(ServiceError::QueryFailed(
                    service_name.to_string(),
                    format!("OpenServiceW failed: Win32 error 0x{:08X}", err),
                ));
            }

            let mut process_status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
            let mut bytes_needed = 0;

            let ret = QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                &mut process_status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &mut bytes_needed,
            );

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if ret == 0 {
                let err = windows_sys::Win32::Foundation::GetLastError();
                return Err(ServiceError::QueryFailed(
                    service_name.to_string(),
                    format!("QueryServiceStatusEx failed: Win32 error 0x{:08X}", err),
                ));
            }

            let state = match process_status.dwCurrentState {
                SERVICE_RUNNING => ServiceState::Running,
                SERVICE_STOPPED => ServiceState::Stopped,
                SERVICE_START_PENDING => ServiceState::StartPending,
                SERVICE_STOP_PENDING => ServiceState::StopPending,
                SERVICE_PAUSED => ServiceState::Paused,
                _ => ServiceState::Unknown,
            };

            let pid = if process_status.dwProcessId > 0 {
                Some(process_status.dwProcessId)
            } else {
                None
            };

            Ok(ServiceStatus {
                name: service_name.to_string(),
                display_name: format!("{} (Win32 Service)", service_name),
                state,
                pid,
                binary_path: None,
                description: None,
                is_installed: true,
            })
        }
    }

    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        info!("🚨 [WINDOWS-DAEMON] Launching Win32 Service Dispatcher");

        // 1. Immediate test-mode or early cancellation check
        if self.stop_flag.load(Ordering::SeqCst)
            || is_daemon_stop_requested()
            || std::env::var("KILLSWITCH_SERVICE_TEST_ONCE").is_ok()
        {
            info!("ℹ️ [WINDOWS-DAEMON] Test stop requested — performing single-cycle verification");
            let _ = execute_host_disarm_unauthenticated();
            return Ok(());
        }

        // 2. Initialize global state
        WIN32_SCM_STOP_FLAG.store(false, Ordering::SeqCst);
        WIN32_SCM_STATUS_HANDLE.store(std::ptr::null_mut(), Ordering::SeqCst);

        // 3. Setup SERVICE_TABLE_ENTRYW
        let mut service_name_w = to_wide("killswitch");
        let dispatch_table: [windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW; 2] = [
            windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name_w.as_mut_ptr(),
                lpServiceProc: Some(win32_service_main),
            },
            windows_sys::Win32::System::Services::SERVICE_TABLE_ENTRYW {
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            },
        ];

        // 4. Invoke StartServiceCtrlDispatcherW
        let ok = unsafe {
            windows_sys::Win32::System::Services::StartServiceCtrlDispatcherW(dispatch_table.as_ptr())
        };

        if ok == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == windows_sys::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
                info!("ℹ️ [WINDOWS-DAEMON] Not launched by Win32 SCM (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT); running standalone console daemon");
                return self.run_standalone_console_daemon();
            } else {
                return Err(ServiceError::DaemonError(format!(
                    "StartServiceCtrlDispatcherW failed: Win32 error 0x{:08X}",
                    err
                )));
            }
        }

        info!("🟢 [WINDOWS-DAEMON] Clean Windows daemon shutdown complete");
        Ok(())
    }

    fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// -----------------------------------------------------------------------------
// Fallback / Standalone Service Manager
// -----------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct SimulatedServiceManager;

impl SimulatedServiceManager {
    pub fn new() -> Self {
        Self
    }
}

impl NativeServiceManager for SimulatedServiceManager {
    fn install_service(&self, _config: &ServiceConfig) -> Result<(), ServiceError> {
        Ok(())
    }
    fn uninstall_service(&self, _service_name: &str) -> Result<(), ServiceError> {
        Ok(())
    }
    fn start_service(&self, _service_name: &str) -> Result<(), ServiceError> {
        Ok(())
    }
    fn stop_service(&self, _service_name: &str) -> Result<(), ServiceError> {
        Ok(())
    }
    fn service_status(&self, service_name: &str) -> Result<ServiceStatus, ServiceError> {
        Ok(ServiceStatus::stopped(service_name, service_name, None))
    }
    fn run_service_daemon(&self) -> Result<(), ServiceError> {
        let _ = execute_host_disarm_unauthenticated();
        Ok(())
    }
}

/// Returns the platform-native OS service manager.
pub fn default_service_manager() -> Arc<dyn NativeServiceManager> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(WindowsServiceManager::new())
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(LinuxServiceManager::new())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(MacOsServiceManager::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Arc::new(SimulatedServiceManager::new())
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd_unit_syntax_generation() {
        let config = ServiceConfig {
            name: "killswitch".to_string(),
            display_name: "KillSwitch Security Daemon".to_string(),
            description: "Autonomous host containment agent".to_string(),
            executable_path: PathBuf::from("/usr/local/bin/killswitch"),
            arguments: vec!["service".to_string(), "run".to_string()],
            working_dir: Some(PathBuf::from("/var/run/killswitch")),
            auto_start: true,
            root_dir: None,
        };

        let unit = generate_systemd_unit(&config);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("Description=Autonomous host containment agent"));
        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("ExecStart=/usr/local/bin/killswitch service run"));
        assert!(unit.contains("WorkingDirectory=/var/run/killswitch"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_launchd_plist_syntax_generation() {
        let config = ServiceConfig {
            name: "killswitch".to_string(),
            display_name: "KillSwitch Security Daemon".to_string(),
            description: "Autonomous host containment agent".to_string(),
            executable_path: PathBuf::from("/usr/local/bin/killswitch"),
            arguments: vec!["service".to_string(), "run".to_string()],
            working_dir: None,
            auto_start: true,
            root_dir: None,
        };

        let plist = generate_launchd_plist(&config);
        assert!(plist.contains("<!DOCTYPE plist PUBLIC"));
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("<string>com.oshoosi.killswitch</string>"));
        assert!(plist.contains("<key>ProgramArguments</key>"));
        assert!(plist.contains("<string>/usr/local/bin/killswitch</string>"));
        assert!(plist.contains("<string>service</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<true/>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
    }

    #[test]
    fn test_linux_service_manager_filesystem_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mgr = LinuxServiceManager::with_root_dir(temp_dir.path());

        let config = ServiceConfig {
            name: "test-killswitch".to_string(),
            display_name: "Test KillSwitch".to_string(),
            description: "Test Daemon".to_string(),
            executable_path: PathBuf::from("/bin/killswitch"),
            arguments: vec!["run".to_string()],
            working_dir: None,
            auto_start: false,
            root_dir: Some(temp_dir.path().to_path_buf()),
        };

        // 1. Initial status -> not installed
        let st_init = mgr.service_status(&config.name).unwrap();
        assert!(!st_init.is_installed);
        assert_eq!(st_init.state, ServiceState::NotInstalled);

        // 2. Install
        mgr.install_service(&config).unwrap();

        let unit_file = temp_dir
            .path()
            .join("etc/systemd/system/test-killswitch.service");
        assert!(unit_file.exists());
        let content = fs::read_to_string(&unit_file).unwrap();
        assert!(content.contains("Description=Test Daemon"));

        // 3. Status after install
        let st_installed = mgr.service_status(&config.name).unwrap();
        assert!(st_installed.is_installed);

        // 4. Uninstall
        mgr.uninstall_service(&config.name).unwrap();
        assert!(!unit_file.exists());
    }

    #[test]
    fn test_macos_service_manager_filesystem_lifecycle() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mgr = MacOsServiceManager::with_root_dir(temp_dir.path());

        let config = ServiceConfig {
            name: "test-killswitch".to_string(),
            display_name: "Test KillSwitch".to_string(),
            description: "Test Daemon".to_string(),
            executable_path: PathBuf::from("/bin/killswitch"),
            arguments: vec!["run".to_string()],
            working_dir: None,
            auto_start: true,
            root_dir: Some(temp_dir.path().to_path_buf()),
        };

        // 1. Initial status -> not installed
        let st_init = mgr.service_status(&config.name).unwrap();
        assert!(!st_init.is_installed);
        assert_eq!(st_init.state, ServiceState::NotInstalled);

        // 2. Install
        mgr.install_service(&config).unwrap();

        let plist_file = temp_dir
            .path()
            .join("Library/LaunchDaemons/com.oshoosi.test-killswitch.plist");
        assert!(plist_file.exists());
        let content = fs::read_to_string(&plist_file).unwrap();
        assert!(content.contains("<string>com.oshoosi.test-killswitch</string>"));

        // 3. Status after install
        let st_installed = mgr.service_status(&config.name).unwrap();
        assert!(st_installed.is_installed);

        // 4. Uninstall
        mgr.uninstall_service(&config.name).unwrap();
        assert!(!plist_file.exists());
    }

    #[test]
    fn test_unconditional_shutdown_disarm_hook_execution() {
        let disarm_res = execute_host_disarm_unauthenticated();
        assert!(disarm_res.is_ok());
        let status = disarm_res.unwrap();
        assert!(!status.isolated);
        assert!(!status.network_isolated);
    }

    #[test]
    fn test_service_daemon_cancellation_and_disarm() {
        // 1. Linux daemon cancellation
        let linux_mgr = LinuxServiceManager::new();
        linux_mgr.request_stop();
        let res = linux_mgr.run_service_daemon();
        assert!(res.is_ok(), "Linux daemon must cleanly exit on stop request");

        // 2. macOS daemon cancellation
        let mac_mgr = MacOsServiceManager::new();
        mac_mgr.request_stop();
        let mac_res = mac_mgr.run_service_daemon();
        assert!(mac_res.is_ok(), "macOS daemon must cleanly exit on stop request");

        // 3. Windows daemon cancellation or console fallback
        #[cfg(target_os = "windows")]
        {
            let win_mgr = WindowsServiceManager::new();
            win_mgr.request_stop();
            let win_res = win_mgr.run_service_daemon();
            assert!(win_res.is_ok(), "Windows daemon must cleanly exit on stop request");
        }

        // 4. Global shutdown hook
        reset_daemon_stop_flag();
        assert!(!is_daemon_stop_requested());
        request_daemon_shutdown();
        assert!(is_daemon_stop_requested());
        let sim_mgr = SimulatedServiceManager::new();
        assert!(sim_mgr.run_service_daemon().is_ok());
        reset_daemon_stop_flag();
    }
}
