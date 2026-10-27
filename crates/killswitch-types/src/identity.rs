use serde::{Deserialize, Serialize};

/// Composite non-detachable identity for process instances.
///
/// Prevents numerical PID reuse, cross-session context laundering, and
/// detached child escapes by binding PID, start time in 100ns units,
/// BLAKE3 executable image digest, parent instance ID, Job Object ID,
/// and origin session ID into a deterministic BLAKE3 UUID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessInstanceIdentity {
    /// Deterministic BLAKE3 hexadecimal UUID (64 chars).
    pub instance_id: String,
    /// OS-assigned numerical Process ID.
    pub pid: u32,
    /// Process creation timestamp in 100-nanosecond intervals since epoch.
    pub start_time_100ns: u64,
    /// Cryptographic BLAKE3 digest of the executable binary on disk.
    pub image_digest_blake3: String,
    /// Parent process `instance_id` UUID, if known.
    pub parent_instance_id: Option<String>,
    /// Windows Job Object or Linux cgroup identifier, if bound.
    pub job_object_id: Option<String>,
    /// Logon session or terminal session identifier.
    pub origin_session_id: String,
}

impl ProcessInstanceIdentity {
    /// Domain separation prefix for process instance hashing.
    pub const DOMAIN_TAG: &'static [u8] = b"KILLSWITCH_PROCESS_INSTANCE_V1:";

    /// Computes deterministic BLAKE3 instance UUID from process provenance fields.
    pub fn compute_instance_id(
        pid: u32,
        start_time_100ns: u64,
        image_digest_blake3: &str,
        parent_instance_id: Option<&str>,
        job_object_id: Option<&str>,
        origin_session_id: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(&pid.to_le_bytes());
        hasher.update(&start_time_100ns.to_le_bytes());
        hasher.update(image_digest_blake3.as_bytes());
        if let Some(parent) = parent_instance_id {
            hasher.update(b"|parent:");
            hasher.update(parent.as_bytes());
        }
        if let Some(job) = job_object_id {
            hasher.update(b"|job:");
            hasher.update(job.as_bytes());
        }
        hasher.update(b"|session:");
        hasher.update(origin_session_id.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Creates a new composite process instance identity and calculates its deterministic UUID.
    pub fn new(
        pid: u32,
        start_time_100ns: u64,
        image_digest_blake3: impl Into<String>,
        parent_instance_id: Option<String>,
        job_object_id: Option<String>,
        origin_session_id: impl Into<String>,
    ) -> Self {
        let digest_str = image_digest_blake3.into();
        let session_str = origin_session_id.into();

        let instance_id = Self::compute_instance_id(
            pid,
            start_time_100ns,
            &digest_str,
            parent_instance_id.as_deref(),
            job_object_id.as_deref(),
            &session_str,
        );

        Self {
            instance_id,
            pid,
            start_time_100ns,
            image_digest_blake3: digest_str,
            parent_instance_id,
            job_object_id,
            origin_session_id: session_str,
        }
    }

    /// Validates whether the instance UUID matches its internal constituent fields.
    pub fn verify_integrity(&self) -> bool {
        let expected = Self::compute_instance_id(
            self.pid,
            self.start_time_100ns,
            &self.image_digest_blake3,
            self.parent_instance_id.as_deref(),
            self.job_object_id.as_deref(),
            &self.origin_session_id,
        );
        self.instance_id == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_instance_identity_deterministic_hashing() {
        let id1 = ProcessInstanceIdentity::new(
            1337,
            132800000000000000,
            "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
            Some("parent-uuid-001".to_string()),
            Some("job-001".to_string()),
            "Session-1",
        );

        let id2 = ProcessInstanceIdentity::new(
            1337,
            132800000000000000,
            "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
            Some("parent-uuid-001".to_string()),
            Some("job-001".to_string()),
            "Session-1",
        );

        assert_eq!(id1.instance_id, id2.instance_id);
        assert!(id1.verify_integrity());
        assert!(id2.verify_integrity());
    }

    #[test]
    fn test_process_instance_identity_tamper_detection() {
        let mut id = ProcessInstanceIdentity::new(
            1337,
            132800000000000000,
            "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
            None,
            None,
            "Session-0",
        );

        assert!(id.verify_integrity());

        // Tamper with PID
        id.pid = 1338;
        assert!(!id.verify_integrity());

        // Tamper with start time
        id.pid = 1337;
        id.start_time_100ns += 1;
        assert!(!id.verify_integrity());

        // Tamper with digest
        id.start_time_100ns -= 1;
        id.image_digest_blake3 = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!id.verify_integrity());
    }
}
