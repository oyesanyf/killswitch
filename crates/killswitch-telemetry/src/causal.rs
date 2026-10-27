//! # Causal Provenance Security Graph
//!
//! Implements a directed acyclic causal graph tracking process execution, file I/O,
//! network sockets, and inter-process injection with transitive taint reachability.
//! Uses deterministic `ProcessInstanceIdentity` BLAKE3 provenance to eliminate PID reuse hazards.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use killswitch_types::identity::ProcessInstanceIdentity;

/// Entity types tracked in the causal provenance graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CausalNodeType {
    Process(ProcessInstanceIdentity),
    File {
        path: String,
        blake3_hash: String,
    },
    Socket {
        destination: String,
        port: u16,
        protocol: String,
    },
    ToolCall {
        tool_name: String,
        execution_id: String,
    },
}

impl CausalNodeType {
    pub fn id(&self) -> String {
        match self {
            Self::Process(proc) => proc.instance_id.clone(),
            Self::File { path, blake3_hash } => {
                format!("file:{}:{}", path, blake3_hash)
            }
            Self::Socket {
                destination,
                port,
                protocol,
            } => {
                format!("sock:{}:{}:{}", protocol, destination, port)
            }
            Self::ToolCall {
                tool_name,
                execution_id,
            } => {
                format!("tool:{}:{}", tool_name, execution_id)
            }
        }
    }
}

/// Relationship edge classifications within the causal DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CausalEdgeKind {
    Spawned,
    Read,
    Wrote,
    Executed,
    Connected,
    Injected,
    BrokeredBy,
}

/// A directed causal edge connecting two graph entities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalEdge {
    pub source_id: String,
    pub target_id: String,
    pub edge_kind: CausalEdgeKind,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Directed acyclic graph managing system causal provenance.
#[derive(Clone)]
pub struct CausalSecurityGraph {
    nodes: Arc<DashMap<String, CausalNodeType>>,
    edges: Arc<DashMap<String, Vec<CausalEdge>>>, // Source -> Outgoing
    reverse_edges: Arc<DashMap<String, Vec<CausalEdge>>>, // Target -> Incoming
    pid_to_instance: Arc<DashMap<u32, String>>,
}

impl Default for CausalSecurityGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl CausalSecurityGraph {
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(DashMap::new()),
            edges: Arc::new(DashMap::new()),
            reverse_edges: Arc::new(DashMap::new()),
            pid_to_instance: Arc::new(DashMap::new()),
        }
    }

    /// Records a process creation event, binding parent-to-child causal link.
    pub fn record_process_spawn(
        &self,
        parent_instance_id: Option<&str>,
        child: &ProcessInstanceIdentity,
        image_path: &str,
    ) {
        let child_id = child.instance_id.clone();
        self.nodes
            .insert(child_id.clone(), CausalNodeType::Process(child.clone()));
        self.pid_to_instance.insert(child.pid, child_id.clone());

        if let Some(parent_id) = parent_instance_id {
            let edge = CausalEdge {
                source_id: parent_id.to_string(),
                target_id: child_id.clone(),
                edge_kind: CausalEdgeKind::Spawned,
                timestamp: Utc::now(),
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("image_path".to_string(), image_path.to_string());
                    m.insert("child_pid".to_string(), child.pid.to_string());
                    m
                },
            };

            self.edges
                .entry(parent_id.to_string())
                .or_default()
                .push(edge.clone());
            self.reverse_edges
                .entry(child_id)
                .or_default()
                .push(edge);
        }
    }

    /// Records a file interaction (read or write).
    pub fn record_file_interaction(
        &self,
        instance_id: &str,
        file_path: &str,
        file_hash: &str,
        is_write: bool,
    ) {
        let file_node = CausalNodeType::File {
            path: file_path.to_string(),
            blake3_hash: file_hash.to_string(),
        };
        let file_id = file_node.id();
        self.nodes.insert(file_id.clone(), file_node);

        let (src, dst, kind) = if is_write {
            (instance_id.to_string(), file_id.clone(), CausalEdgeKind::Wrote)
        } else {
            (file_id.clone(), instance_id.to_string(), CausalEdgeKind::Read)
        };

        let edge = CausalEdge {
            source_id: src.clone(),
            target_id: dst.clone(),
            edge_kind: kind,
            timestamp: Utc::now(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("file_path".to_string(), file_path.to_string());
                m.insert("file_hash".to_string(), file_hash.to_string());
                m
            },
        };

        self.edges.entry(src).or_default().push(edge.clone());
        self.reverse_edges.entry(dst).or_default().push(edge);
    }

    /// Records an outbound network socket connection.
    pub fn record_network_connect(&self, instance_id: &str, dst_ip: &str, port: u16) {
        let socket_node = CausalNodeType::Socket {
            destination: dst_ip.to_string(),
            port,
            protocol: "TCP".to_string(),
        };
        let socket_id = socket_node.id();
        self.nodes.insert(socket_id.clone(), socket_node);

        let edge = CausalEdge {
            source_id: instance_id.to_string(),
            target_id: socket_id.clone(),
            edge_kind: CausalEdgeKind::Connected,
            timestamp: Utc::now(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("destination".to_string(), dst_ip.to_string());
                m.insert("port".to_string(), port.to_string());
                m
            },
        };

        self.edges
            .entry(instance_id.to_string())
            .or_default()
            .push(edge.clone());
        self.reverse_edges.entry(socket_id).or_default().push(edge);
    }

    /// Records a cross-process code injection (e.g. CreateRemoteThread).
    pub fn record_injection(
        &self,
        source_instance_id: &str,
        target_instance_id: &str,
        technique: &str,
    ) {
        let edge = CausalEdge {
            source_id: source_instance_id.to_string(),
            target_id: target_instance_id.to_string(),
            edge_kind: CausalEdgeKind::Injected,
            timestamp: Utc::now(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("technique".to_string(), technique.to_string());
                m
            },
        };

        self.edges
            .entry(source_instance_id.to_string())
            .or_default()
            .push(edge.clone());
        self.reverse_edges
            .entry(target_instance_id.to_string())
            .or_default()
            .push(edge);
    }

    /// Traverses incoming edges backwards to reconstruct the process lineage ancestry up to `max_depth`.
    pub fn get_lineage_ancestry(
        &self,
        instance_id: &str,
        max_depth: usize,
    ) -> Vec<ProcessInstanceIdentity> {
        let mut ancestry = Vec::new();
        let mut curr_id = instance_id.to_string();
        let mut visited = HashSet::new();
        visited.insert(curr_id.clone());

        for _ in 0..max_depth {
            let parent_opt = self.reverse_edges.get(&curr_id).and_then(|edges| {
                edges
                    .iter()
                    .find(|e| e.edge_kind == CausalEdgeKind::Spawned)
                    .map(|e| e.source_id.clone())
            });

            match parent_opt {
                Some(p_id) => {
                    if visited.contains(&p_id) {
                        break; // Cycle detected
                    }
                    visited.insert(p_id.clone());

                    if let Some(node) = self.nodes.get(&p_id) {
                        if let CausalNodeType::Process(ref proc_id) = *node {
                            ancestry.push(proc_id.clone());
                        }
                    }
                    curr_id = p_id;
                }
                None => break,
            }
        }

        ancestry
    }

    /// Computes transitive forward taint reachability: returns all descendant node IDs reachable
    /// from `seed_id` via Spawned, Wrote, Injected, or Connected edges.
    pub fn get_transitive_taint_forward(&self, seed_id: &str) -> HashSet<String> {
        let mut reachable = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(seed_id.to_string());
        reachable.insert(seed_id.to_string());

        while let Some(current) = queue.pop_front() {
            if let Some(outgoing) = self.edges.get(&current) {
                for edge in outgoing.iter() {
                    // Taint flows across execution, writes, injections, and socket connects
                    if matches!(
                        edge.edge_kind,
                        CausalEdgeKind::Spawned
                            | CausalEdgeKind::Wrote
                            | CausalEdgeKind::Injected
                            | CausalEdgeKind::Connected
                            | CausalEdgeKind::Executed
                    ) && !reachable.contains(&edge.target_id)
                    {
                        reachable.insert(edge.target_id.clone());
                        queue.push_back(edge.target_id.clone());
                    }
                }
            }
        }

        reachable
    }

    /// Finds the active instance ID for a numerical PID.
    pub fn find_instance_by_pid(&self, pid: u32) -> Option<String> {
        self.pid_to_instance.get(&pid).map(|r| r.value().clone())
    }

    /// Purges a terminated PID's lookup mapping to prevent PID reuse contamination.
    pub fn purge_terminated_pid(&self, pid: u32) {
        self.pid_to_instance.remove(&pid);
    }

    /// Returns the total number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the total number of source entities with edges.
    pub fn edge_sources_count(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_causal_graph_spawn_and_ancestry() {
        let graph = CausalSecurityGraph::new();

        let root = ProcessInstanceIdentity::new(100, 1000, "root_hash", None, None, "Session-0");
        let child = ProcessInstanceIdentity::new(
            200,
            2000,
            "child_hash",
            Some(root.instance_id.clone()),
            None,
            "Session-0",
        );
        let grandchild = ProcessInstanceIdentity::new(
            300,
            3000,
            "grandchild_hash",
            Some(child.instance_id.clone()),
            None,
            "Session-0",
        );

        graph.record_process_spawn(None, &root, "system.exe");
        graph.record_process_spawn(Some(&root.instance_id), &child, "worker.exe");
        graph.record_process_spawn(Some(&child.instance_id), &grandchild, "task.exe");

        let ancestry = graph.get_lineage_ancestry(&grandchild.instance_id, 5);
        assert_eq!(ancestry.len(), 2);
        assert_eq!(ancestry[0].pid, 200);
        assert_eq!(ancestry[1].pid, 100);
    }

    #[test]
    fn test_transitive_taint_forward_propagation() {
        let graph = CausalSecurityGraph::new();

        let attacker = ProcessInstanceIdentity::new(666, 1000, "malware_hash", None, None, "Session-1");
        let dropped_file = "C:\\Temp\\payload.exe";
        let spawned_child = ProcessInstanceIdentity::new(777, 2000, "child_hash", Some(attacker.instance_id.clone()), None, "Session-1");

        graph.record_process_spawn(None, &attacker, "evil.exe");
        graph.record_file_interaction(&attacker.instance_id, dropped_file, "file_hash_123", true);
        graph.record_process_spawn(Some(&attacker.instance_id), &spawned_child, "payload.exe");
        graph.record_network_connect(&spawned_child.instance_id, "198.51.100.1", 443);

        let taint = graph.get_transitive_taint_forward(&attacker.instance_id);

        assert!(taint.contains(&attacker.instance_id));
        assert!(taint.contains(&spawned_child.instance_id));
        assert!(taint.iter().any(|id| id.contains("payload.exe")));
        assert!(taint.iter().any(|id| id.contains("198.51.100.1")));
    }
}
