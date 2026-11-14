//! Lineaged AI Agent Subtree Registry & Breakout Scope Resolver
//!
//! Tracks registered AI agent root PIDs, confirmed threat roots, and all
//! spawned descendant processes (`bash`, `powershell.exe`, `pwsh.exe`, `cmd.exe`,
//! `python`, `node`, `curl`, background workers, etc.) across parent exits and
//! multi-hop chains, while bounding containment strictly to offending subtrees so
//! uninvolved host interactive TTY shells and desktop parents are spared.

use crate::killchain::is_immutable_os_kernel_pid;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{Pid, ProcessRefreshKind, System};

/// Maximum hops walked upward or downward during lineage resolution.
const MAX_LINEAGE_DEPTH: usize = 64;

/// Classification of a process PID within the agent subtree lineage graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentLineageClass {
    /// Registered root PID of an AI agent runtime.
    TrackedAgentRoot,
    /// Descendant (shell, script interpreter, tool, background worker) spawned under a tracked agent root.
    TaintedAgentDescendant,
    /// Confirmed threat process or descendant of a confirmed threat PID.
    ConfirmedThreatSubtree,
    /// Uninvolved OS/desktop/terminal host boundary above which containment must stop.
    HostBoundary,
    /// Normal host process not rooted under any tracked agent or confirmed threat.
    Untracked,
}

impl AgentLineageClass {
    /// Returns true if processes of this class are eligible for subtree containment
    /// and denied blanket shell/developer-tool immunity.
    #[inline]
    pub fn is_containment_eligible(self) -> bool {
        matches!(
            self,
            Self::TrackedAgentRoot | Self::TaintedAgentDescendant | Self::ConfirmedThreatSubtree
        )
    }
}

/// Metadata for a registered AI agent root process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedAgentRoot {
    pub pid: u32,
    pub agent_id: String,
    pub runtime_label: String,
    pub sandbox_id: Option<String>,
    pub process_start_time_secs: Option<u64>,
    pub registered_at_epoch_secs: u64,
}

/// Record caching a tainted descendant even if an intermediate parent exits (reparenting defense).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintedDescendantRecord {
    pub pid: u32,
    pub root_pid: u32,
    pub proc_name: Option<String>,
    pub depth_from_root: usize,
    pub observed_at_epoch_secs: u64,
}

/// Result of resolving an offending child/leaf PID upward to its containment boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubtreeResolution {
    pub root_pid: u32,
    pub trigger_pid: u32,
    pub root_class: AgentLineageClass,
    pub root_name: Option<String>,
    pub sandbox_id: Option<String>,
    pub stopped_below_uninvolved_host_shell: bool,
    /// Ordered from `trigger_pid` upward to `root_pid` inclusive.
    pub ancestor_chain: Vec<(u32, String)>,
}

/// Global and instanceable lock-free registry tracking AI agent roots, confirmed threats,
/// parent->child spawn edges, and cached tainted descendants.
#[derive(Debug, Default)]
pub struct TrackedAgentTreeRegistry {
    /// Tracked AI agent roots indexed by PID.
    pub tracked_roots: DashMap<u32, TrackedAgentRoot>,
    /// Explicitly confirmed threat PIDs indexed by PID -> detection summary.
    pub confirmed_threat_pids: DashMap<u32, String>,
    /// Explicit parent -> direct child PIDs (supplementing live OS `sysinfo` ancestry).
    pub parent_child_edges: DashMap<u32, Vec<u32>>,
    /// Explicit child -> parent PID reverse lookup.
    pub child_to_parent: DashMap<u32, u32>,
    /// Descendants tainted via an ancestor agent root or threat root (survives parent exit).
    pub tainted_descendants: DashMap<u32, TaintedDescendantRecord>,
}

static GLOBAL_AGENT_REGISTRY: OnceLock<TrackedAgentTreeRegistry> = OnceLock::new();

impl TrackedAgentTreeRegistry {
    /// Constructs an isolated empty registry instance (ideal for deterministic unit tests).
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the process-wide shared agent subtree registry.
    pub fn global() -> &'static Self {
        GLOBAL_AGENT_REGISTRY.get_or_init(Self::new)
    }

    /// Registers an AI agent root PID with a runtime label (refuses kernel PIDs <= 4,
    /// self PID, and immutable OS kernel anchors).
    pub fn register_agent_root(&self, pid: u32, label: &str) -> bool {
        self.register_agent_root_with_sandbox(pid, label, label, None)
    }

    /// Registers an AI agent root PID with explicit agent identifier, runtime label, and optional
    /// OS sandbox identifier. Refuses immutable OS kernel/self PIDs.
    pub fn register_agent_root_with_sandbox(
        &self,
        pid: u32,
        agent_id: impl Into<String>,
        runtime_label: impl Into<String>,
        sandbox_id: Option<String>,
    ) -> bool {
        let label_str = runtime_label.into();
        if is_protected_kernel_or_self_pid(pid, Some(&label_str)) {
            return false;
        }
        let now = epoch_secs_now();
        self.tracked_roots.insert(
            pid,
            TrackedAgentRoot {
                pid,
                agent_id: agent_id.into(),
                runtime_label: label_str,
                sandbox_id,
                process_start_time_secs: None,
                registered_at_epoch_secs: now,
            },
        );
        true
    }

    /// Attaches or updates an OS sandbox identifier (Job Object, cgroup path, or pf anchor)
    /// for a registered agent root.
    pub fn bind_sandbox(&self, root_pid: u32, sandbox_id: impl Into<String>) {
        if let Some(mut root) = self.tracked_roots.get_mut(&root_pid) {
            root.sandbox_id = Some(sandbox_id.into());
        }
    }

    /// Marks a PID as a confirmed threat subtree root (unless it is an immutable OS kernel/self PID).
    pub fn mark_confirmed_threat(&self, pid: u32, reason: impl Into<String>) -> bool {
        if is_protected_kernel_or_self_pid(pid, None) {
            return false;
        }
        self.confirmed_threat_pids.insert(pid, reason.into());
        true
    }

    /// Records a `(child_pid, parent_pid)` relationship and propagates taint immediately if
    /// `parent_pid` is a tracked agent root, tainted descendant, or confirmed threat.
    pub fn register_child(&self, child_pid: u32, parent_pid: u32) -> bool {
        if parent_pid == child_pid || is_protected_kernel_or_self_pid(child_pid, None) {
            return false;
        }
        self.child_to_parent.insert(child_pid, parent_pid);
        self.parent_child_edges
            .entry(parent_pid)
            .and_modify(|children| {
                if !children.contains(&child_pid) {
                    children.push(child_pid);
                }
            })
            .or_insert_with(|| vec![child_pid]);

        if let Some((root_pid, depth)) = self.find_taint_anchor_in_memory(parent_pid) {
            self.tainted_descendants.insert(
                child_pid,
                TaintedDescendantRecord {
                    pid: child_pid,
                    root_pid,
                    proc_name: None,
                    depth_from_root: depth + 1,
                    observed_at_epoch_secs: epoch_secs_now(),
                },
            );
        }
        true
    }

    /// Alias taking `(parent_pid, child_pid)` order for edge-oriented callers.
    #[inline]
    pub fn register_child_edge(&self, parent_pid: u32, child_pid: u32) -> bool {
        self.register_child(child_pid, parent_pid)
    }

    /// Unregisters a PID from root/threat/taint tables and parent-child edge maps.
    pub fn unregister_pid(&self, pid: u32) {
        self.tracked_roots.remove(&pid);
        self.confirmed_threat_pids.remove(&pid);
        self.tainted_descendants.remove(&pid);
        if let Some((_, parent_pid)) = self.child_to_parent.remove(&pid) {
            if let Some(mut siblings) = self.parent_child_edges.get_mut(&parent_pid) {
                siblings.retain(|&c| c != pid);
            }
        }
        if let Some((_, children)) = self.parent_child_edges.remove(&pid) {
            for child in children {
                self.child_to_parent.remove(&child);
            }
        }
    }

    /// Returns a snapshot of all currently tracked agent root PIDs.
    pub fn tracked_roots(&self) -> Vec<u32> {
        let mut out: Vec<u32> = self.tracked_roots.iter().map(|e| *e.key()).collect();
        out.sort_unstable();
        out
    }

    /// Returns a snapshot of `(child_pid, parent_pid)` links.
    pub fn snapshot_child_links(&self) -> Vec<(u32, u32)> {
        self.child_to_parent
            .iter()
            .map(|e| (*e.key(), *e.value()))
            .collect()
    }

    /// Removes dead PIDs that are no longer present in a freshly refreshed OS process table.
    pub fn prune_exited_pids(&self, live_pids: &HashSet<u32>) {
        self.tracked_roots.retain(|pid, _| live_pids.contains(pid));
        self.confirmed_threat_pids
            .retain(|pid, _| live_pids.contains(pid));
        self.tainted_descendants
            .retain(|pid, _| live_pids.contains(pid));
        self.child_to_parent
            .retain(|child, parent| live_pids.contains(child) && live_pids.contains(parent));
        self.parent_child_edges.retain(|parent, children| {
            children.retain(|c| live_pids.contains(c));
            live_pids.contains(parent) && !children.is_empty()
        });
    }

    /// Alias for [`Self::is_pid_tracked_or_tainted`] preserved for compatibility with killchain callers.
    #[inline]
    pub fn is_tracked_pid(&self, pid: u32) -> bool {
        self.is_pid_tracked_or_tainted(pid)
    }

    /// Returns `true` if `pid` is a tracked agent root, tainted agent descendant, or confirmed threat.
    pub fn is_pid_tracked_or_tainted(&self, pid: u32) -> bool {
        if self.tracked_roots.is_empty()
            && self.confirmed_threat_pids.is_empty()
            && self.tainted_descendants.is_empty()
        {
            return false;
        }
        if is_protected_kernel_or_self_pid(pid, None) {
            return false;
        }
        if self.tracked_roots.contains_key(&pid)
            || self.confirmed_threat_pids.contains_key(&pid)
            || self.tainted_descendants.contains_key(&pid)
        {
            return true;
        }
        self.find_taint_anchor_in_memory(pid).is_some()
            || self.classify_pid(pid, None, &[]).is_containment_eligible()
    }

    /// Classifies `pid` using in-memory registry edges, `extra_edges`, and a fresh OS snapshot.
    pub fn classify_pid(
        &self,
        pid: u32,
        proc_name: Option<&str>,
        extra_edges: &[(u32, u32)],
    ) -> AgentLineageClass {
        if self.tracked_roots.is_empty()
            && self.confirmed_threat_pids.is_empty()
            && self.tainted_descendants.is_empty()
            && extra_edges.is_empty()
        {
            if is_protected_kernel_or_self_pid(pid, proc_name)
                || is_host_boundary_name(proc_name.unwrap_or(""))
            {
                return AgentLineageClass::HostBoundary;
            }
            return AgentLineageClass::Untracked;
        }

        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessRefreshKind::new());
        self.classify_pid_with_system(pid, proc_name, extra_edges, &sys)
    }

    /// Classifies `pid` against an already-refreshed `sysinfo::System` snapshot.
    pub fn classify_pid_with_system(
        &self,
        pid: u32,
        proc_name: Option<&str>,
        extra_edges: &[(u32, u32)],
        sys: &System,
    ) -> AgentLineageClass {
        let resolved_name = proc_name
            .map(str::to_string)
            .or_else(|| {
                sys.process(Pid::from_u32(pid))
                    .map(|p| p.name().to_string())
            })
            .unwrap_or_default();

        if is_protected_kernel_or_self_pid(pid, Some(&resolved_name)) {
            return AgentLineageClass::HostBoundary;
        }
        if self.tracked_roots.contains_key(&pid) {
            return AgentLineageClass::TrackedAgentRoot;
        }
        if self.confirmed_threat_pids.contains_key(&pid) {
            return AgentLineageClass::ConfirmedThreatSubtree;
        }
        if let Some(tainted) = self.tainted_descendants.get(&pid) {
            if self.tracked_roots.contains_key(&tainted.root_pid) {
                return AgentLineageClass::TaintedAgentDescendant;
            }
            if self.confirmed_threat_pids.contains_key(&tainted.root_pid) {
                return AgentLineageClass::ConfirmedThreatSubtree;
            }
        }

        let mut child_map = HashMap::with_capacity(extra_edges.len());
        for &(parent, child) in extra_edges {
            child_map.insert(child, parent);
        }

        let mut cursor = pid;
        let mut visited = HashSet::with_capacity(16);
        visited.insert(cursor);

        for depth in 0..MAX_LINEAGE_DEPTH {
            let Some(parent_pid) = self.lookup_parent(cursor, &child_map, sys) else {
                break;
            };
            if parent_pid == 0 || !visited.insert(parent_pid) {
                break;
            }
            let parent_name = sys
                .process(Pid::from_u32(parent_pid))
                .map(|p| p.name())
                .unwrap_or("");
            if is_protected_kernel_or_self_pid(parent_pid, Some(parent_name)) {
                break;
            }
            if self.tracked_roots.contains_key(&parent_pid) {
                self.cache_tainted_descendant(pid, parent_pid, &resolved_name, depth + 1);
                return AgentLineageClass::TaintedAgentDescendant;
            }
            if self.confirmed_threat_pids.contains_key(&parent_pid) {
                self.cache_tainted_descendant(pid, parent_pid, &resolved_name, depth + 1);
                return AgentLineageClass::ConfirmedThreatSubtree;
            }
            // Drop the DashMap read guard immediately before cache_tainted_descendant() writes back
            // into tainted_descendants, preventing same-shard RwLock self-deadlock on child chains.
            let ancestor_taint_info = self
                .tainted_descendants
                .get(&parent_pid)
                .map(|t| (t.root_pid, t.depth_from_root));
            if let Some((anchor, anchor_depth)) = ancestor_taint_info {
                if self.tracked_roots.contains_key(&anchor) {
                    self.cache_tainted_descendant(
                        pid,
                        anchor,
                        &resolved_name,
                        anchor_depth + depth + 1,
                    );
                    return AgentLineageClass::TaintedAgentDescendant;
                }
                if self.confirmed_threat_pids.contains_key(&anchor) {
                    self.cache_tainted_descendant(
                        pid,
                        anchor,
                        &resolved_name,
                        anchor_depth + depth + 1,
                    );
                    return AgentLineageClass::ConfirmedThreatSubtree;
                }
            }
            cursor = parent_pid;
        }

        if is_host_boundary_name(&resolved_name) {
            AgentLineageClass::HostBoundary
        } else {
            AgentLineageClass::Untracked
        }
    }

    /// Resolves a potentially deeply nested offending child/leaf PID upward to its
    /// containment root (`TrackedAgentRoot` or highest `ConfirmedThreatSubtree`),
    /// stopping strictly below any uninvolved host interactive TTY shell or desktop parent.
    pub fn resolve_offending_process_subtree(
        &self,
        trigger_pid: u32,
        trigger_name: Option<&str>,
        extra_edges: &[(u32, u32)],
    ) -> SubtreeResolution {
        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessRefreshKind::new());
        self.resolve_offending_process_subtree_with_system(
            trigger_pid,
            trigger_name,
            extra_edges,
            &sys,
        )
    }

    /// Snapshot-backed variant of [`Self::resolve_offending_process_subtree`].
    pub fn resolve_offending_process_subtree_with_system(
        &self,
        trigger_pid: u32,
        trigger_name: Option<&str>,
        extra_edges: &[(u32, u32)],
        sys: &System,
    ) -> SubtreeResolution {
        let mut child_map = HashMap::with_capacity(extra_edges.len());
        for &(parent, child) in extra_edges {
            child_map.insert(child, parent);
        }

        let mut raw_chain: Vec<(u32, String)> = Vec::with_capacity(16);
        let mut visited = HashSet::with_capacity(16);
        let mut cursor = trigger_pid;

        for depth in 0..MAX_LINEAGE_DEPTH {
            if !visited.insert(cursor) {
                break;
            }
            let name = if depth == 0 {
                trigger_name
                    .map(str::to_string)
                    .or_else(|| {
                        sys.process(Pid::from_u32(cursor))
                            .map(|p| p.name().to_string())
                    })
                    .unwrap_or_default()
            } else {
                sys.process(Pid::from_u32(cursor))
                    .map(|p| p.name().to_string())
                    .unwrap_or_default()
            };

            if depth > 0 && is_protected_kernel_or_self_pid(cursor, Some(&name)) {
                break;
            }
            raw_chain.push((cursor, name));

            let Some(parent_pid) = self.lookup_parent(cursor, &child_map, sys) else {
                break;
            };
            if parent_pid == 0 {
                break;
            }
            let parent_name = sys
                .process(Pid::from_u32(parent_pid))
                .map(|p| p.name())
                .unwrap_or("");
            if is_protected_kernel_or_self_pid(parent_pid, Some(parent_name)) {
                break;
            }
            cursor = parent_pid;
        }

        // 1. Prefer the nearest ancestor that is a registered TrackedAgentRoot.
        for (idx, (anc_pid, anc_name)) in raw_chain.iter().enumerate() {
            if let Some(root) = self.tracked_roots.get(anc_pid) {
                let chain = raw_chain[..=idx].to_vec();
                return SubtreeResolution {
                    root_pid: *anc_pid,
                    trigger_pid,
                    root_class: AgentLineageClass::TrackedAgentRoot,
                    root_name: (!anc_name.is_empty()).then(|| anc_name.clone()),
                    sandbox_id: root.sandbox_id.clone(),
                    stopped_below_uninvolved_host_shell: true,
                    ancestor_chain: chain,
                };
            }
        }

        // 2. Fallback to cached taint anchor if an intermediate parent exited.
        if let Some(tainted) = self.tainted_descendants.get(&trigger_pid) {
            if let Some(root) = self.tracked_roots.get(&tainted.root_pid) {
                return SubtreeResolution {
                    root_pid: tainted.root_pid,
                    trigger_pid,
                    root_class: AgentLineageClass::TrackedAgentRoot,
                    root_name: Some(root.runtime_label.clone()),
                    sandbox_id: root.sandbox_id.clone(),
                    stopped_below_uninvolved_host_shell: true,
                    ancestor_chain: raw_chain,
                };
            }
        }

        // 3. Otherwise climb only across confirmed-threat ancestors or live named non-host
        //    ancestors, stopping strictly at the highest confirmed threat or below any
        //    uninvolved interactive shell / desktop boundary.
        let mut stopped_below_host = false;
        let mut highest_confirmed_idx: Option<usize> = self
            .confirmed_threat_pids
            .contains_key(&trigger_pid)
            .then_some(0);

        for (idx, (anc_pid, anc_name)) in raw_chain.iter().enumerate().skip(1) {
            if self.confirmed_threat_pids.contains_key(anc_pid) {
                highest_confirmed_idx = Some(idx);
                continue;
            }
            if is_host_boundary_name(anc_name) || is_interactive_host_shell_name(anc_name) {
                stopped_below_host = true;
                break;
            }
        }

        let stop_idx = if let Some(conf_idx) = highest_confirmed_idx {
            if conf_idx + 1 < raw_chain.len() {
                stopped_below_host = true;
            }
            conf_idx
        } else {
            let mut non_host_top = 0usize;
            for (idx, (_, anc_name)) in raw_chain.iter().enumerate().skip(1) {
                if anc_name.is_empty()
                    || is_host_boundary_name(anc_name)
                    || is_interactive_host_shell_name(anc_name)
                {
                    stopped_below_host = true;
                    break;
                }
                non_host_top = idx;
            }
            non_host_top
        };

        let (root_pid, root_name_str) = raw_chain
            .get(stop_idx)
            .cloned()
            .unwrap_or((trigger_pid, trigger_name.unwrap_or("").to_string()));
        let root_class = if self.confirmed_threat_pids.contains_key(&root_pid) {
            AgentLineageClass::ConfirmedThreatSubtree
        } else {
            self.classify_pid_with_system(root_pid, Some(&root_name_str), extra_edges, sys)
        };

        SubtreeResolution {
            root_pid,
            trigger_pid,
            root_class,
            root_name: (!root_name_str.is_empty()).then_some(root_name_str),
            sandbox_id: self
                .tracked_roots
                .get(&root_pid)
                .and_then(|r| r.sandbox_id.clone()),
            stopped_below_uninvolved_host_shell: stopped_below_host,
            ancestor_chain: raw_chain[..=stop_idx].to_vec(),
        }
    }

    /// Collects all live + edge-linked PIDs rooted at `root_pid` (inclusive) in BFS
    /// parent-before-child order, automatically omitting immutable OS kernel PIDs and self.
    pub fn collect_subtree_pids(&self, root_pid: u32, extra_edges: &[(u32, u32)]) -> Vec<u32> {
        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessRefreshKind::new());
        self.collect_subtree_pids_with_system(root_pid, extra_edges, &sys)
    }

    /// Snapshot-backed BFS descendant enumeration (parent-before-child order).
    pub fn collect_subtree_pids_with_system(
        &self,
        root_pid: u32,
        extra_edges: &[(u32, u32)],
        sys: &System,
    ) -> Vec<u32> {
        let mut adj: HashMap<u32, Vec<u32>> = HashMap::new();

        for (pid_raw, proc_entry) in sys.processes() {
            if let Some(ppid) = proc_entry.parent() {
                adj.entry(ppid.as_u32()).or_default().push(pid_raw.as_u32());
            }
        }
        for entry in self.parent_child_edges.iter() {
            adj.entry(*entry.key())
                .or_default()
                .extend(entry.value().iter().copied());
        }
        for entry in self.tainted_descendants.iter() {
            adj.entry(entry.value().root_pid)
                .or_default()
                .push(*entry.key());
        }
        for &(parent, child) in extra_edges {
            adj.entry(parent).or_default().push(child);
        }

        let mut ordered = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((root_pid, 0usize));
        visited.insert(root_pid);

        while let Some((pid, depth)) = queue.pop_front() {
            let p_name = sys.process(Pid::from_u32(pid)).map(|p| p.name());
            if !is_protected_kernel_or_self_pid(pid, p_name) {
                ordered.push(pid);
            }
            if depth >= MAX_LINEAGE_DEPTH {
                continue;
            }
            if let Some(children) = adj.get(&pid) {
                let mut sorted_children = children.clone();
                sorted_children.sort_unstable();
                sorted_children.dedup();
                for child in sorted_children {
                    if visited.insert(child) {
                        queue.push_back((child, depth + 1));
                    }
                }
            }
        }

        ordered
    }

    /// Collects all deduplicated PIDs across every registered `TrackedAgentRoot` and
    /// `ConfirmedThreatSubtree` in parent-before-child BFS order so a caller can
    /// freeze whole agent subtrees while sparing uninvolved host processes.
    pub fn collect_all_containment_candidates(&self, extra_edges: &[(u32, u32)]) -> Vec<u32> {
        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessRefreshKind::new());

        let mut roots: Vec<u32> = self
            .tracked_roots
            .iter()
            .map(|e| *e.key())
            .chain(self.confirmed_threat_pids.iter().map(|e| *e.key()))
            .collect();
        roots.sort_unstable();
        roots.dedup();

        let mut seen = HashSet::new();
        let mut all_targets = Vec::new();

        for root_pid in roots {
            for pid in self.collect_subtree_pids_with_system(root_pid, extra_edges, &sys) {
                if seen.insert(pid) {
                    all_targets.push(pid);
                }
            }
        }
        for entry in self.tainted_descendants.iter() {
            let pid = *entry.key();
            if !is_protected_kernel_or_self_pid(pid, None) && seen.insert(pid) {
                all_targets.push(pid);
            }
        }

        all_targets
    }

    fn lookup_parent(
        &self,
        pid: u32,
        extra_child_map: &HashMap<u32, u32>,
        sys: &System,
    ) -> Option<u32> {
        if let Some(parent) = extra_child_map.get(&pid) {
            return Some(*parent);
        }
        if let Some(parent) = self.child_to_parent.get(&pid) {
            return Some(*parent);
        }
        sys.process(Pid::from_u32(pid))
            .and_then(|p| p.parent().map(|pp| pp.as_u32()))
    }

    fn find_taint_anchor_in_memory(&self, start_pid: u32) -> Option<(u32, usize)> {
        let mut cursor = start_pid;
        let mut visited = HashSet::with_capacity(16);
        visited.insert(cursor);

        for depth in 0..MAX_LINEAGE_DEPTH {
            if self.tracked_roots.contains_key(&cursor)
                || self.confirmed_threat_pids.contains_key(&cursor)
            {
                return Some((cursor, depth));
            }
            if let Some(tainted) = self.tainted_descendants.get(&cursor) {
                return Some((tainted.root_pid, tainted.depth_from_root + depth));
            }
            let Some(parent) = self.child_to_parent.get(&cursor).map(|p| *p) else {
                break;
            };
            if parent == 0 || !visited.insert(parent) {
                break;
            }
            cursor = parent;
        }
        None
    }

    fn cache_tainted_descendant(
        &self,
        pid: u32,
        root_pid: u32,
        proc_name: &str,
        depth_from_root: usize,
    ) {
        self.tainted_descendants.insert(
            pid,
            TaintedDescendantRecord {
                pid,
                root_pid,
                proc_name: (!proc_name.is_empty()).then(|| proc_name.to_string()),
                depth_from_root,
                observed_at_epoch_secs: epoch_secs_now(),
            },
        );
    }
}

fn normalized_proc_name_lc(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// Returns true strictly for immutable OS kernel anchors and KillSwitch self PIDs.
fn is_protected_kernel_or_self_pid(pid: u32, name: Option<&str>) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    if let Some(raw_name) = name {
        if is_immutable_os_kernel_pid(pid, raw_name) {
            return true;
        }
    }
    false
}

/// Returns true for host desktop, window-server, or terminal emulator boundaries above which
/// unrooted threat resolution must stop so host GUI/terminal sessions are not frozen.
fn is_host_boundary_name(name: &str) -> bool {
    let lc = normalized_proc_name_lc(name);
    let stem = lc.strip_suffix(".exe").unwrap_or(&lc);
    matches!(
        stem,
        "explorer"
            | "windowserver"
            | "gnome-terminal"
            | "gnome-terminal-server"
            | "konsole"
            | "xterm"
            | "alacritty"
            | "wezterm-gui"
            | "kitty"
            | "iterm2"
            | "terminal"
            | "wt"
            | "windowsterminal"
            | "openconsole"
            | "conhost"
            | "sshd"
            | "login"
            | "systemd"
            | "init"
            | "launchd"
    )
}

/// Returns true for interactive shells that should NOT be frozen when acting as an
/// uninvolved host parent above a standalone non-agent threat process.
fn is_interactive_host_shell_name(name: &str) -> bool {
    let lc = normalized_proc_name_lc(name);
    let stem = lc.strip_suffix(".exe").unwrap_or(&lc);
    matches!(
        stem,
        "bash" | "zsh" | "fish" | "sh" | "dash" | "pwsh" | "powershell" | "cmd"
    )
}

#[inline]
fn epoch_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_subtree_nested_shells_are_tainted_while_sibling_tty_is_untracked() {
        let reg = TrackedAgentTreeRegistry::new();

        assert!(reg.register_agent_root_with_sandbox(
            900_200,
            "agent-alpha",
            "openclaw",
            Some("job-1".into())
        ));

        let edges = [
            (900_000, 900_100),
            (900_100, 900_101),
            (900_000, 900_200),
            (900_200, 900_300),
            (900_300, 900_400),
            (900_400, 900_500),
        ];

        assert_eq!(
            reg.classify_pid(900_200, Some("openclaw"), &edges),
            AgentLineageClass::TrackedAgentRoot
        );
        assert_eq!(
            reg.classify_pid(900_300, Some("bash"), &edges),
            AgentLineageClass::TaintedAgentDescendant
        );
        assert_eq!(
            reg.classify_pid(900_400, Some("python3"), &edges),
            AgentLineageClass::TaintedAgentDescendant
        );
        assert_eq!(
            reg.classify_pid(900_500, Some("curl"), &edges),
            AgentLineageClass::TaintedAgentDescendant
        );

        assert_eq!(
            reg.classify_pid(900_100, Some("bash"), &edges),
            AgentLineageClass::Untracked
        );
        assert_eq!(
            reg.classify_pid(900_101, Some("git"), &edges),
            AgentLineageClass::Untracked
        );
        assert_eq!(
            reg.classify_pid(900_000, Some("wt.exe"), &edges),
            AgentLineageClass::HostBoundary
        );

        let targets = reg.collect_all_containment_candidates(&edges);
        assert_eq!(targets, vec![900_200, 900_300, 900_400, 900_500]);
    }

    #[test]
    fn test_resolve_offending_subtree_stops_below_uninvolved_host_terminal_and_explorer() {
        let reg = TrackedAgentTreeRegistry::new();

        assert!(reg.register_agent_root_with_sandbox(910_200, "agent-beta", "claude-code", None));
        let agent_edges = [(910_050, 910_200), (910_200, 910_300), (910_300, 910_400)];
        let res_agent =
            reg.resolve_offending_process_subtree(910_400, Some("curl.exe"), &agent_edges);
        assert_eq!(res_agent.root_pid, 910_200);
        assert_eq!(res_agent.root_class, AgentLineageClass::TrackedAgentRoot);
        assert!(res_agent.stopped_below_uninvolved_host_shell);
        assert!(!res_agent
            .ancestor_chain
            .iter()
            .any(|(pid, _)| *pid == 910_050));

        assert!(reg.mark_confirmed_threat(920_300, "malicious python payload"));
        let non_agent_edges = [(920_100, 920_200), (920_200, 920_300), (920_300, 920_400)];
        let res_threat =
            reg.resolve_offending_process_subtree(920_400, Some("nc"), &non_agent_edges);
        assert_eq!(res_threat.root_pid, 920_300);
        assert_eq!(
            res_threat.root_class,
            AgentLineageClass::ConfirmedThreatSubtree
        );
        assert!(res_threat.stopped_below_uninvolved_host_shell);
        assert!(!res_threat
            .ancestor_chain
            .iter()
            .any(|(pid, _)| *pid == 920_200 || *pid == 920_100));
    }

    #[test]
    fn test_reparented_descendant_remains_tainted_after_intermediate_shell_exits() {
        let reg = TrackedAgentTreeRegistry::new();
        assert!(reg.register_agent_root(930_100, "codex"));
        assert!(reg.register_child(930_200, 930_100));
        assert!(reg.register_child(930_300, 930_200));

        reg.parent_child_edges.remove(&930_200);
        reg.child_to_parent.insert(930_300, 1);

        assert!(reg.is_tracked_pid(930_300));
        assert_eq!(
            reg.classify_pid(930_300, Some("python3"), &[]),
            AgentLineageClass::TaintedAgentDescendant
        );
    }

    #[test]
    fn test_immutable_kernel_and_self_pid_cannot_be_registered_as_targets() {
        let reg = TrackedAgentTreeRegistry::new();
        assert!(!reg.register_agent_root(1, "init"));
        assert!(!reg.register_agent_root(4, "system"));
        assert!(!reg.register_agent_root(std::process::id(), "self"));
        assert!(!reg.mark_confirmed_threat(std::process::id(), "self"));
        assert!(!reg.is_tracked_pid(std::process::id()));
    }

    #[test]
    fn test_tainted_descendant_cache_propagation_no_same_shard_deadlock() {
        let reg = TrackedAgentTreeRegistry::new();
        let sys = System::new();
        let root_pid = 940_000;
        let tainted_parent = 940_001;
        assert!(reg.register_agent_root(root_pid, "agent-root"));
        assert!(reg.register_child(tainted_parent, root_pid));
        assert_eq!(
            reg.classify_pid_with_system(tainted_parent, Some("bash"), &[], &sys),
            AgentLineageClass::TaintedAgentDescendant
        );

        // Pigeonhole principle: fan out >256 child PIDs from the same cached
        // tainted parent via extra_edges so at least one child guarantees a
        // DashMap shard collision with tainted_parent across <=64-CPU hosts.
        for offset in 2u32..=320u32 {
            let child_pid = root_pid + offset;
            let edges = [(tainted_parent, child_pid)];
            assert_eq!(
                reg.classify_pid_with_system(child_pid, Some("sh"), &edges, &sys),
                AgentLineageClass::TaintedAgentDescendant
            );
        }
    }
}
