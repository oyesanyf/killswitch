//! # Autonomous Mode DLP Lineage Trigger Node
//!
//! Evaluates active process and file taint graphs from `EndpointLineageEngine`.
//! When exfiltration of `CrownJewel` or `Quarantine` data is detected, constructs
//! a typed `LineageAdjudicationEvidence` bundle, verifies it through the 5-layer
//! `ZeroFalsePositiveAdjudicator`, and if confirmed, triggers autonomous containment
//! while preserving critical system PIDs.

use std::sync::Arc;
use killswitch_adjudication::voters::{
    AdjudicationContext, DlpClassification as AdjClassification, DlpPolicy as AdjPolicy,
    EgressVerdict as AdjEgressVerdict, LineageAdjudicationEvidence, LineageCausalLink,
    OpenLineageDataset as AdjDataset, OpenLineageDatasetFacets as AdjFacets,
    TaintBaggage as AdjBaggage,
};
use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::is_critical_system_pid;
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EgressVerdict, EndpointLineageEngine,
};
use killswitch_types::adjudication::{AdjudicationResult, EvidenceClass, ThreatCandidate};
use killswitch_types::errors::Result;
use killswitch_types::graph::KillSwitchGraphState;
use tracing::info;

pub struct LineageTriggerEvaluator {
    pub lineage_engine: Arc<EndpointLineageEngine>,
    pub adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
}

impl LineageTriggerEvaluator {
    pub fn new(
        lineage_engine: Arc<EndpointLineageEngine>,
        adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
    ) -> Self {
        Self {
            lineage_engine,
            adjudicator,
        }
    }

    /// Evaluates live endpoint taint states and handles autonomous DLP Lineage containment triggers.
    pub async fn evaluate_dlp_trigger(&self, state: &mut KillSwitchGraphState) -> Result<Option<ThreatCandidate>> {
        let tainted_procs = self.lineage_engine.all_tainted_processes();

        for proc in tainted_procs {
            let proc_key = self.lineage_engine.find_process_by_pid(proc.proc_key.pid).unwrap_or(proc.proc_key);

            // Fast inline evaluation of egress state
            let destination = "https://egress-check.internal";
            let verdict = self.lineage_engine.evaluate_egress(proc_key, destination);

            if let EgressVerdict::Block { reason, trace_id, classification, policy, source_hashes } = verdict {
                if policy == DlpPolicy::Quarantine || classification == DlpClassification::CrownJewel {
                    let is_critical = is_critical_system_pid(proc_key.pid, &proc.exe_path);

                    let adj_verdict = AdjEgressVerdict::Block {
                        reason: reason.clone(),
                        trace_id: trace_id.clone(),
                    };

                    let adj_baggage = proc.baggage.as_ref().map(|b| {
                        let adj_class = match b.classification {
                            DlpClassification::Public => AdjClassification::Public,
                            DlpClassification::Internal => AdjClassification::Internal,
                            DlpClassification::Confidential => AdjClassification::Confidential,
                            DlpClassification::CrownJewel => AdjClassification::CrownJewel,
                        };
                        let adj_pol = match b.policy {
                            DlpPolicy::Allow => AdjPolicy::Allow,
                            DlpPolicy::Audit => AdjPolicy::Audit,
                            DlpPolicy::Block | DlpPolicy::Quarantine => AdjPolicy::Quarantine,
                        };
                        AdjBaggage::new(adj_class, adj_pol, &b.source_sha256)
                    });

                    let adj_datasets: Vec<AdjDataset> = proc.input_datasets.iter().map(|d| {
                        let adj_class = match d.facets.dlp_classification {
                            DlpClassification::Public => AdjClassification::Public,
                            DlpClassification::Internal => AdjClassification::Internal,
                            DlpClassification::Confidential => AdjClassification::Confidential,
                            DlpClassification::CrownJewel => AdjClassification::CrownJewel,
                        };
                        AdjDataset {
                            namespace: d.namespace.clone(),
                            name: d.name.clone(),
                            facets: AdjFacets {
                                content_sha256: d.facets.content_sha256.clone(),
                                dlp_classification: adj_class,
                            },
                        }
                    }).collect();

                    let adj_links: Vec<LineageCausalLink> = proc.causal_links.iter().map(|l| {
                        LineageCausalLink {
                            trace_id: l.span_context.trace_id().to_string(),
                            span_id: l.span_context.span_id().to_string(),
                            role: "INPUT".to_string(),
                            file_path: String::new(),
                        }
                    }).collect();

                    let evidence = LineageAdjudicationEvidence {
                        actor_pid: proc_key.pid,
                        actor_exe: proc.exe_path.clone(),
                        parent_pid: proc.parent_pid,
                        destination: destination.to_string(),
                        egress_verdict: adj_verdict,
                        baggage: adj_baggage,
                        causal_links: adj_links,
                        input_datasets: adj_datasets,
                        provenance_hops: proc.provenance_hops.clone(),
                    };

                    let candidate = ThreatCandidate::new(
                        Some(proc_key.pid),
                        &proc.exe_path,
                        "EndpointLineageEngine",
                        &reason,
                        0.96,
                        EvidenceClass::Behavior,
                    );

                    let context = AdjudicationContext {
                        lineage_evidence: Some(evidence),
                        security_event: None,
                        process_ancestry: vec![],
                        is_dev_environment: false,
                    };

                    // Run through 5-layer Zero-False-Positive Adjudication Gate
                    let adj_result = self.adjudicator.adjudicate_threat_candidate(&candidate, Some(&context)).await;
                    if let AdjudicationResult::ConfirmedThreat { .. } = adj_result {
                        info!("🚨 [LINEAGE-AUTONOMOUS-TRIGGER] DLP Lineage confirmed threat for PID {}", proc_key.pid);

                        // Store Lineage Provenance in State Metadata
                        state.metadata.insert("lineage_trace_id".to_string(), trace_id);
                        state.metadata.insert("lineage_source_hashes".to_string(), source_hashes.join(","));
                        state.metadata.insert("lineage_classification".to_string(), format!("{:?}", classification));
                        state.metadata.insert("lineage_policy".to_string(), format!("{:?}", policy));
                        state.metadata.insert("lineage_critical_pid_preserved".to_string(), is_critical.to_string());

                        return Ok(Some(candidate));
                    }
                }
            }
        }

        Ok(None)
    }
}
