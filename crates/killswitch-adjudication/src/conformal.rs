//! Multi-Source Conformal Sequential Detection for Unseen LLM Jailbreak Sources.
//!
//! Captures:
//! - Finite-memory sliding window detector (Persist-L / Persist-3: W=10, L=3, B=12)
//! - Full-history Shiryaev-Roberts detector with DKW adjustments (SR-DKW / SR-RAW)
//! - Layered guardrail escalation logic (I_t^{(G+M)} = G_t \lor A_t^{(M)})
//! - Theoretical bounds (Overlap weight sum A_{W,L}, Theorem 4.3, Corollary 4.7)

pub mod linalg;
pub use linalg::{Array1, Array2};
use std::collections::VecDeque;

/// Represents a calibrated known attack source k in the projected PCA space.
#[derive(Clone, Debug)]
pub struct CalibratedSource {
    /// Mean vector \hat{\mu}_k in the projected space (dimension d).
    pub mean: Array1<f64>,
    /// Moore-Penrose pseudoinverse of the Ledoit-Wolf covariance \hat{\Sigma}_k^+ (d x d).
    pub precision_matrix: Array2<f64>,
    /// Calibration nonconformity scores R_{k,i} sorted in ascending order for O(log n_k) lookup.
    pub sorted_cal_scores: Vec<f64>,
}

impl CalibratedSource {
    pub fn new(
        mean: Array1<f64>,
        precision_matrix: Array2<f64>,
        mut cal_scores: Vec<f64>,
    ) -> Self {
        cal_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Self {
            mean,
            precision_matrix,
            sorted_cal_scores: cal_scores,
        }
    }

    /// Equation (1): S_k(x) = (z - \hat{\mu}_k)^T \hat{\Sigma}_k^+ (z - \hat{\mu}_k)
    pub fn nonconformity_score(&self, z: &Array1<f64>) -> f64 {
        let diff = z - &self.mean;
        let temp = self.precision_matrix.dot(&diff);
        diff.dot(&temp).max(0.0)
    }

    /// Equation (2): p_k(x) = (1 + \sum_{i=1}^{n_k} I{R_{k,i} >= S_k(x)}) / (n_k + 1)
    pub fn conformal_p_value(&self, score: f64) -> f64 {
        let n_k = self.sorted_cal_scores.len();
        if n_k == 0 {
            return 1.0;
        }
        // Find the first index where R_{k,i} >= score
        let idx = self.sorted_cal_scores.partition_point(|&r| r < score);
        let count_ge = n_k - idx;
        (1.0 + count_ge as f64) / (n_k as f64 + 1.0)
    }

    /// Evidence transformation: Z_k(x) = -log p_k(x)
    pub fn evidence(&self, z: &Array1<f64>) -> f64 {
        let score = self.nonconformity_score(z);
        let p = self.conformal_p_value(score);
        -p.ln()
    }

    pub fn calibration_size(&self) -> usize {
        self.sorted_cal_scores.len()
    }
}

/// Shared offline calibration model holding the PCA projection map \Pi and all K known sources.
#[derive(Clone, Debug)]
pub struct MultiSourceCalibration {
    /// Shared PCA projection matrix \Pi of shape (d, original_dim) where d <= 32.
    pub pca_projection: Array2<f64>,
    /// Optional centering mean from pooled training data prior to PCA projection.
    pub pca_mean: Option<Array1<f64>>,
    /// The K calibrated known sources.
    pub sources: Vec<CalibratedSource>,
}

impl MultiSourceCalibration {
    pub fn new(
        pca_projection: Array2<f64>,
        pca_mean: Option<Array1<f64>>,
        sources: Vec<CalibratedSource>,
    ) -> Self {
        assert!(!sources.is_empty(), "At least one known source is required.");
        Self {
            pca_projection,
            pca_mean,
            sources,
        }
    }

    /// Projects raw hidden representation X \in \mathcal{X} into z = \Pi(X).
    pub fn project(&self, x: &Array1<f64>) -> Array1<f64> {
        match &self.pca_mean {
            Some(mean) => {
                let centered = x - mean;
                self.pca_projection.dot(&centered)
            }
            None => self.pca_projection.dot(x),
        }
    }

    /// Computes source-wise p-values (p_1(x), ..., p_K(x)) for an incoming representation.
    pub fn source_p_values(&self, x: &Array1<f64>) -> Vec<f64> {
        let z = self.project(x);
        self.sources
            .iter()
            .map(|src| {
                let s = src.nonconformity_score(&z);
                src.conformal_p_value(s)
            })
            .collect()
    }

    /// Default calibrated sources in d-dimensional space.
    pub fn default_calibrated(d: usize, original_dim: usize) -> Self {
        let mut proj = Array2::zeros((d, original_dim));
        let step = (original_dim / d).max(1);
        for i in 0..d {
            let start = i * step;
            let end = ((i + 1) * step).min(original_dim);
            let count = (end - start).max(1) as f64;
            for j in start..end {
                proj[[i, j]] = 1.0 / count.sqrt();
            }
        }

        let id_d = Array2::eye(d);

        let gen_scores = |scale: f64| -> Vec<f64> {
            (1..=100)
                .map(|i| {
                    let u = i as f64 / 101.0;
                    scale * (-((1.0 - u).ln()))
                })
                .collect()
        };

        // 4 calibrated attack distribution anchors
        let mut m1 = Array1::zeros(d);
        if d > 0 { m1[0] = 1.5; }
        let src1 = CalibratedSource::new(m1, id_d.clone(), gen_scores(1.2));

        let mut m2 = Array1::zeros(d);
        if d > 1 { m2[1] = 2.0; }
        let src2 = CalibratedSource::new(m2, id_d.clone(), gen_scores(1.5));

        let mut m3 = Array1::zeros(d);
        if d > 2 { m3[2] = 2.5; }
        let src3 = CalibratedSource::new(m3, id_d.clone(), gen_scores(1.8));

        let mut m4 = Array1::zeros(d);
        for i in 0..d { m4[i] = 1.0; }
        let src4 = CalibratedSource::new(m4, id_d, gen_scores(2.0));

        Self::new(proj, None, vec![src1, src2, src3, src4])
    }
}

/// Step-by-step diagnostic output for the Persist-L detector.
#[derive(Clone, Debug)]
pub struct PersistStepResult {
    pub step: usize,
    pub c_fam: f64,
    pub threshold_crossed: bool,
    pub consecutive_crossings: usize,
    pub alarm_raised: bool,
    pub first_alarm_step: Option<usize>,
}

/// Algorithm 1: Persist-L (Persist-3 uses W = 10, L = 3)
/// Window-based multi-source conformal detector with finite forgetting B = W + L - 1.
#[derive(Clone, Debug)]
pub struct PersistDetector {
    calibration: MultiSourceCalibration,
    window_length: usize,
    persistence_length: usize,
    threshold: f64,
    /// Sliding window storing vectors of Z_k(X_r) = -log p_k(X_r) for the last W observations.
    window: VecDeque<Vec<f64>>,
    consecutive_crossings: usize,
    current_step: usize,
    first_alarm_step: Option<usize>,
}

impl PersistDetector {
    /// Creates a new Persist-L detector. For Persist-3, pass window_length = 10, persistence_length = 3.
    pub fn new(
        calibration: MultiSourceCalibration,
        window_length: usize,
        persistence_length: usize,
        threshold: f64,
    ) -> Self {
        assert!(window_length >= 1, "Window length W must be >= 1");
        assert!(persistence_length >= 1, "Persistence length L must be >= 1");
        Self {
            calibration,
            window_length,
            persistence_length,
            threshold,
            window: VecDeque::with_capacity(window_length),
            consecutive_crossings: 0,
            current_step: 0,
            first_alarm_step: None,
        }
    }

    /// Returns the finite forgetting horizon B = W + L - 1 (Proposition 4.4).
    pub fn finite_forgetting_horizon(&self) -> usize {
        self.window_length + self.persistence_length - 1
    }

    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Processes a new victim-model hidden representation X_t.
    pub fn observe(&mut self, x: &Array1<f64>) -> PersistStepResult {
        self.current_step += 1;
        let z = self.calibration.project(x);

        let z_scores: Vec<f64> = self
            .calibration
            .sources
            .iter()
            .map(|src| src.evidence(&z))
            .collect();

        if self.window.len() == self.window_length {
            self.window.pop_front();
        }
        self.window.push_back(z_scores);

        let m_t = self.window.len() as f64;
        let num_sources = self.calibration.sources.len();

        // Equation (3) & (4): Compute C_{k,t} over the window and take C^{fam}_t = min_{k \in [K]} C_{k,t}
        let mut c_fam = f64::INFINITY;
        for k in 0..num_sources {
            let sum_k: f64 = self.window.iter().map(|step_vec| step_vec[k]).sum();
            let c_k_t = sum_k / m_t;
            if c_k_t < c_fam {
                c_fam = c_k_t;
            }
        }

        // Equation (5): Persistent confirmation A_t(\tau) = I{C^{fam}_t >= \tau}
        let crossed = c_fam >= self.threshold;
        if crossed {
            self.consecutive_crossings += 1;
        } else {
            self.consecutive_crossings = 0;
        }

        let d_t = self.current_step >= self.persistence_length
            && self.consecutive_crossings >= self.persistence_length;

        if d_t && self.first_alarm_step.is_none() {
            self.first_alarm_step = Some(self.current_step);
        }

        PersistStepResult {
            step: self.current_step,
            c_fam,
            threshold_crossed: crossed,
            consecutive_crossings: self.consecutive_crossings,
            alarm_raised: d_t,
            first_alarm_step: self.first_alarm_step,
        }
    }

    pub fn reset(&mut self) {
        self.window.clear();
        self.consecutive_crossings = 0;
        self.current_step = 0;
        self.first_alarm_step = None;
    }
}

/// Appendix F: Shiryaev-Roberts detector with DKW-adjusted or raw p-values (SR-DKW / SR-RAW).
#[derive(Clone, Debug)]
pub struct SrDetector {
    calibration: MultiSourceCalibration,
    /// Precomputed DKW inflation terms \varepsilon_k(\beta) = \sqrt{\log(2K/\beta) / (2 n_k)}.
    dkw_epsilons: Vec<f64>,
    use_dkw: bool,
    /// Betting parameter \lambda \in [0, 1] for g_\lambda(p) = 1 + \lambda(1 - 2p).
    lambda: f64,
    threshold: f64,
    r_state: f64,
    current_step: usize,
    first_alarm_step: Option<usize>,
}

impl SrDetector {
    pub fn new(
        calibration: MultiSourceCalibration,
        beta: f64,
        use_dkw: bool,
        lambda: f64,
        threshold: f64,
    ) -> Self {
        let k_float = calibration.sources.len() as f64;
        let dkw_epsilons = calibration
            .sources
            .iter()
            .map(|src| {
                let n_k = src.calibration_size() as f64;
                if n_k > 0.0 {
                    ((2.0 * k_float / beta.max(1e-12)).ln() / (2.0 * n_k)).sqrt()
                } else {
                    0.0
                }
            })
            .collect();

        Self {
            calibration,
            dkw_epsilons,
            use_dkw,
            lambda: lambda.clamp(0.0, 1.0),
            threshold,
            r_state: 0.0,
            current_step: 0,
            first_alarm_step: None,
        }
    }

    /// Updates R_{t,\lambda} = (1 + R_{t-1,\lambda}) g_\lambda(\tilde{p}^{fam}_t)
    pub fn observe(&mut self, x: &Array1<f64>) -> (f64, bool) {
        self.current_step += 1;
        let raw_p = self.calibration.source_p_values(x);

        let p_fam = raw_p
            .into_iter()
            .enumerate()
            .map(|(k, p_k)| {
                if self.use_dkw {
                    (p_k + self.dkw_epsilons[k]).min(1.0)
                } else {
                    p_k
                }
            })
            .fold(0.0_f64, f64::max);

        let g_val = 1.0 + self.lambda * (1.0 - 2.0 * p_fam);
        self.r_state = (1.0 + self.r_state) * g_val;

        let alarm = self.r_state >= self.threshold;
        if alarm && self.first_alarm_step.is_none() {
            self.first_alarm_step = Some(self.current_step);
        }

        (self.r_state, alarm)
    }

    pub fn r_state(&self) -> f64 {
        self.r_state
    }

    pub fn reset(&mut self) {
        self.r_state = 0.0;
        self.current_step = 0;
        self.first_alarm_step = None;
    }
}

/// Section 3.6: Layered Intervention Policy combining a prompt-level guardrail G_t and monitor M.
/// Implements I^{(G+M)}_t = G_t \lor A^{(M)}_t where A^{(M)}_t = I{t >= T^{(M)}_{act}}.
#[derive(Clone, Debug)]
pub struct LayeredGuardrail {
    monitor: PersistDetector,
    escalated: bool,
}

impl LayeredGuardrail {
    pub fn new(monitor: PersistDetector) -> Self {
        Self {
            monitor,
            escalated: false,
        }
    }

    /// Evaluates prompt t given the base guardrail decision `g_t` and hidden representation `x_t`.
    /// Returns true if the system should intervene (block or escalate to strict review).
    pub fn evaluate_step(&mut self, g_t: bool, x_t: &Array1<f64>) -> bool {
        let res = self.monitor.observe(x_t);
        if res.alarm_raised {
            self.escalated = true;
        }
        g_t || self.escalated
    }

    pub fn is_escalated(&self) -> bool {
        self.escalated
    }

    pub fn reset(&mut self) {
        self.monitor.reset();
        self.escalated = false;
    }
}

/// Deterministic projection bridge mapping text prompts to feature vectors in R^{dim}.
pub fn project_text_to_feature_vector(text: &str, dim: usize) -> Array1<f64> {
    assert!(dim > 0, "Feature dimension must be > 0");
    let mut vec = Array1::zeros(dim);
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return vec;
    }

    for w in bytes.windows(3) {
        let h = ((w[0] as usize) << 16) | ((w[1] as usize) << 8) | (w[2] as usize);
        let idx = h % dim;
        vec[idx] += 1.0;
    }

    let mut freq = [0usize; 256];
    for &b in bytes {
        freq[b as usize] += 1;
    }
    let len_f = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / len_f;
            entropy -= p * p.log2();
        }
    }
    vec[0] += entropy * 2.0;

    let norm = vec.dot(&vec).sqrt();
    if norm > 1e-12 {
        vec /= norm;
    }
    vec
}

/// Theoretical Guarantee Utilities from Section 4
pub mod bounds {
    /// Equation (6): Computes overlap weight sum A_{W,L} = \sum_{h=1}^B a_h^2 for W >= L.
    pub fn compute_a_w_l(w: usize, l: usize) -> usize {
        assert!(w >= l, "Equation (6) assumes W >= L");
        let sum_squares: usize = (1..l).map(|r| r * r).sum();
        2 * sum_squares + (w - l + 1) * l * l
    }

    /// Equation (7), Theorem 4.3: Persistence-aware stationary false-alarm upper bound under source P_j.
    pub fn stationary_false_alarm_bound(
        w: usize,
        l: usize,
        tau: f64,
        mu_0_j: f64,
        n_j: usize,
    ) -> f64 {
        if tau <= mu_0_j {
            return 1.0;
        }
        let b_j = ((n_j + 1) as f64).ln();
        let a_wl = compute_a_w_l(w, l) as f64;
        let lw = (l * w) as f64;
        let gap = tau - mu_0_j;
        let exponent = -2.0 * lw.powi(2) * gap.powi(2) / (b_j.powi(2) * a_wl);
        exponent.exp().min(1.0)
    }

    /// Equation (9), Corollary 4.7: Nearest-source separation detection power lower bound.
    pub fn nearest_source_power_bound(
        w: usize,
        l: usize,
        k_sources: usize,
        delta_star: f64,
        max_n_k: usize,
    ) -> f64 {
        if delta_star <= 0.0 {
            return 0.0;
        }
        let b_max = ((max_n_k + 1) as f64).ln();
        let exponent = -2.0 * (w as f64) * delta_star.powi(2) / b_max.powi(2);
        let penalty = (l * k_sources) as f64 * exponent.exp();
        (1.0 - penalty).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::array;

    #[test]
    fn test_effective_sample_size_and_finite_forgetting() {
        // Verify paper example in Section 4.2: W = 10, L = 3 gives A_{10,3} = 82
        let a_10_3 = bounds::compute_a_w_l(10, 3);
        assert_eq!(a_10_3, 82);

        // Build a two-source mock calibration in 2D projected space
        let pca = Array2::eye(2);
        let src1 = CalibratedSource::new(
            array![0.0, 0.0],
            Array2::eye(2),
            vec![0.1, 0.2, 0.5, 0.8, 1.2, 1.5, 2.0, 2.5, 3.0],
        );
        let src2 = CalibratedSource::new(
            array![5.0, 5.0],
            Array2::eye(2),
            vec![0.1, 0.3, 0.6, 0.9, 1.1, 1.4, 1.9, 2.2, 2.8],
        );

        let cal = MultiSourceCalibration::new(pca, None, vec![src1, src2]);
        let mut detector1 = PersistDetector::new(cal.clone(), 10, 3, 2.0);
        let mut detector2 = PersistDetector::new(cal, 10, 3, 2.0);

        // Verify Proposition 4.4 (Finite forgetting after B = 12 steps)
        assert_eq!(detector1.finite_forgetting_horizon(), 12);

        // Feed different pre-switch histories into detector1 and detector2
        for _ in 0..5 {
            detector1.observe(&array![0.1, 0.1]); // Near source 1
            detector2.observe(&array![20.0, 20.0]); // Far unseen source
        }

        // Feed 12 identical post-switch observations from source 2
        let mut res1 = None;
        let mut res2 = None;
        for _ in 0..12 {
            res1 = Some(detector1.observe(&array![5.1, 4.9]));
            res2 = Some(detector2.observe(&array![5.1, 4.9]));
        }

        let r1 = res1.unwrap();
        let r2 = res2.unwrap();
        assert!((r1.c_fam - r2.c_fam).abs() < 1e-12);
        assert_eq!(r1.alarm_raised, r2.alarm_raised);
    }

    #[test]
    fn test_sr_detector_dkw_escalation() {
        let pca = Array2::eye(2);
        let cal_scores: Vec<f64> = (1..=100).map(|i| i as f64 * 0.05).collect();
        let src = CalibratedSource::new(
            array![0.0, 0.0],
            Array2::eye(2),
            cal_scores,
        );
        let cal = MultiSourceCalibration::new(pca, None, vec![src]);

        let mut sr = SrDetector::new(cal, 0.05, true, 0.5, 5.0);
        assert_eq!(sr.r_state(), 0.0);

        let mut alarmed = false;
        for _ in 0..10 {
            let (_, alarm) = sr.observe(&array![5.0, 5.0]);
            if alarm {
                alarmed = true;
                break;
            }
        }
        assert!(alarmed);
        assert!(sr.r_state() >= 5.0);
    }

    #[test]
    fn test_layered_guardrail_persistence_latch() {
        let pca = Array2::eye(2);
        let src = CalibratedSource::new(
            array![0.0, 0.0],
            Array2::eye(2),
            vec![0.1, 0.2, 0.5, 0.8, 1.0],
        );
        let cal = MultiSourceCalibration::new(pca, None, vec![src]);
        let persist = PersistDetector::new(cal, 5, 2, 1.0);
        let mut guard = LayeredGuardrail::new(persist);

        assert!(!guard.is_escalated());

        let _ = guard.evaluate_step(false, &array![3.0, 3.0]);
        let _ = guard.evaluate_step(false, &array![3.0, 3.0]);

        assert!(guard.is_escalated());
        assert!(guard.evaluate_step(false, &array![0.0, 0.0]));
    }
}
