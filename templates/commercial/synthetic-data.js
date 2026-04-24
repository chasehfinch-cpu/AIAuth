// AIAuth synthetic data generator
// Produces data in the EXACT shape of /v1/admin/dashboard/data so that
// the commercial demo templates render identically with synthetic or
// real data. See CLAUDE.md "Dashboard Data Contract".

(function (global) {
  "use strict";

  const DEFAULT_COMPANY = "Acme Financial Services";
  const DEFAULT_DEPARTMENTS = [
    { name: "Finance",     reviewRate: 0.94, rubberRate: 0.02, topModel: "claude",   size: 28 },
    { name: "Legal",       reviewRate: 0.96, rubberRate: 0.01, topModel: "claude",   size: 14 },
    { name: "Engineering", reviewRate: 0.82, rubberRate: 0.05, topModel: "copilot",  size: 46 },
    { name: "Marketing",   reviewRate: 0.71, rubberRate: 0.11, topModel: "chatgpt",  size: 22 },
    { name: "HR",          reviewRate: 0.89, rubberRate: 0.03, topModel: "chatgpt",  size: 12 },
    { name: "Operations",  reviewRate: 0.86, rubberRate: 0.04, topModel: "copilot",  size: 21 },
  ];

  const MODELS = [
    { model: "claude",         provider: "anthropic" },
    { model: "chatgpt",        provider: "openai"    },
    { model: "copilot",        provider: "microsoft" },
    { model: "gemini",         provider: "google"    },
    { model: "github-copilot", provider: "microsoft" },
  ];

  const TTA_BUCKETS = ["0-10s", "10-30s", "30-60s", "1-5m", "5-15m", "15m+"];

  function gradeFor(rr, critical) {
    if (critical > 0 && rr < 0.95) return "F";
    if (rr >= 0.95 && critical === 0) return "A";
    if (rr >= 0.85) return "B";
    if (rr >= 0.70) return "C";
    if (rr >= 0.50) return "D";
    return "F";
  }

  function generateDashboardData(options = {}) {
    const company = options.company || DEFAULT_COMPANY;
    const deptSpecs = options.departments || DEFAULT_DEPARTMENTS;
    const daysBack = options.days || 30;

    const now = new Date();
    const from_ = new Date(now.getTime() - daysBack * 86400000);

    // Summary counts — derived from department specs so everything is
    // internally consistent.
    const totalUsers = deptSpecs.reduce((n, d) => n + d.size, 0);
    const attestsPerUserPerDay = 2.3;
    const totalAttestations = Math.round(totalUsers * attestsPerUserPerDay * daysBack);

    const by_department = deptSpecs.map((d) => {
      const total = Math.round(d.size * attestsPerUserPerDay * daysBack);
      const reviewed = Math.round(total * d.reviewRate);
      const rubber = Math.round(total * d.rubberRate);
      const extExposure = Math.round(total * 0.07);
      const critical = d.reviewRate < 0.8 ? 1 : 0;
      const high = d.reviewRate < 0.85 ? 3 : 1;
      const medium = Math.round(total * 0.01);
      const low = Math.round(total * 0.02);
      return {
        department: d.name,
        total,
        unique_users: d.size,
        review_rate: d.reviewRate,
        rubber_stamp_rate: d.rubberRate,
        avg_tta: 60 + Math.round((1 - d.reviewRate) * 300),
        external_exposure: extExposure,
        violations: { critical, high, medium, low },
        grade: gradeFor(d.reviewRate, critical),
      };
    });

    const totalReviewed = by_department.reduce((n, d) => n + d.total * d.review_rate, 0);
    const totalRubber = by_department.reduce((n, d) => n + d.total * d.rubber_stamp_rate, 0);
    const totalExtExposure = by_department.reduce((n, d) => n + d.external_exposure, 0);
    const totalViolations = by_department.reduce((acc, d) => {
      for (const k of Object.keys(acc)) acc[k] += d.violations[k];
      return acc;
    }, { critical: 0, high: 0, medium: 0, low: 0 });

    const by_model = MODELS.map((m, i) => ({
      model: m.model, provider: m.provider,
      count: Math.round(totalAttestations * [0.41, 0.27, 0.20, 0.08, 0.04][i]),
      avg_tta: 80 + i * 12,
    })).filter((m) => m.count > 0);

    // TTA distribution — realistic bell curve with a visible rubber-stamp bucket
    const ttaWeights = { "0-10s": 0.03, "10-30s": 0.09, "30-60s": 0.26, "1-5m": 0.40, "5-15m": 0.16, "15m+": 0.06 };
    const tta_buckets = TTA_BUCKETS.map((k) => ({
      range: k, count: Math.round(totalAttestations * ttaWeights[k]),
      flagged: k === "0-10s",
    }));

    const topOffenders = by_department
      .filter((d) => d.rubber_stamp_rate > 0.05)
      .slice(0, 3)
      .map((d, i) => ({
        uid: `user${i + 1}@${company.toLowerCase().replace(/\s+/g, "")}.com`,
        count: Math.round(d.total * d.rubber_stamp_rate * 0.3),
        department: d.department,
      }));

    const shadow_by_app = [
      { app: "chatgpt-desktop", times_open: 3402, times_attested_from: 2180, shadow_ratio: 0.36,
        interpretation: "open but not attesting — potential ungoverned use" },
      { app: "poe-desktop",      times_open: 412,  times_attested_from: 31,   shadow_ratio: 0.92,
        interpretation: "open but not attesting — potential ungoverned use" },
      { app: "perplexity-desktop", times_open: 198, times_attested_from: 140, shadow_ratio: 0.29,
        interpretation: "open but not attesting — potential ungoverned use" },
    ];

    return {
      meta: {
        org_id: "ORG_demo12345",
        org_name: company,
        date_range: { from: from_.toISOString(), to: now.toISOString() },
        filters_applied: { department: null, model: null, classification: null },
        generated_at: now.toISOString(),
        schema_version: "0.5.0",
        synthetic: true,
      },
      summary: {
        total_attestations: totalAttestations,
        unique_users: totalUsers,
        unique_sessions: Math.round(totalAttestations * 0.7),
        review_rate: Math.round((totalReviewed / totalAttestations) * 1000) / 1000,
        rubber_stamp_count: Math.round(totalRubber),
        rubber_stamp_rate: Math.round((totalRubber / totalAttestations) * 10000) / 10000,
        external_exposure_count: totalExtExposure,
        chain_break_count: Math.round(totalAttestations * 0.001),
        policy_violations: totalViolations,
        avg_tta_seconds: 127,
        median_tta_seconds: 84,
        prompt_hash_coverage: 0.92,
        ai_authored_detected: Math.round(totalAttestations * 0.033),
        shadow_ai_alerts: shadow_by_app.filter((s) => s.shadow_ratio > 0.2).length,
      },
      by_department,
      by_model,
      by_time: { bucket_size: "week", buckets: [] },
      tta_distribution: {
        buckets: tta_buckets,
        rubber_stamps: {
          count: Math.round(totalRubber),
          threshold: { tta_under: 10, len_over: 500 },
          top_offenders: topOffenders,
        },
      },
      file_types: [
        { type: "text",         count: Math.round(totalAttestations * 0.40) },
        { type: "code",         count: Math.round(totalAttestations * 0.24) },
        { type: "spreadsheet",  count: Math.round(totalAttestations * 0.16) },
        { type: "document",     count: Math.round(totalAttestations * 0.11) },
        { type: "presentation", count: Math.round(totalAttestations * 0.05) },
        { type: "data",         count: Math.round(totalAttestations * 0.04) },
      ],
      external_exposure: {
        total: totalExtExposure,
        by_destination: [
          { dest: "email",            count: Math.round(totalExtExposure * 0.47), external: Math.round(totalExtExposure * 0.43) },
          { dest: "messaging",        count: Math.round(totalExtExposure * 0.35), external: Math.round(totalExtExposure * 0.24) },
          { dest: "code-repository",  count: Math.round(totalExtExposure * 0.18), external: Math.round(totalExtExposure * 0.05) },
        ],
        by_classification: [
          { classification: "client-facing", count: Math.round(totalExtExposure * 0.38) },
          { classification: "financial",     count: Math.round(totalExtExposure * 0.10) },
          { classification: "internal",      count: Math.round(totalExtExposure * 0.52) },
        ],
      },
      chain_integrity: {
        total_chains: 340,
        complete_chains: 328,
        broken_chains: 12,
        breaks: [
          { doc_id: "DOC_abc123", gap_at: from_.toISOString(),
            missing_parent_hash: "e3b0c4...", chain_length_before_break: 4, chain_length_after_break: 2 },
        ],
      },
      // Commercial-KPI-Honesty PR (2026-04-24): canonical cross-format
      // block. Production server populates these from real queries on
      // enterprise_attestations.content_hash_canonical + policy_violations.
      // Synthetic demo numbers here are plausible for a mid-size pilot.
      cross_format: {
        canonical_groups: 340,
        multi_format_documents: 47,
        ai_authored_artifacts: Math.round(totalAttestations * 0.033),
        ungoverned_ai_content: Math.round(totalAttestations * 0.002),
      },
      recent_violations: [
        { id: 1, attestation_id: "a1b2c3", policy_id: "no-rubber-stamping",
          severity: "medium", details: { tta: 3, len: 4200, uid: "bob@" + company.toLowerCase().replace(/\s+/g, "") + ".com" },
          detected_at: now.toISOString(), resolved: false },
      ],
      shadow_ai_heatmap: {
        total_unique_apps_detected: shadow_by_app.length,
        by_app: shadow_by_app,
        by_department: deptSpecs.slice(0, 3).map((d) => ({
          department: d.name,
          top_shadow_apps: ["poe-desktop", "perplexity-desktop"],
          shadow_ratio: 0.25 + Math.random() * 0.3,
        })),
      },
      ai_authorship: {
        total_with_markers: Math.round(totalAttestations * 0.033),
        by_source: [
          { source: "docx-copilot",   count: Math.round(totalAttestations * 0.016) },
          { source: "pdf-chatgpt",    count: Math.round(totalAttestations * 0.009) },
          { source: "c2pa",           count: Math.round(totalAttestations * 0.008) },
        ],
        unattested_with_markers: {
          count: Math.round(totalAttestations * 0.001),
          interpretation: "AI-authored content appearing in chain without attestation",
        },
      },
    };
  }

  // Export to browser + Node
  global.AIAuthSynthetic = { generateDashboardData };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { generateDashboardData };
  }
})(typeof window !== "undefined" ? window : globalThis);
