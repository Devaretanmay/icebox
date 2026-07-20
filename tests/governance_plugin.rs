//! Governance-plugin test surface (formerly `icebox-governance`).
//!
//! In ICEBOX v2 the v1 governance kernel is preserved as an OPTIONAL plugin,
//! off by default. These integration tests validate that plugin: RBAC, the
//! approval queue, policy rules, audit export, REST auth, and end-to-end
//! safety-kernel assertions. They are not part of the core Session product.

#[path = "governance_plugin/governance.rs"]
mod governance;

#[path = "governance_plugin/rest_auth.rs"]
mod rest_auth;

#[path = "governance_plugin/eval.rs"]
mod eval;
