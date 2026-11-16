//! Compiled only under the non-shipping `synthetic-oci-input-smoke` feature.
//!
//! The feature changes only lines inside files every build compiles, so this
//! empty module is what puts it in a build's dep-info: release admission
//! refuses a `cw` whose dep-info lists this file (`cw_release.py`
//! `NON_SHIPPING_INPUTS`, #4986).
