pub mod capture;
pub mod detectors;
pub mod diagnosis;
pub mod entity;
pub mod normalizer;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
