pub mod capture;
pub mod detectors;
pub mod diagnosis;
pub mod entity;
pub mod investigation;
pub mod normalizer;
pub mod probes;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
