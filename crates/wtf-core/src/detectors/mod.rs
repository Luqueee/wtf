use serde::{Deserialize, Serialize};

use crate::capture::CommandExecution;
use crate::entity::ExtractedEntities;
use crate::normalizer::NormalizedOutput;

pub mod command_not_found;
pub mod connection_refused;
pub mod disk_full;
pub mod file_not_found;
pub mod permission_denied;
pub mod port_conflict;

pub use command_not_found::CommandNotFoundDetector;
pub use connection_refused::ConnectionRefusedDetector;
pub use disk_full::DiskFullDetector;
pub use file_not_found::FileNotFoundDetector;
pub use permission_denied::PermissionDeniedDetector;
pub use port_conflict::PortConflictDetector;

/// Context passed to each detector during diagnostic analysis.
pub struct DiagnosisContext<'a> {
    pub execution: &'a CommandExecution,
    pub normalized: &'a NormalizedOutput,
    pub entities: &'a ExtractedEntities,
}

/// A diagnostic finding produced by a detector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    pub detector_id: String,
    pub category: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub entities: ExtractedEntities,
    pub confidence: f32,
    pub remedy: Option<String>,
}

/// Trait implemented by all deterministic failure detectors.
pub trait Detector: Send + Sync {
    fn id(&self) -> &'static str;
    fn detect(&self, ctx: &DiagnosisContext) -> Option<Detection>;
}

/// Returns the default list of built-in deterministic detectors.
pub fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(CommandNotFoundDetector),
        Box::new(FileNotFoundDetector),
        Box::new(PermissionDeniedDetector),
        Box::new(PortConflictDetector),
        Box::new(ConnectionRefusedDetector),
        Box::new(DiskFullDetector),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CommandExecution, ProcessExit};
    use crate::entity::EntityExtractor;
    use crate::normalizer::OutputNormalizer;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn test_context<'a>(
        exec: &'a CommandExecution,
        norm: &'a NormalizedOutput,
        entities: &'a ExtractedEntities,
    ) -> DiagnosisContext<'a> {
        DiagnosisContext {
            execution: exec,
            normalized: norm,
            entities,
        }
    }

    fn create_test_setup(
        cmd: &str,
        args: &[&str],
        stdout: &str,
        stderr: &str,
        exit_code: i32,
        spawn_error: Option<String>,
    ) -> (CommandExecution, NormalizedOutput, ExtractedEntities) {
        let exec = CommandExecution {
            command: cmd.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: PathBuf::from("/test"),
            exit_status: ProcessExit {
                code: Some(exit_code),
                signal: None,
            },
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            duration: Duration::from_millis(5),
            timestamp: SystemTime::now(),
            spawn_error,
        };
        let norm = OutputNormalizer::normalize(stdout, stderr);
        let entities = EntityExtractor::extract(&exec, &norm);
        (exec, norm, entities)
    }

    #[test]
    fn test_file_not_found_detection() {
        let (exec, norm, entities) = create_test_setup(
            "cat",
            &["/foo/bar"],
            "",
            "cat: /foo/bar: No such file or directory\n",
            1,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = FileNotFoundDetector;
        let res = detector.detect(&ctx).expect("must detect file not found");
        assert_eq!(res.category, "filesystem/not-found");
        assert_eq!(res.summary, "File does not exist.");
        assert_eq!(
            res.evidence,
            vec!["cat: /foo/bar: No such file or directory"]
        );
        assert_eq!(
            res.entities.primary_path(),
            Some(&PathBuf::from("/foo/bar"))
        );
    }

    #[test]
    fn test_port_conflict_detection() {
        let (exec, norm, entities) = create_test_setup(
            "docker",
            &["run", "-p", "8080:80", "nginx"],
            "",
            "bind: address already in use\n",
            1,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = PortConflictDetector;
        let res = detector.detect(&ctx).expect("must detect port conflict");
        assert_eq!(res.category, "network/port-conflict");
        assert_eq!(res.summary, "Port 8080 is already in use.");
        assert_eq!(res.evidence, vec!["bind: address already in use"]);
        assert_eq!(res.entities.primary_port(), Some(8080));
    }

    #[test]
    fn test_command_not_found_spawn_error() {
        let (exec, norm, entities) = create_test_setup(
            "bogus_tool",
            &[],
            "",
            "wtf: failed to execute 'bogus_tool': No such file or directory",
            127,
            Some("No such file or directory".to_string()),
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = CommandNotFoundDetector;
        let res = detector
            .detect(&ctx)
            .expect("must detect command not found");
        assert_eq!(res.category, "command/not-found");
        assert!(res.summary.contains("bogus_tool"));
    }

    #[test]
    fn test_permission_denied_detection() {
        let (exec, norm, entities) = create_test_setup(
            "cat",
            &["/etc/shadow"],
            "",
            "cat: /etc/shadow: Permission denied\n",
            1,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = PermissionDeniedDetector;
        let res = detector
            .detect(&ctx)
            .expect("must detect permission denied");
        assert_eq!(res.category, "filesystem/permission-denied");
        assert_eq!(res.summary, "Permission denied.");
        assert_eq!(
            res.entities.primary_path(),
            Some(&PathBuf::from("/etc/shadow"))
        );
    }

    #[test]
    fn test_connection_refused_detection() {
        let (exec, norm, entities) = create_test_setup(
            "curl",
            &["http://localhost:5432"],
            "",
            "curl: (7) Failed to connect to localhost port 5432: Connection refused\n",
            7,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = ConnectionRefusedDetector;
        let res = detector
            .detect(&ctx)
            .expect("must detect connection refused");
        assert_eq!(res.category, "network/connection-refused");
        assert_eq!(res.summary, "Connection to port 5432 was refused.");
        assert_eq!(res.entities.primary_port(), Some(5432));
    }

    #[test]
    fn test_disk_full_detection() {
        let (exec, norm, entities) = create_test_setup(
            "dd",
            &["if=/dev/zero", "of=/tmp/bigfile"],
            "",
            "dd: error writing '/tmp/bigfile': No space left on device\n",
            1,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = DiskFullDetector;
        let res = detector.detect(&ctx).expect("must detect disk full");
        assert_eq!(res.category, "filesystem/disk-full");
        assert_eq!(res.summary, "No space left on device.");
    }

    #[test]
    fn test_linux_gnu_cannot_access_quotes() {
        let (exec, norm, entities) = create_test_setup(
            "ls",
            &["/var/log/missing"],
            "",
            "ls: cannot access '/var/log/missing': No such file or directory\n",
            2,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = FileNotFoundDetector;
        let res = detector.detect(&ctx).expect("must detect file not found");
        assert_eq!(res.category, "filesystem/not-found");
        assert_eq!(
            res.entities.primary_path(),
            Some(&PathBuf::from("/var/log/missing"))
        );
    }

    #[test]
    fn test_linux_gnu_unicode_directional_quotes() {
        let (exec, norm, entities) = create_test_setup(
            "cat",
            &["/etc/missing.conf"],
            "",
            "cat: ‘/etc/missing.conf’: No such file or directory\n",
            1,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = FileNotFoundDetector;
        let res = detector.detect(&ctx).expect("must detect file not found");
        assert_eq!(res.category, "filesystem/not-found");
        assert_eq!(
            res.entities.primary_path(),
            Some(&PathBuf::from("/etc/missing.conf"))
        );
    }

    #[test]
    fn test_linux_ubuntu_dash_command_not_found() {
        let (exec, norm, entities) = create_test_setup(
            "sh",
            &["-c", "bogus_app"],
            "",
            "sh: 1: bogus_app: not found\n",
            127,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = CommandNotFoundDetector;
        let res = detector
            .detect(&ctx)
            .expect("must detect command not found");
        assert_eq!(res.category, "command/not-found");
    }

    #[test]
    fn test_linux_gnu_mkdir_permission_denied() {
        let (exec, norm, entities) = create_test_setup(
            "mkdir",
            &["/root/secret"],
            "",
            "mkdir: cannot create directory ‘/root/secret’: Permission denied\n",
            1,
            None,
        );
        let ctx = test_context(&exec, &norm, &entities);
        let detector = PermissionDeniedDetector;
        let res = detector
            .detect(&ctx)
            .expect("must detect permission denied");
        assert_eq!(res.category, "filesystem/permission-denied");
        assert_eq!(
            res.entities.primary_path(),
            Some(&PathBuf::from("/root/secret"))
        );
    }
}
