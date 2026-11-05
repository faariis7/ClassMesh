//! Explicit disposable lab authority names; no arbitrary key deletion targets.
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LabSession {
    pub id: String,
    pub directory: PathBuf,
    pub key_name: String,
}

impl LabSession {
    pub fn new(temp: &Path, id: &str) -> Result<Self, &'static str> {
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("session must be exactly 32 lowercase hexadecimal digits");
        }
        Ok(Self {
            id: id.to_owned(),
            directory: temp.join(format!("ClassMesh-LabCA-{id}")),
            key_name: format!("ClassMesh-LabCA-{id}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_targets_only_fixed_lab_names_under_temp() {
        let temp = Path::new("temporary");
        let id = "0123456789abcdef0123456789abcdef";
        let session = LabSession::new(temp, id).expect("explicit unique lab session");
        assert_eq!(
            session.directory,
            temp.join(format!("ClassMesh-LabCA-{id}"))
        );
        assert_eq!(session.key_name, format!("ClassMesh-LabCA-{id}"));
    }

    #[test]
    fn rejects_paths_or_existing_production_key_names_as_session_ids() {
        for id in [
            "",
            "..",
            "../production",
            "ClassMesh-StudentDevice-123",
            "ABCDEF0123456789abcdef0123456789ab",
        ] {
            assert!(LabSession::new(Path::new("temporary"), id).is_err());
        }
    }
}
