//! CLI enrollment role selection. Existing Teacher workflow stays the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentCliRole {
    Teacher,
    StudentDevice,
}

impl EnrollmentCliRole {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "teacher" => Ok(Self::Teacher),
            "student-device" => Ok(Self::StudentDevice),
            _ => Err("--role must be teacher or student-device"),
        }
    }

    pub const fn key_prefix(self) -> &'static str {
        match self {
            Self::Teacher => "ClassMesh-Teacher",
            Self::StudentDevice => "ClassMesh-StudentDevice",
        }
    }

    pub const fn common_name_label(self) -> &'static str {
        match self {
            Self::Teacher => "Teacher",
            Self::StudentDevice => "Student Device",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EnrollmentCliRole;

    #[test]
    fn enrollment_roles_require_explicit_known_spelling() {
        assert_eq!(
            EnrollmentCliRole::parse("teacher"),
            Ok(EnrollmentCliRole::Teacher)
        );
        assert_eq!(
            EnrollmentCliRole::parse("student-device"),
            Ok(EnrollmentCliRole::StudentDevice)
        );
        for wrong in [
            "",
            "student",
            "admin",
            "service",
            "Teacher",
            "student-device ",
        ] {
            assert!(
                EnrollmentCliRole::parse(wrong).is_err(),
                "incorrectly accepted {wrong:?}"
            );
        }
    }

    #[test]
    fn teacher_and_student_keys_use_nonoverlapping_namespaces() {
        assert_eq!(EnrollmentCliRole::Teacher.key_prefix(), "ClassMesh-Teacher");
        assert_eq!(
            EnrollmentCliRole::StudentDevice.key_prefix(),
            "ClassMesh-StudentDevice"
        );
        assert_ne!(
            EnrollmentCliRole::Teacher.common_name_label(),
            EnrollmentCliRole::StudentDevice.common_name_label()
        );
    }
}
