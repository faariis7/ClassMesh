use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{Display, Formatter};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use p256::ecdsa::Signature;
use rcgen::{PKCS_ECDSA_P256_SHA256, PublicKeyData, SigningKey};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::NTE_BAD_SIGNATURE;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_PUBLIC_P256_MAGIC, MS_KEY_STORAGE_PROVIDER,
    NCRYPT_ALLOW_SIGNING_FLAG,
    NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_PERSIST_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, NCryptVerifySignature,
};

const SHA256_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CngKeyError {
    InvalidKeyName,
    Windows {
        operation: &'static str,
        status: i32,
    },
    UnexpectedPropertySize {
        property: &'static str,
        expected: u32,
        actual: u32,
    },
    InvalidPublicKeyBlob,
    InvalidSignatureEncoding,
}

impl Display for CngKeyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyName => write!(
                formatter,
                "CNG key name must be non-empty and contain no NUL"
            ),
            Self::Windows { operation, status } => {
                write!(
                    formatter,
                    "{operation} failed with CNG status 0x{:08x}",
                    *status as u32
                )
            }
            Self::UnexpectedPropertySize {
                property,
                expected,
                actual,
            } => write!(
                formatter,
                "{property} returned {actual} bytes; expected {expected}"
            ),
            Self::InvalidPublicKeyBlob => write!(formatter, "unexpected CNG ECDSA P-256 public key blob"),
            Self::InvalidSignatureEncoding => write!(formatter, "unexpected CNG ECDSA P-256 signature encoding"),
        }
    }
}

impl Error for CngKeyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CngMachineKey {
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CngRcgenSigningKey {
    key: CngMachineKey,
    public_key_sec1: Vec<u8>,
}

impl CngRcgenSigningKey {
    pub fn new(key: CngMachineKey) -> Result<Self, CngKeyError> {
        let public_key_sec1 = sec1_public_key_from_cng_blob(&key.public_key_blob()?)?;
        Ok(Self {
            key,
            public_key_sec1,
        })
    }

    #[must_use]
    pub fn machine_key(&self) -> &CngMachineKey {
        &self.key
    }
}

impl PublicKeyData for CngRcgenSigningKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_sec1
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for CngRcgenSigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let digest: [u8; SHA256_BYTES] = Sha256::digest(msg).into();
        let raw_signature = self
            .key
            .sign_sha256_digest(&digest)
            .map_err(|_| rcgen::Error::RemoteKeyError)?;
        let signature =
            Signature::from_slice(&raw_signature).map_err(|_| rcgen::Error::RemoteKeyError)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

impl CngMachineKey {
    /// Creates a machine-scoped ECDSA P-256 signing key in the Microsoft Software KSP.
    ///
    /// The key is persisted by CNG, is restricted to signing usage, and has an explicit
    /// export policy of zero so ClassMesh never needs private-key bytes on disk.
    pub fn create(name: impl Into<String>) -> Result<Self, CngKeyError> {
        let name = validate_key_name(name.into())?;
        let wide_name = wide_null(OsStr::new(&name));
        let provider = open_provider()?;
        let mut raw_key: NCRYPT_KEY_HANDLE = 0;

        // SAFETY: provider is a valid NCrypt provider handle, output points to writable storage,
        // algorithm/provider constants are NUL-terminated PCWSTR values, and wide_name lives
        // through the call.
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.raw as NCRYPT_PROV_HANDLE,
                &mut raw_key,
                NCRYPT_ECDSA_P256_ALGORITHM,
                wide_name.as_ptr(),
                0,
                NCRYPT_MACHINE_KEY_FLAG,
            )
        };
        check_status("NCryptCreatePersistedKey", status)?;
        let key = OwnedNcryptHandle::new(raw_key as NCRYPT_HANDLE);

        let export_policy = 0_u32;
        set_u32_property(
            key.raw,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            export_policy,
            NCRYPT_PERSIST_FLAG,
            "NCryptSetProperty(export policy)",
        )?;
        set_u32_property(
            key.raw,
            NCRYPT_KEY_USAGE_PROPERTY,
            NCRYPT_ALLOW_SIGNING_FLAG,
            NCRYPT_PERSIST_FLAG,
            "NCryptSetProperty(key usage)",
        )?;

        // SAFETY: key is a valid not-yet-finalized persisted-key handle.
        let status = unsafe { NCryptFinalizeKey(key.raw as NCRYPT_KEY_HANDLE, 0) };
        check_status("NCryptFinalizeKey", status)?;

        Ok(Self { name })
    }

    /// Verifies that a persisted machine key with this name can be opened.
    pub fn open(name: impl Into<String>) -> Result<Self, CngKeyError> {
        let name = validate_key_name(name.into())?;
        let provider = open_provider()?;
        let _key = open_key(&provider, &name)?;
        Ok(Self { name })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the public CNG ECC blob only. Private-key export is intentionally unsupported.
    pub fn public_key_blob(&self) -> Result<Vec<u8>, CngKeyError> {
        let provider = open_provider()?;
        let key = open_key(&provider, &self.name)?;
        export_blob(key.raw as NCRYPT_KEY_HANDLE, BCRYPT_ECCPUBLIC_BLOB)
    }

    /// Returns the persisted CNG export policy. ClassMesh-created keys must return zero.
    pub fn export_policy(&self) -> Result<u32, CngKeyError> {
        let provider = open_provider()?;
        let key = open_key(&provider, &self.name)?;
        get_u32_property(
            key.raw,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            "NCRYPT_EXPORT_POLICY_PROPERTY",
        )
    }

    /// Signs a SHA-256 digest using the persisted ECDSA P-256 private key.
    ///
    /// This returns CNG's native ECDSA signature representation. Conversion to the
    /// TLS signature encoding belongs in the rustls adapter planned for Phase 5C3.
    pub fn sign_sha256_digest(&self, digest: &[u8; SHA256_BYTES]) -> Result<Vec<u8>, CngKeyError> {
        let provider = open_provider()?;
        let key = open_key(&provider, &self.name)?;

        let mut signature_bytes = 0_u32;
        // SAFETY: key is valid, digest is exactly 32 readable bytes, and the first call requests
        // only the output size with a NULL signature buffer.
        let status = unsafe {
            NCryptSignHash(
                key.raw as NCRYPT_KEY_HANDLE,
                null(),
                digest.as_ptr(),
                SHA256_BYTES as u32,
                null_mut(),
                0,
                &mut signature_bytes,
                0,
            )
        };
        check_status("NCryptSignHash(size)", status)?;

        let mut signature = vec![0_u8; signature_bytes as usize];
        // SAFETY: output buffer has signature_bytes writable bytes; all other pointers remain valid.
        let status = unsafe {
            NCryptSignHash(
                key.raw as NCRYPT_KEY_HANDLE,
                null(),
                digest.as_ptr(),
                SHA256_BYTES as u32,
                signature.as_mut_ptr(),
                signature_bytes,
                &mut signature_bytes,
                0,
            )
        };
        check_status("NCryptSignHash", status)?;
        signature.truncate(signature_bytes as usize);
        Ok(signature)
    }

    /// Test/diagnostic helper that verifies a CNG-native ECDSA signature using the same public key.
    pub fn verify_sha256_digest(
        &self,
        digest: &[u8; SHA256_BYTES],
        signature: &[u8],
    ) -> Result<bool, CngKeyError> {
        let provider = open_provider()?;
        let key = open_key(&provider, &self.name)?;
        let signature_len = u32::try_from(signature.len()).map_err(|_| CngKeyError::Windows {
            operation: "signature length conversion",
            status: -1,
        })?;

        // SAFETY: key is valid; digest and signature slices remain readable for the call.
        let status = unsafe {
            NCryptVerifySignature(
                key.raw as NCRYPT_KEY_HANDLE,
                null(),
                digest.as_ptr(),
                SHA256_BYTES as u32,
                signature.as_ptr(),
                signature_len,
                0,
            )
        };
        if status == 0 {
            Ok(true)
        } else if status == NTE_BAD_SIGNATURE {
            Ok(false)
        } else {
            Err(CngKeyError::Windows {
                operation: "NCryptVerifySignature",
                status,
            })
        }
    }

    /// Deletes the persisted key. The CNG delete call also frees the key handle on success.
    pub fn delete(self) -> Result<(), CngKeyError> {
        let provider = open_provider()?;
        let mut key = open_key(&provider, &self.name)?;
        let raw = key.take();

        // SAFETY: raw is the valid handle removed from the RAII wrapper. On success Windows both
        // deletes the persisted key and frees this handle. On failure we free it ourselves.
        let status = unsafe { NCryptDeleteKey(raw as NCRYPT_KEY_HANDLE, NCRYPT_SILENT_FLAG) };
        if status != 0 {
            // SAFETY: NCryptDeleteKey failed, so Microsoft documents that NCryptFreeObject may be
            // used to release the still-valid handle.
            unsafe {
                NCryptFreeObject(raw);
            }
            return Err(CngKeyError::Windows {
                operation: "NCryptDeleteKey",
                status,
            });
        }
        Ok(())
    }
}


fn sec1_public_key_from_cng_blob(blob: &[u8]) -> Result<Vec<u8>, CngKeyError> {
    const HEADER_BYTES: usize = 8;
    const P256_COORDINATE_BYTES: usize = 32;
    const P256_BLOB_BYTES: usize = HEADER_BYTES + (P256_COORDINATE_BYTES * 2);

    if blob.len() != P256_BLOB_BYTES {
        return Err(CngKeyError::InvalidPublicKeyBlob);
    }
    let magic = u32::from_le_bytes(
        blob[0..4]
            .try_into()
            .map_err(|_| CngKeyError::InvalidPublicKeyBlob)?,
    );
    let key_bytes = u32::from_le_bytes(
        blob[4..8]
            .try_into()
            .map_err(|_| CngKeyError::InvalidPublicKeyBlob)?,
    );
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || key_bytes != P256_COORDINATE_BYTES as u32 {
        return Err(CngKeyError::InvalidPublicKeyBlob);
    }

    let mut sec1 = Vec::with_capacity(1 + (P256_COORDINATE_BYTES * 2));
    sec1.push(0x04);
    sec1.extend_from_slice(&blob[HEADER_BYTES..]);
    Ok(sec1)
}

fn validate_key_name(name: String) -> Result<String, CngKeyError> {
    if name.is_empty() || name.encode_utf16().any(|unit| unit == 0) {
        return Err(CngKeyError::InvalidKeyName);
    }
    Ok(name)
}

fn open_provider() -> Result<OwnedNcryptHandle, CngKeyError> {
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    // SAFETY: output points to writable storage and MS_KEY_STORAGE_PROVIDER is a valid PCWSTR.
    let status = unsafe { NCryptOpenStorageProvider(&mut provider, MS_KEY_STORAGE_PROVIDER, 0) };
    check_status("NCryptOpenStorageProvider", status)?;
    Ok(OwnedNcryptHandle::new(provider as NCRYPT_HANDLE))
}

fn open_key(provider: &OwnedNcryptHandle, name: &str) -> Result<OwnedNcryptHandle, CngKeyError> {
    let wide_name = wide_null(OsStr::new(name));
    let mut key: NCRYPT_KEY_HANDLE = 0;
    // SAFETY: provider is valid, key output is writable, and wide_name is NUL-terminated.
    let status = unsafe {
        NCryptOpenKey(
            provider.raw as NCRYPT_PROV_HANDLE,
            &mut key,
            wide_name.as_ptr(),
            0,
            NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
        )
    };
    check_status("NCryptOpenKey", status)?;
    Ok(OwnedNcryptHandle::new(key as NCRYPT_HANDLE))
}

fn set_u32_property(
    handle: NCRYPT_HANDLE,
    property: *const u16,
    value: u32,
    flags: u32,
    operation: &'static str,
) -> Result<(), CngKeyError> {
    // SAFETY: value points to exactly four readable bytes and handle/property are valid.
    let status = unsafe {
        NCryptSetProperty(
            handle,
            property,
            (&value as *const u32).cast::<u8>(),
            size_of::<u32>() as u32,
            flags,
        )
    };
    check_status(operation, status)
}

fn get_u32_property(
    handle: NCRYPT_HANDLE,
    property: *const u16,
    property_name: &'static str,
) -> Result<u32, CngKeyError> {
    let mut value = 0_u32;
    let mut written = 0_u32;
    // SAFETY: value is writable for exactly four bytes and written points to writable u32 storage.
    let status = unsafe {
        NCryptGetProperty(
            handle,
            property,
            (&mut value as *mut u32).cast::<u8>(),
            size_of::<u32>() as u32,
            &mut written,
            0,
        )
    };
    check_status("NCryptGetProperty", status)?;
    if written != size_of::<u32>() as u32 {
        return Err(CngKeyError::UnexpectedPropertySize {
            property: property_name,
            expected: size_of::<u32>() as u32,
            actual: written,
        });
    }
    Ok(value)
}

fn export_blob(key: NCRYPT_KEY_HANDLE, blob_type: *const u16) -> Result<Vec<u8>, CngKeyError> {
    let mut bytes = 0_u32;
    // SAFETY: key/blob type are valid; the first call requests only output size.
    let status =
        unsafe { NCryptExportKey(key, 0, blob_type, null(), null_mut(), 0, &mut bytes, 0) };
    check_status("NCryptExportKey(size)", status)?;

    let mut output = vec![0_u8; bytes as usize];
    // SAFETY: output has bytes writable bytes and all other arguments are valid.
    let status = unsafe {
        NCryptExportKey(
            key,
            0,
            blob_type,
            null(),
            output.as_mut_ptr(),
            bytes,
            &mut bytes,
            0,
        )
    };
    check_status("NCryptExportKey", status)?;
    output.truncate(bytes as usize);
    Ok(output)
}

fn check_status(operation: &'static str, status: i32) -> Result<(), CngKeyError> {
    if status == 0 {
        Ok(())
    } else {
        Err(CngKeyError::Windows { operation, status })
    }
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[derive(Debug)]
struct OwnedNcryptHandle {
    raw: NCRYPT_HANDLE,
}

impl OwnedNcryptHandle {
    const fn new(raw: NCRYPT_HANDLE) -> Self {
        Self { raw }
    }

    fn take(&mut self) -> NCRYPT_HANDLE {
        let raw = self.raw;
        self.raw = 0;
        raw
    }
}

impl Drop for OwnedNcryptHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            // SAFETY: this wrapper exclusively owns the NCrypt handle.
            unsafe {
                NCryptFreeObject(self.raw);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_key_name() -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        format!("ClassMesh-CI-{}-{nonce}", process::id())
    }

    struct TestKeyCleanup {
        name: String,
    }

    impl TestKeyCleanup {
        fn new(name: String) -> Self {
            Self { name }
        }
    }

    impl Drop for TestKeyCleanup {
        fn drop(&mut self) {
            if let Ok(key) = CngMachineKey::open(self.name.clone()) {
                let _ = key.delete();
            }
        }
    }

    #[test]
    fn persisted_machine_key_reopens_signs_and_stays_non_exportable() {
        let name = unique_key_name();
        let _cleanup = TestKeyCleanup::new(name.clone());
        let key = CngMachineKey::create(name.clone()).expect("machine key should be created");

        assert_eq!(key.export_policy().expect("export policy should read"), 0);
        let public_key = key.public_key_blob().expect("public key should export");
        assert!(!public_key.is_empty());

        let digest = [0x5a_u8; SHA256_BYTES];
        let signature = key.sign_sha256_digest(&digest).expect("digest should sign");
        assert!(!signature.is_empty());
        assert!(
            key.verify_sha256_digest(&digest, &signature)
                .expect("signature verification should run")
        );
        let tampered_digest = [0x5b_u8; SHA256_BYTES];
        assert!(
            !key.verify_sha256_digest(&tampered_digest, &signature)
                .expect("bad signature should be reported, not treated as an API failure")
        );

        drop(key);
        let reopened = CngMachineKey::open(name).expect("persisted key should reopen");
        let second_signature = reopened
            .sign_sha256_digest(&digest)
            .expect("reopened key should sign");
        assert!(
            reopened
                .verify_sha256_digest(&digest, &second_signature)
                .expect("reopened signature verification should run")
        );

        reopened.delete().expect("test key should delete");
    }

    #[test]
    fn rcgen_adapter_signs_without_private_key_export() {
        let name = unique_key_name();
        let _cleanup = TestKeyCleanup::new(name.clone());
        let key = CngMachineKey::create(name.clone()).expect("machine key should be created");
        assert_eq!(key.export_policy().expect("export policy should read"), 0);

        let adapter = CngRcgenSigningKey::new(key).expect("rcgen adapter should initialize");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
            .expect("certificate params");
        params.serial_number = Some(1_u64.into());
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ClassMesh CNG Test Authority");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let issuer =
            rcgen::CertifiedIssuer::self_signed(params, adapter).expect("CNG key should sign X.509");
        assert!(!issuer.der().is_empty());
        assert_eq!(
            issuer
                .signing_key()
                .machine_key()
                .export_policy()
                .expect("export policy should remain readable"),
            0
        );

        drop(issuer);
        CngMachineKey::open(name)
            .expect("persisted key should reopen")
            .delete()
            .expect("test key should delete");
    }

    #[test]
    fn key_name_validation_rejects_empty_and_embedded_nul() {
        assert_eq!(CngMachineKey::create(""), Err(CngKeyError::InvalidKeyName));
        assert_eq!(
            CngMachineKey::create("bad\0name"),
            Err(CngKeyError::InvalidKeyName)
        );
    }
}
