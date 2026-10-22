//! Experimental independent Registry anchor for trusted Windows/admin machines.
//! No disk-snapshot rollback protection, policy installation or Service activation.
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{GENERIC_MAPPING, MapGenericMask, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CommitTransaction, CreateTransaction, GetTransactionId,
};
use windows_sys::Win32::System::Registry::*;

const RECORD_LEN: usize = 48;
const ACCESS: u32 = KEY_QUERY_VALUE | KEY_SET_VALUE | 0x0002_0000 | KEY_WOW64_64KEY;

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // Safety: exactly one owner of a successful non-predefined key handle.
        unsafe { RegCloseKey(self.0) };
    }
}
struct Descriptor(*mut std::ffi::c_void);
impl Drop for Descriptor {
    fn drop(&mut self) {
        // Safety: allocation returned by ConvertStringSecurityDescriptor.
        unsafe { LocalFree(self.0) };
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified registry epoch anchor",
    )
}
fn status(value: u32) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(value as i32))
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
fn epoch(record: &[u8; RECORD_LEN]) -> io::Result<u64> {
    if &record[..8] != b"CMPBND02" {
        return Err(denied());
    }
    let value = u64::from_le_bytes(record[8..16].try_into().expect("fixed width"));
    if value == 0 {
        return Err(denied());
    }
    Ok(value)
}
fn transaction() -> io::Result<OwnedHandle> {
    // Safety: unnamed, non-inheritable transaction; no distributed promotion,
    // default isolation and bounded 10-second transaction lifetime.
    let raw = unsafe {
        CreateTransaction(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            0,
            0,
            10_000,
            std::ptr::null(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // Safety: own the successful handle once; Drop aborts uncommitted changes.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn commit(tx: &OwnedHandle) -> io::Result<()> {
    // Safety: retained active transaction owned by this operation.
    if unsafe { CommitTransaction(tx.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn open(parent: HKEY, name: &str, access: u32) -> io::Result<Key> {
    let name = wide(name);
    let mut raw = std::ptr::null_mut();
    // Safety: fixed/prevalidated name; output initialized. OPEN_LINK means a
    // registry link is opened itself, never followed to a substitute target.
    status(unsafe {
        RegOpenKeyExW(
            parent,
            name.as_ptr(),
            REG_OPTION_OPEN_LINK,
            access,
            &raw mut raw,
        )
    })?;
    if raw.is_null() {
        return Err(denied());
    }
    Ok(Key(raw))
}
fn no_link(key: &Key) -> io::Result<()> {
    let name = wide("SymbolicLinkValue");
    let mut length = 0;
    // Safety: retained key, bounded metadata-only value query; no data allocation.
    let result = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut length,
        )
    };
    if result != ERROR_FILE_NOT_FOUND {
        return Err(denied());
    }
    Ok(())
}
fn attest(key: &Key, shared_parent: bool) -> io::Result<()> {
    no_link(key)?;
    // Safety: the owned key includes READ_CONTROL and remains retained.
    let descriptor =
        unsafe { crate::file_security_descriptor::read_allowed_registry_descriptor(key.0) }?;
    if descriptor.owner != "S-1-5-18" && descriptor.owner != "S-1-5-32-544" {
        return Err(denied());
    }
    let mut system = false;
    let mut admin = false;
    let mapping = GENERIC_MAPPING {
        GenericRead: KEY_READ,
        GenericWrite: KEY_WRITE,
        GenericExecute: KEY_EXECUTE,
        GenericAll: KEY_ALL_ACCESS,
    };
    for entry in descriptor.entries {
        if entry.flags & !0x1f != 0 {
            return Err(denied());
        }
        if shared_parent && entry.flags & 0x08 != 0 {
            continue;
        }
        let mut mask = entry.mask;
        // Safety: initialized access mask and registry generic-rights mapping.
        unsafe { MapGenericMask(&raw mut mask, &mapping) };
        if mask & !KEY_ALL_ACCESS != 0 {
            return Err(denied());
        }
        match entry.sid.as_str() {
            "S-1-5-18" => system |= mask & KEY_READ == KEY_READ,
            "S-1-5-32-544" => admin |= mask & KEY_READ == KEY_READ,
            // CREATOR OWNER is an inheritance placeholder. Child creation uses
            // an explicit protected ACL, so none of these ACEs are inherited.
            "S-1-3-0" if shared_parent && entry.flags & 0x02 != 0 => {}
            _ if shared_parent && mask & !KEY_READ == 0 => {}
            _ => return Err(denied()),
        }
        if !shared_parent && entry.flags != 0 {
            return Err(denied());
        }
    }
    if !system || !admin {
        return Err(denied());
    }
    Ok(())
}
fn machine_parent(scope: &str) -> io::Result<Key> {
    if scope != "ClassMesh-Policy-v2" && !scope.starts_with("ClassMesh-anchor-probe-")
        || scope.len() > 100
        || !scope
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(denied());
    }
    let parent = open(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE",
        KEY_READ | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY,
    )?;
    attest(&parent, true)?;
    Ok(parent)
}
fn read_record(key: &Key) -> io::Result<[u8; RECORD_LEN]> {
    let mut bytes = [0; RECORD_LEN + 1];
    let mut size = bytes.len() as u32;
    let mut kind = 0;
    let name = wide("CommittedPolicy");
    // Safety: fixed live buffer, initialized size, retained non-predefined key.
    status(unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            std::ptr::null(),
            &raw mut kind,
            bytes.as_mut_ptr(),
            &raw mut size,
        )
    })?;
    if kind != REG_BINARY || size != RECORD_LEN as u32 {
        return Err(denied());
    }
    let record = bytes[..RECORD_LEN].try_into().expect("fixed width");
    epoch(&record)?;
    Ok(record)
}
fn write_record(key: &Key, record: &[u8; RECORD_LEN]) -> io::Result<()> {
    epoch(record)?;
    let name = wide("CommittedPolicy");
    // Safety: live fixed-size record and retained transaction-bound key.
    status(unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_BINARY,
            record.as_ptr(),
            RECORD_LEN as u32,
        )
    })
}

pub(crate) struct RegistryAnchor {
    key: Key,
}
impl RegistryAnchor {
    /// A fresh installer must not seed startup inputs that would activate an
    /// earlier committed policy. Probe without flushing or adopting a key.
    pub(crate) fn require_absent(scope: &str) -> io::Result<()> {
        let parent = machine_parent(scope)?;
        match open(parent.0, scope, KEY_READ | KEY_WOW64_64KEY) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            _ => Err(denied()),
        }
    }
    pub(crate) fn create(scope: &str, record: &[u8; RECORD_LEN]) -> io::Result<Self> {
        epoch(record)?;
        let parent = machine_parent(scope)?;
        let tx = transaction()?;
        let mut descriptor = Descriptor(std::ptr::null_mut());
        let sddl = wide("O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)");
        // Safety: fixed SDDL, initialized allocation output; owned until create returns.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor.0,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let mut raw = std::ptr::null_mut();
        let mut disposition = 0;
        let name = wide(scope);
        // Safety: retained parent/transaction, protected descriptor and live buffers.
        status(unsafe {
            RegCreateKeyTransactedW(
                parent.0,
                name.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                ACCESS,
                &attributes,
                &raw mut raw,
                &raw mut disposition,
                tx.as_raw_handle(),
                std::ptr::null(),
            )
        })?;
        if raw.is_null() {
            return Err(denied());
        }
        let key = Key(raw);
        if disposition != REG_CREATED_NEW_KEY {
            return Err(denied());
        }
        attest(&key, false)?;
        write_record(&key, record)?;
        commit(&tx)?;
        drop(key);
        let anchor = Self {
            key: open(parent.0, scope, ACCESS)?,
        };
        anchor.flush_exact(record)?;
        Ok(anchor)
    }
    pub(crate) fn open(scope: &str) -> io::Result<Self> {
        let parent = machine_parent(scope)?;
        let anchor = Self {
            key: open(parent.0, scope, ACCESS)?,
        };
        let record = anchor.read()?;
        // A prior process may have died after KTM commit but before flushing.
        // Recovery acknowledges the visible record only after persisting it.
        anchor.flush_exact(&record)?;
        Ok(anchor)
    }
    pub(crate) fn read(&self) -> io::Result<[u8; RECORD_LEN]> {
        attest(&self.key, false)?;
        read_record(&self.key)
    }
    /// Acquisition-time candidate only. The callback must only parse and must
    /// not publish; its value is released after commit/flush/exact readback.
    pub(crate) fn with_record<T>(
        &self,
        parse: impl FnOnce(&[u8; RECORD_LEN]) -> io::Result<T>,
    ) -> io::Result<T> {
        let expected = self.read()?;
        let pending = self.begin(&expected)?;
        let value = parse(&expected)?;
        commit(&pending.transaction)?;
        self.flush_exact(&expected)?;
        Ok(value)
    }
    fn flush_exact(&self, expected: &[u8; RECORD_LEN]) -> io::Result<()> {
        // Safety: retained key includes KEY_QUERY_VALUE; flush is required only
        // at a commit boundary, never polled. Failure never issues a receipt.
        status(unsafe { RegFlushKey(self.key.0) })?;
        if self.read()? != *expected {
            return Err(denied());
        }
        Ok(())
    }
    fn begin<'a>(&'a self, expected: &[u8; RECORD_LEN]) -> io::Result<PendingAdvance<'a>> {
        if self.read()? != *expected {
            return Err(denied());
        }
        let transaction = transaction()?;
        let mut raw = std::ptr::null_mut();
        // Safety: open the SAME retained non-predefined key in a new transaction;
        // no pathname traversal or predefined-handle transaction exemption.
        status(unsafe {
            RegOpenKeyTransactedW(
                self.key.0,
                std::ptr::null(),
                0,
                ACCESS,
                &raw mut raw,
                transaction.as_raw_handle(),
                std::ptr::null(),
            )
        })?;
        if raw.is_null() {
            return Err(denied());
        }
        let key = Key(raw);
        // TxR reads alone do not reserve the value: a read-then-write transaction
        // can otherwise overwrite a newer commit. Reserve a common write value
        // with this transaction's unique ID BEFORE reading the authoritative record.
        let mut id = windows_sys::core::GUID::from_u128(0);
        // Safety: live transaction and writable GUID output.
        if unsafe { GetTransactionId(transaction.as_raw_handle(), &raw mut id) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let fence = wide("WriterReservation");
        // Safety: GUID occupies 16 initialized bytes, valid for this synchronous call.
        status(unsafe {
            RegSetValueExW(
                key.0,
                fence.as_ptr(),
                0,
                REG_BINARY,
                (&raw const id).cast(),
                16,
            )
        })?;
        if read_record(&key)? != *expected {
            return Err(denied());
        }
        Ok(PendingAdvance {
            anchor: self,
            key,
            transaction,
            previous: *expected,
        })
    }
    pub(crate) fn advance(
        &self,
        expected: &[u8; RECORD_LEN],
        next: &[u8; RECORD_LEN],
    ) -> io::Result<()> {
        self.begin(expected)?.commit(next)
    }
}
struct PendingAdvance<'a> {
    anchor: &'a RegistryAnchor,
    key: Key,
    transaction: OwnedHandle,
    previous: [u8; RECORD_LEN],
}
impl PendingAdvance<'_> {
    fn stage(&self, next: &[u8; RECORD_LEN]) -> io::Result<()> {
        if epoch(next)? <= epoch(&self.previous)? {
            return Err(denied());
        }
        write_record(&self.key, next)
    }
    fn commit(self, next: &[u8; RECORD_LEN]) -> io::Result<()> {
        self.stage(next)?;
        commit(&self.transaction)?;
        self.anchor.flush_exact(next)
    }
}

#[test]
fn registry_anchor_creates_without_adopting_existing_state() {
    let scope = format!("ClassMesh-anchor-probe-{}", std::process::id());
    let record =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, b"policy").unwrap();
    let anchor =
        RegistryAnchor::create(&scope, &record).expect("create independent protected anchor");
    assert_eq!(anchor.read().unwrap(), record);
    assert!(RegistryAnchor::create(&scope, &record).is_err());
    assert_eq!(
        RegistryAnchor::open(&scope).unwrap().read().unwrap(),
        record
    );
    let next =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(9, b"new policy").unwrap();
    let stale =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(8, b"stale policy")
            .unwrap();
    let parsed = anchor
        .with_record(|observed| {
            assert_eq!(*observed, record);
            assert!(
                anchor.advance(&record, &next).is_err(),
                "writer must not advance during parsing"
            );
            Ok(42)
        })
        .unwrap();
    assert_eq!(parsed, 42);
    assert!(
        anchor
            .with_record::<()>(|_| Err(io::Error::other("injected parse failure")))
            .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| {
            let _ = anchor.with_record::<()>(|_| panic!("injected parse unwind"));
        })
        .is_err()
    );
    assert_eq!(anchor.read().unwrap(), record);
    let pending = anchor.begin(&record).unwrap();
    assert!(
        anchor.advance(&record, &next).is_err(),
        "writer reservation must exclude competitor"
    );
    let competitor = run_worker(&scope, "compete");
    assert!(
        competitor.status.success(),
        "independent competing process failed: {}",
        String::from_utf8_lossy(&competitor.stderr)
    );
    pending.commit(&stale).unwrap();
    anchor.advance(&stale, &next).unwrap();
    assert_eq!(anchor.read().unwrap(), next);
    assert!(anchor.advance(&next, &record).is_err());
    assert!(anchor.advance(&next, &next).is_err());
    assert!(anchor.advance(&record, &stale).is_err());
    drop(anchor);
    // Remove only this newly-created, test-owned key after all handles close.
    let parent = machine_parent(&scope).unwrap();
    let name = wide(&scope);
    // Safety: exact single test-owned child, never a production ClassMesh key.
    status(unsafe { RegDeleteKeyExW(parent.0, name.as_ptr(), KEY_WOW64_64KEY, 0) }).unwrap();
}

#[test]
fn registry_anchor_recovers_after_process_exit_before_and_after_commit() {
    let scope = format!("ClassMesh-anchor-probe-crash-{}", std::process::id());
    let old =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, b"policy").unwrap();
    let new =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(9, b"new policy").unwrap();
    let anchor = RegistryAnchor::create(&scope, &old).unwrap();
    for (mode, expected) in [("before", old), ("after", new)] {
        let output = run_worker(&scope, mode);
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let recovered = RegistryAnchor::open(&scope).unwrap();
        assert_eq!(recovered.read().unwrap(), expected);
    }
    assert!(anchor.advance(&old, &new).is_err());
    drop(anchor);
    remove_fixture(&scope);
}

#[test]
fn registry_anchor_process_worker() {
    let Ok(scope) = std::env::var("CLASSMESH_REGISTRY_PROBE_SCOPE") else {
        return;
    };
    let mode = std::env::var("CLASSMESH_REGISTRY_PROBE_MODE").unwrap();
    assert!(scope.starts_with("ClassMesh-anchor-probe-"));
    let old =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, b"policy").unwrap();
    let new =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(9, b"new policy").unwrap();
    let anchor = RegistryAnchor::open(&scope).unwrap();
    if mode == "compete" {
        assert!(
            anchor.advance(&old, &new).is_err(),
            "other process owns writer reservation"
        );
        assert_eq!(anchor.read().unwrap(), old);
        return;
    }
    let pending = anchor.begin(&old).unwrap();
    pending.stage(&new).unwrap();
    match mode.as_str() {
        "before" => {}
        "after" => commit(&pending.transaction).unwrap(),
        _ => panic!("unsupported test mode"),
    }
    // Deliberately bypass Rust destructors; the OS closes handles at process
    // termination. This is process-crash evidence, not machine power loss.
    std::process::exit(0);
}

#[test]
fn registry_anchor_rejects_torn_wrong_type_and_untrusted_descriptor() {
    let scope = format!("ClassMesh-anchor-probe-invalid-{}", std::process::id());
    let old =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, b"policy").unwrap();
    let anchor = RegistryAnchor::create(&scope, &old).unwrap();
    let value = wide("CommittedPolicy");
    for (kind, bytes) in [
        (REG_BINARY, old[..47].to_vec()),
        (REG_BINARY, [old.as_slice(), &[0]].concat()),
        (REG_SZ, old.to_vec()),
        (REG_BINARY, [0u8; 48].to_vec()),
    ] {
        // Safety: test-owned key and valid byte slice. Inject malformed storage.
        status(unsafe {
            RegSetValueExW(
                anchor.key.0,
                value.as_ptr(),
                0,
                kind,
                bytes.as_ptr(),
                bytes.len() as u32,
            )
        })
        .unwrap();
        assert!(anchor.read().is_err());
        assert!(RegistryAnchor::open(&scope).is_err());
    }
    write_record(&anchor.key, &old).unwrap();
    let abandoned = anchor.begin(&old).unwrap();
    let new =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(9, b"new policy").unwrap();
    abandoned.stage(&new).unwrap();
    drop(abandoned);
    assert_eq!(
        anchor.read().unwrap(),
        old,
        "uncommitted writes must roll back on drop"
    );
    // Change ONLY this disposable key's DACL. A readable untrusted grant is
    // rejected as well as write grants; no production/system key is modified.
    set_fixture_dacl(&scope, "O:BAG:BAD:P(A;;KR;;;SY)(A;;KR;;;BA)");
    assert_eq!(anchor.read().unwrap(), old);
    assert!(
        anchor.advance(&old, &new).is_err(),
        "OS write denial must not be acknowledged"
    );
    assert_eq!(anchor.read().unwrap(), old);
    set_fixture_dacl(&scope, "O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)");
    assert!(anchor.read().is_err());
    assert!(RegistryAnchor::open(&scope).is_err());
    drop(anchor);
    remove_fixture(&scope);
}

#[cfg(test)]
pub(crate) fn remove_fixture(scope: &str) {
    let parent = machine_parent(scope).unwrap();
    let name = wide(scope);
    // Safety: called only for a newly created test-owned single child.
    status(unsafe { RegDeleteKeyExW(parent.0, name.as_ptr(), KEY_WOW64_64KEY, 0) }).unwrap();
}

#[cfg(test)]
fn set_fixture_dacl(scope: &str, sddl: &str) {
    let parent = machine_parent(scope).unwrap();
    let acl_key = open(parent.0, scope, 0x0004_0000 | KEY_WOW64_64KEY).unwrap();
    let sddl = wide(sddl);
    let mut descriptor = Descriptor(std::ptr::null_mut());
    // Safety: fixed test SDDL and initialized allocation output.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor.0,
                std::ptr::null_mut(),
            )
        },
        0
    );
    // Safety: WRITE_DAC handle to a test-owned key and live valid descriptor.
    status(unsafe {
        RegSetKeySecurity(
            acl_key.0,
            windows_sys::Win32::Security::DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    })
    .unwrap();
}

#[cfg(test)]
fn run_worker(scope: &str, mode: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "registry_epoch::registry_anchor_process_worker",
            "--nocapture",
        ])
        .env("CLASSMESH_REGISTRY_PROBE_SCOPE", scope)
        .env("CLASSMESH_REGISTRY_PROBE_MODE", mode)
        .output()
        .unwrap()
}

#[test]
fn registry_anchor_rejects_actual_registry_symbolic_link() {
    let scope = format!("ClassMesh-anchor-probe-link-target-{}", std::process::id());
    let alias = format!("ClassMesh-anchor-probe-link-alias-{}", std::process::id());
    let record =
        classmesh_security::policy_epoch::encode_bound_policy_checkpoint(7, b"policy").unwrap();
    let anchor = RegistryAnchor::create(&scope, &record).unwrap();
    let parent = machine_parent(&alias).unwrap();
    let name = wide(&alias);
    let mut raw = std::ptr::null_mut();
    let mut disposition = 0;
    // Safety: unique test-owned child; create an actual registry link object.
    status(unsafe {
        RegCreateKeyExW(
            parent.0,
            name.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_CREATE_LINK,
            KEY_ALL_ACCESS | KEY_WOW64_64KEY,
            std::ptr::null(),
            &raw mut raw,
            &raw mut disposition,
        )
    })
    .unwrap();
    let link = Key(raw);
    assert_eq!(disposition, REG_CREATED_NEW_KEY);
    let value = wide("SymbolicLinkValue");
    let target: Vec<u16> = format!(r"\Registry\Machine\SOFTWARE\{scope}")
        .encode_utf16()
        .collect();
    // Safety: UTF-16 link target bytes exclude NUL as required for REG_LINK.
    status(unsafe {
        RegSetValueExW(
            link.0,
            value.as_ptr(),
            0,
            REG_LINK,
            target.as_ptr().cast(),
            (target.len() * 2) as u32,
        )
    })
    .unwrap();
    assert!(RegistryAnchor::open(&alias).is_err());
    let mut followed = std::ptr::null_mut();
    // Safety: positive control intentionally follows only this test-owned link.
    status(unsafe { RegOpenKeyExW(parent.0, name.as_ptr(), 0, ACCESS, &raw mut followed) })
        .unwrap();
    assert_eq!(read_record(&Key(followed)).unwrap(), record);
    // RegDeleteKeyEx follows registry links even during deletion. Delete the
    // already-open link object directly, never its target pathname.
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtDeleteKey(key: HKEY) -> i32;
    }
    // Safety: retained link HANDLE with DELETE from KEY_ALL_ACCESS; own fixture.
    assert_eq!(unsafe { NtDeleteKey(link.0) }, 0);
    drop(link);
    assert_eq!(
        anchor.read().unwrap(),
        record,
        "deleting alias must preserve target"
    );
    drop(anchor);
    remove_fixture(&scope);
}
