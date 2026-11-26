//! Ephemeral roster issuer for ClassMesh development only; no machine writes.
use classmesh_security::PrincipalId;
use classmesh_security::teacher_roster::{
    MAX_ENVELOPE_BYTES, RosterClaims, RosterDevice, RosterKey, RosterPolicy, UnsignedRoster,
    inspect_roster, verify_teacher_roster,
};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fs::{self, File},
    io::Read,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const MAX_JSON: usize = 128 * 1024;
const USAGE: &str = "ClassMesh development-only roster issuer
  fixture NEW_DIRECTORY [TEACHER_HEX STUDENT_HEX]
  issue CLAIMS_JSON NEW_DIRECTORY
  inspect ROSTER_COSE
  verify ROSTER_COSE PUBLIC_POLICY_JSON [NOW_UNIX_MS]";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicPolicy {
    issuer: String,
    organization: String,
    key_id: String,
    sec1: Vec<u8>,
    epoch: u64,
    roster_payload_sha256: [u8; 32],
    teacher_principal: [u8; 32],
    refreshed_at_ms: u64,
    max_age_ms: u64,
    max_lifetime_ms: u64,
    revoked_key: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ClaimsFile {
    issuer: String,
    organization: String,
    key_id: String,
    teacher: [u8; 32],
    issued_at_ms: u64,
    not_before_ms: u64,
    expires_at_ms: u64,
    epoch: u64,
    devices: Vec<DeviceFile>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceFile {
    principal: [u8; 32],
    source: u64,
}

impl From<RosterClaims> for ClaimsFile {
    fn from(c: RosterClaims) -> Self {
        Self {
            issuer: c.issuer,
            organization: c.organization,
            key_id: c.key_id,
            teacher: c.teacher.0,
            issued_at_ms: c.issued_at_ms,
            not_before_ms: c.not_before_ms,
            expires_at_ms: c.expires_at_ms,
            epoch: c.epoch,
            devices: c
                .devices
                .into_iter()
                .map(|d| DeviceFile {
                    principal: d.principal.0,
                    source: d.source,
                })
                .collect(),
        }
    }
}

impl From<ClaimsFile> for RosterClaims {
    fn from(c: ClaimsFile) -> Self {
        Self {
            issuer: c.issuer,
            organization: c.organization,
            key_id: c.key_id,
            teacher: PrincipalId(c.teacher),
            issued_at_ms: c.issued_at_ms,
            not_before_ms: c.not_before_ms,
            expires_at_ms: c.expires_at_ms,
            epoch: c.epoch,
            devices: c
                .devices
                .into_iter()
                .map(|d| RosterDevice {
                    principal: PrincipalId(d.principal),
                    source: d.source,
                })
                .collect(),
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Roster lab: {error}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mode = args.first().and_then(|value| value.to_str());
    match (mode, &args[1.min(args.len())..]) {
        (Some("fixture"), [destination]) => fixture(Path::new(destination), [7; 32], [8; 32]),
        (Some("fixture"), [destination, teacher, student]) => fixture(
            Path::new(destination),
            principal_hex(teacher)?,
            principal_hex(student)?,
        ),
        (Some("issue"), [claims, destination]) => {
            let claims: ClaimsFile = serde_json::from_slice(&read(Path::new(claims), MAX_JSON)?)?;
            issue(Path::new(destination), claims.into(), false)
        }
        (Some("inspect"), [roster]) => {
            let metadata = ClaimsFile::from(inspect_roster(&read(
                Path::new(roster),
                MAX_ENVELOPE_BYTES,
            )?)?);
            println!(
                "untrusted_metadata=true\n{}",
                serde_json::to_string_pretty(&metadata)?
            );
            Ok(())
        }
        (Some("verify"), [roster, policy]) => {
            verify(Path::new(roster), Path::new(policy), unix_ms()?)
        }
        (Some("verify"), [roster, policy, at]) => {
            let at = at.to_str().ok_or("invalid test timestamp")?.parse()?;
            verify(Path::new(roster), Path::new(policy), at)
        }
        (Some("--help" | "-h"), []) => {
            println!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn fixture(destination: &Path, teacher: [u8; 32], student: [u8; 32]) -> AppResult<()> {
    let now = unix_ms()?;
    let mut nonce = [0; 8];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "system RNG unavailable")?;
    let unique = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    issue(
        destination,
        RosterClaims {
            issuer: format!("disposable-issuer-{unique}"),
            key_id: "lab-es256".into(),
            organization: format!("disposable-organization-{unique}"),
            teacher: PrincipalId(teacher),
            issued_at_ms: now,
            not_before_ms: now,
            expires_at_ms: now + 900_000,
            epoch: 2,
            devices: vec![RosterDevice {
                principal: PrincipalId(student),
                source: 1,
            }],
        },
        true,
    )
}

fn issue(destination: &Path, claims: RosterClaims, fixtures: bool) -> AppResult<()> {
    let unsigned = UnsignedRoster::new(&claims)?;
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| "generate disposable roster key")?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.as_ref(), &rng)
        .map_err(|_| "load disposable roster key")?;
    let signing_data = unsigned.signing_data();
    let signature = key.sign(&rng, &signing_data).map_err(|_| "sign roster")?;
    let envelope = unsigned.attach_signature(signature.as_ref())?;
    let mut policy = PublicPolicy {
        issuer: claims.issuer.clone(),
        organization: claims.organization.clone(),
        key_id: claims.key_id.clone(),
        sec1: key.public_key().as_ref().to_vec(),
        epoch: claims.epoch,
        roster_payload_sha256: unsigned.payload_sha256(),
        teacher_principal: claims.teacher.0,
        refreshed_at_ms: claims.issued_at_ms,
        max_age_ms: 900_000,
        max_lifetime_ms: claims.expires_at_ms - claims.issued_at_ms,
        revoked_key: false,
    };

    fs::create_dir(destination)?;
    fs::write(destination.join("roster.cose"), &envelope)?;
    fs::write(
        destination.join("public-policy.json"),
        serde_json::to_vec_pretty(&policy)?,
    )?;
    fs::write(destination.join("signing-input.cbor"), signing_data)?;
    fs::write(destination.join("signature.raw"), signature)?;
    fs::write(destination.join("public-key.sec1"), &policy.sec1)?;
    if fixtures {
        let mut forged = envelope;
        if let Some(last) = forged.last_mut() {
            *last ^= 1;
        }
        fs::write(destination.join("forged.cose"), forged)?;
        let mut variant = claims.clone();
        variant.epoch -= 1;
        write_variant(destination, "stale.cose", &variant, &rng, &key)?;
        let mut mismatched = [0xd1; 32];
        while mismatched == claims.teacher.0
            || claims.devices.iter().any(|d| d.principal.0 == mismatched)
        {
            mismatched[0] = mismatched[0].wrapping_add(1);
        }
        variant.epoch = claims.epoch;
        variant.teacher = PrincipalId(mismatched);
        write_variant(destination, "wrong-teacher.cose", &variant, &rng, &key)?;
        variant = claims;
        variant.issued_at_ms -= 60_000;
        variant.not_before_ms = variant.issued_at_ms;
        variant.expires_at_ms = policy.refreshed_at_ms - 1;
        let expired = write_variant(destination, "expired.cose", &variant, &rng, &key)?;
        let current_hash = policy.roster_payload_sha256;
        policy.roster_payload_sha256 = expired;
        fs::write(
            destination.join("expired-public-policy.json"),
            serde_json::to_vec_pretty(&policy)?,
        )?;
        policy.roster_payload_sha256 = current_hash;
        policy.revoked_key = true;
        fs::write(
            destination.join("revoked-public-policy.json"),
            serde_json::to_vec_pretty(&policy)?,
        )?;
    }
    println!("development_only=true directory={}", destination.display());
    Ok(())
}

fn write_variant(
    dir: &Path,
    name: &str,
    claims: &RosterClaims,
    rng: &SystemRandom,
    key: &EcdsaKeyPair,
) -> AppResult<[u8; 32]> {
    let unsigned = UnsignedRoster::new(claims)?;
    let signature = key
        .sign(rng, &unsigned.signing_data())
        .map_err(|_| "sign fixture")?;
    fs::write(
        dir.join(name),
        unsigned.attach_signature(signature.as_ref())?,
    )?;
    Ok(unsigned.payload_sha256())
}

fn verify(roster: &Path, policy: &Path, now_ms: u64) -> AppResult<()> {
    let bytes = read(roster, MAX_ENVELOPE_BYTES)?;
    let policy: PublicPolicy = serde_json::from_slice(&read(policy, MAX_JSON)?)?;
    let keys = [RosterKey {
        id: policy.key_id,
        sec1: policy.sec1,
        revoked: policy.revoked_key,
    }];
    let proof = verify_teacher_roster(
        &bytes,
        &RosterPolicy {
            issuer: &policy.issuer,
            organization: &policy.organization,
            keys: &keys,
            epoch: policy.epoch,
            payload_sha256: policy.roster_payload_sha256,
            refreshed_at_ms: policy.refreshed_at_ms,
            max_age_ms: policy.max_age_ms,
            max_lifetime_ms: policy.max_lifetime_ms,
            revoked: &[],
        },
        PrincipalId(policy.teacher_principal),
        now_ms,
    )?;
    println!(
        "verified_under_supplied_lab_policy=true devices={} valid_until_ms={}",
        proof.devices().len(),
        proof.valid_until_ms()
    );
    Ok(())
}

fn principal_hex(value: &std::ffi::OsStr) -> AppResult<[u8; 32]> {
    let hex = value.to_str().ok_or("invalid principal encoding")?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("principal must contain exactly 64 hexadecimal characters".into());
    }
    let mut id = [0; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(id)
}

fn unix_ms() -> AppResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn read(path: &Path, limit: usize) -> AppResult<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("bounded input too large".into());
    }
    Ok(bytes)
}
