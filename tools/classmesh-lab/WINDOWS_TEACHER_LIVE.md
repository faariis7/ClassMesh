# Windows Teacher Live Mode qualification

Use the exact CI Windows artifacts from #776. The normal Windows MVP ZIP contains Teacher, Service and Worker. For protected lab qualification, use Teacher and Worker from that ZIP and the opt-in Service and trusted provisioner from `protected-lab/` in the same-run Phase 6F artifact. That artifact also contains the enrollment and roster tools. Verify its `source-and-checksums.json` against the manifest hashes printed in the Windows job before signing. Both artifacts ship unsigned for development.

## Isolated positive and negative vectors

The commands create a new test-owned directory, generate a disposable ES256 signer in memory, and leave only public evidence. They do not install trust or write ProgramData or HKLM. The issuer can also sign a claims JSON document via `issue CLAIMS_JSON NEW_DIRECTORY` with a fresh ephemeral key. Use the output of `inspect` after removing its first diagnostic line as a claims JSON example.

```powershell
.\classmesh-teacher-roster-lab.exe fixture .\new-roster-fixture
$f = '.\new-roster-fixture'
.\classmesh-teacher-roster-lab.exe inspect "$f\roster.cose"
.\classmesh-teacher-roster-lab.exe verify "$f\roster.cose" "$f\public-policy.json"
.\classmesh-teacher-roster-lab.exe verify "$f\forged.cose" "$f\public-policy.json"
.\classmesh-teacher-roster-lab.exe verify "$f\stale.cose" "$f\public-policy.json"
.\classmesh-teacher-roster-lab.exe verify "$f\wrong-teacher.cose" "$f\public-policy.json"
.\classmesh-teacher-roster-lab.exe verify "$f\expired.cose" "$f\expired-public-policy.json"
.\classmesh-teacher-roster-lab.exe verify "$f\roster.cose" "$f\revoked-public-policy.json"
```

The first verification exits 0 during its stated lease. Each subsequent case exits 1 with a specific rejection. `verify` optionally accepts a final Unix-ms argument for repeatable verification at a recorded test time. The vector's `signing-input.cbor`, `signature.raw` and `public-key.sec1` are interoperable ES256 test inputs. An independent tool can reconstruct the RFC 9052 Sig_structure and compare it to the exported bytes, then verify the fixed-width signature using P-256 SHA-256. Treat inspect output as untrusted. [Roster wire profile](../../docs/decisions/0009-teacher-roster-trust.md)

## Prepare the exact enrollment and protected candidate

1. Follow the [existing Windows lab CA guide](WINDOWS_LAB_CA.md). Enroll distinct Teacher and StudentDevice identities using the existing CSR, role, proof of possession, leaf and non-exportable CNG key verification. Keep machine keys on their enrollment machines. The Teacher hosts only approved Windows CNG enrollment and public trust material. The operator must ensure the specific ordinary Teacher Windows account can use its exact CNG signer under the approved key descriptor. The development tools do not change key ACLs.
2. For isolated signer vectors tied to the actual fixture principal IDs, use `classmesh-teacher-roster-lab fixture NEW_DIRECTORY TEACHER_HEX STUDENT_HEX`. Use its positive profile on an isolated disposable host only when publication there is explicitly approved. Build the configuration from the *verified* enrollment outputs and the approved public roster verifier inputs. The JSON below shows the field names. Byte values are JSON arrays of unsigned octets (not hexadecimal strings). Copy the enrolled Teacher machine identity file's literal bytes into `machine_identity`. Match addresses and DNS against the target lab. The Student leaf pin comes from its authenticated enrollment output.
3. Generate a new signed roster at every new protected epoch. Before publication run `classmesh-teacher-policy plan EPOCH POLICY_JSON`. This does not install, grant CNG access, contact the Student or mutate SCM. A readable JSON file is only an input to this offline provisioning tool.

Use the approved Student DNS name or IP address as `--student-server-name`
when the enrollment authority issues the Student leaf. Put that same value in
`student.server_name` below. After reissuing an older leaf without the right
SAN, use the current certificate and fingerprint for both authorization and
Teacher policy.

```powershell
# Variables here are populated from approved inputs and verified enrollment results.
$profile = Get-Content -Raw "$f\public-policy.json" | ConvertFrom-Json
$policy = [ordered]@{
    version = 1
    issuer = $profile.issuer
    organization = $profile.organization
    keys = @(@{ id = $profile.key_id; sec1 = $profile.sec1; revoked = $false })
    roster = @([IO.File]::ReadAllBytes((Resolve-Path "$f\roster.cose")))
    roster_payload_sha256 = $profile.roster_payload_sha256
    refreshed_at_ms = $profile.refreshed_at_ms
    max_age_ms = $profile.max_age_ms
    max_lifetime_ms = $profile.max_lifetime_ms
    revoked_principals = @()
    teacher_principal = $profile.teacher_principal
    teacher_leaf_sha256 = $ApprovedTeacherLeafSha256Octets
    teacher_enrollment_ca_der = @([IO.File]::ReadAllBytes($ApprovedTeacherCaDer))
    machine_identity = @([IO.File]::ReadAllBytes($ApprovedTeacherIdentity))
    student = @{
        principal = $ApprovedStudentPrincipalOctets
        leaf_sha256 = $ApprovedStudentLeafSha256Octets
        address = $ApprovedStudentAddress
        server_name = $ApprovedStudentServerName
    }
}
$policyPath = Join-Path (Get-Location).Path 'teacher-policy.json'
[IO.File]::WriteAllText($policyPath, ($policy | ConvertTo-Json -Depth 7 -Compress), [Text.UTF8Encoding]::new($false))
.\classmesh-teacher-policy.exe plan $profile.epoch .\teacher-policy.json
```

## Approved protected execution

Use a named disposable machine and authorization for the exact protected operations. Record the preflight output, source SHA and signed image hashes and independent Authenticode thumbprint. Inspect existing machine state and reserve an exclusive operation window. From the approved elevated account, `classmesh-teacher-policy create EPOCH POLICY_JSON` creates the dedicated namespace once. `advance` applies a strictly higher signed policy. `revoke EPOCH` commits a higher-epoch deny snapshot without deleting the rollback anchor. These commands require the normal OS ACL. The ordinary account then runs `classmesh-teacher-ui.exe --check-live` to verify configuration, CNG and enrolled QUIC without opening a GUI or sending a command. With valid signed inputs the same entry point with no flags opens connected Teacher and selects the single authorized target after Hello. In **Device Actions**, enter a harmless message and choose **Send message**. Its authenticated control access is shown independently of Worker readiness. Missing or invalid policy fails with exit 3. `--offline` remains explicit and isolated.

Use the existing guarded SCM Plan and approved Service procedure. The approved Student authorization must explicitly grant SendTeacherMessage for the independently enrolled Teacher. The authorized interactive Student operator verifies the harmless lab message and clicks **OK** in the visible **ClassMesh** dialog in the matching Worker session. Record Teacher account integrity/session, SCM LocalSystem/image identity, Worker user/session/incarnation, request ID, Accepted and genuine correlated Completed, denial for unauthorized and replayed requests, and final cleanup. [Protected Service and ACK procedure](../../docs/WINDOWS_RUNTIME_PLAN.md)

The qualification artifact contains the trusted provisioner. For protected
SCM acceptance, the Service build also requires `experimental-trusted-policy`.
Verify the signed SHA-256 and independent signer pin for the exact executable
set before the guarded Apply step. Keep proof of VM restorability, the initial
machine inventory, the run-owned resource list and measured cleanup.

If `--check-live` reports `NotNegotiated` after protected provisioning, confirm
whether the exact interactive Worker authenticated to Service and published
its command capabilities. On VM1 the ordinary Worker could not open the
LocalSystem process for its token check and Teacher failed closed. Capture the
SCM PID, Worker PID/session and native error before teardown. A connected GUI
and actual Student confirmation are still required. [VM1 run record](../../docs/WINDOWS_RUNTIME_PLAN.md#protected-vm1-run--2026-11-26)

## Expiry, revocation and recovery

While the test connects, publish a higher-epoch reviewed snapshot, withdraw the selected device or revoke the signing key using the authority's next policy and confirm control retires. To test expiry, use a short signed lease and leave the connected window open without publishing a new epoch. Record disconnection and a denied second command. Reconnect by restarting Teacher only once a current protected snapshot and peer enrollment are available. Safe presentation stop and Service/Worker teardown use the existing guarded runtime procedure. A device/host outage does not extend the freshness lease.

For rollback on a managed host, retain the approved good program images, restore via the reviewed signed package and re-issue any recovered safe policy content at a higher independently approved epoch. Do not reset the checkpoint or reuse an older roster. For an explicitly approved disposable VM cleanup, close Teacher, stop and remove only the run-owned SCM service and Worker using the existing guard, then restore the recorded pre-run VM snapshot or remove only the policy namespace, CNG keys and files proven to be owned by that run. An unrelated or preexisting installation is never adopted or deleted.
