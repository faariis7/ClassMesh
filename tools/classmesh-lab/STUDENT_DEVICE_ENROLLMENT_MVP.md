# StudentDevice enrollment staging for Windows MVP

These tools add **explicit, opt-in StudentDevice enrollment support** without changing the default Teacher workflow. They do not install or enable a Windows Service.

The operator must supply `--role student-device` on each of `classmesh-enrollment-request`, `classmesh-enrollment-authority` and `classmesh-enrollment-install`. Omission retains `Teacher`, and a mismatched request role is rejected.

## Test-only workflow

1. Generate a StudentDevice CSR using `classmesh-enrollment-request --role student-device --display-name VM1-Lab --output <request.pb>`. The P-256 CNG key remains machine-scoped, signing-only, and non-exportable.
2. With an operator-approved existing offline CA key and certificate, issue an approved, short-lived result: `classmesh-enrollment-authority --role student-device --request <request.pb> --ca-cert <ca.der> --ca-key-name <machine-CNG-CA-key> --output <approved.pb> --lifetime-hours 1`. Do not create or export production CA credentials.
3. `classmesh-student-authorization-init --request <request.pb> --result <approved.pb> --trust-root <operator-approved-ca.der> --output-dir <fresh direct child of user TEMP> --bind-address 127.0.0.1:5151`. This stages `state/authorization.json` and `config/control-runtime.json` only in the new TEMP directory. It validates request/result binding, credential fingerprint, expiry, non-exportable matching CNG key and loopback-only listener. The StudentDevice principal is created with **zero privileged command permissions**.
4. `classmesh-enrollment-install --role student-device --request <request.pb> --result <approved.pb> --trust-root <ca.der> --identity-output <staging>/state/machine-identity.json` stages the bound identity. It rejects wrong role, wrong CNG key or exportable key.
5. **Do not copy these temporary files into ProgramData as a shortcut.** A separately reviewed protected installer/Windows ACL policy must establish the actual Service installation and identity. Approved Teacher credentials must be added separately through the existing `classmesh-student-authorize-teacher` process.
6. Remove only this newly created staging directory and its deliberately disposable CNG test key after authorized testing.

## Outstanding gates

- The opt-in [Windows Lab CA bootstrap](WINDOWS_LAB_CA.md) creates a disposable, non-exportable CNG test authority. It is never imported into a Windows trust store.
- The staging tool does not register, run or relax SCM/LocalSystem Service. Missing or untrusted ProgramData identity must still fail closed.
- FileTransfer and Clipboard stay OFF.
- Service→interactive Worker IPC, authenticated Teacher QUIC control, rendering an actual frame, release signing, security review, and physical gate #288 remain open.

The installer and staging authorizer now verify the signed chain against explicit operator roots, signed validity, CSR proof of possession and the CSR public-key binding. An EnrollmentResult cannot supply its own trust.
