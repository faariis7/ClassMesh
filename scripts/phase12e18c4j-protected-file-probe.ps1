[CmdletBinding()]
param(
    [ValidateSet('Help','All')]
    [string]$Mode = 'Help'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Mode -eq 'Help') {
    @'
ClassMesh Phase12E18c4j: DISPOSABLE protected policy file attestation
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\phase12e18c4j-protected-file-probe.ps1 -Mode All
Requires an elevated interactive administrator on disposable Windows.
Uses native SAME HANDLE GetFileInformationByHandleEx + GetSecurityInfo.
Only touches unique disposable ProgramData subtree; no real policy file.
Does not prove production ACL/trusted reload, SCM owner, anti-rollback,
cross-component path race immunity or clipboard IPC v12.
'@ | Write-Output
    return
}
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only native probe' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Elevated admin required'
}
if ([Diagnostics.Process]::GetCurrentProcess().SessionId -le 0 -or $identity.User.Value -eq 'S-1-5-18') {
    throw 'Interactive non-SYSTEM admin session required'
}
$nativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
public static class ClassMeshPolicyHandleAttestation {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo { public uint FileAttributes; public uint ReparseTag; }
    [DllImport("kernel32.dll", EntryPoint="CreateFileW", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CreateFile(string name,uint access,uint sharing,IntPtr attributes,uint creation,uint flags,IntPtr templateFile);
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool GetFileInformationByHandleEx(IntPtr handle,int infoClass,out FileAttributeTagInfo attributes,uint size);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern uint GetSecurityInfo(IntPtr handle,uint objectType,uint securityInformation,out IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll",EntryPoint="ConvertSecurityDescriptorToStringSecurityDescriptorW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern bool ConvertSecurityDescriptorToString(IntPtr descriptor,uint revision,uint information,out IntPtr sddl,out uint length);
    [DllImport("kernel32.dll",SetLastError=true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);
    public static string Check(string path,bool isDirectory) {
        const uint readControl=0x00020000,readAttributes=0x80,openReparse=0x00200000,backupSemantics=0x02000000;
        const uint reparse=0x400,directory=0x10;
        uint flags=openReparse|(isDirectory?backupSemantics:0u);
        IntPtr file=CreateFile(path,readControl|readAttributes,7,IntPtr.Zero,3,flags,IntPtr.Zero);
        if(file==new IntPtr(-1)||file==IntPtr.Zero) return "OPEN_DENIED";
        try {
            FileAttributeTagInfo info;
            if(!GetFileInformationByHandleEx(file,9,out info,(uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))))
                return "NATIVE_INFO_DENIED";
            if((info.FileAttributes&reparse)!=0) return "REPARSE_DENIED";
            if(((info.FileAttributes&directory)!=0)!=isDirectory) return "TYPE_DENIED";
            IntPtr owner,group,dacl,sacl,descriptor;
            uint rc=GetSecurityInfo(file,1,5,out owner,out group,out dacl,out sacl,out descriptor);
            if(rc!=0||descriptor==IntPtr.Zero) return "SECURITY_DENIED";
            try {
                if(owner==IntPtr.Zero||dacl==IntPtr.Zero) return "NULL_ACL_DENIED";
                IntPtr sddl=IntPtr.Zero;uint length;
                if(!ConvertSecurityDescriptorToString(descriptor,1,5,out sddl,out length)||sddl==IntPtr.Zero)
                    return "SDDL_DENIED";
                try {
                    RawSecurityDescriptor raw=new RawSecurityDescriptor(Marshal.PtrToStringUni(sddl));
                    string ownerSid=raw.Owner==null?"":raw.Owner.Value;
                    if(ownerSid!="S-1-5-18"&&ownerSid!="S-1-5-32-544")return "OWNER_DENIED";
                    if(raw.DiscretionaryAcl==null||raw.DiscretionaryAcl.Count==0)return "DACL_DENIED";
                    bool sy=false,ba=false;
                    foreach(GenericAce ace in raw.DiscretionaryAcl) {
                        CommonAce a=ace as CommonAce;
                        if(a==null||a.AceQualifier!=AceQualifier.AccessAllowed)return "DACL_DENIED";
                        string sid=a.SecurityIdentifier.Value;
                        if(sid=="S-1-5-18")sy=true;
                        else if(sid=="S-1-5-32-544")ba=true;
                        else return "OTHER_TRUSTEE_DENIED";
                    }
                    return sy&&ba?"ALLOW":"MISSING_TRUSTEE_DENIED";
                }finally{if(sddl!=IntPtr.Zero)LocalFree(sddl);}
            }finally{LocalFree(descriptor);}
        }finally{CloseHandle(file);}
    }
}
'@
Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
$id=[Guid]::NewGuid().ToString('N')
$root=Join-Path $env:ProgramData ('classmesh-e18c4j-'+$id)
$leaf=Join-Path $root 'authorization.json'
$link=Join-Path $root 'authorization-link.json'
$adminSid='*S-1-5-32-544'
$systemSid='*S-1-5-18'
$userSid='*S-1-5-32-545'
function Set-TestAcl {
    param([string]$Path,[string[]]$Options)
    $output=& icacls.exe $Path @Options 2>&1
    if($LASTEXITCODE -ne 0) {throw "icacls failed: $($output -join ';')"}
}
function Assert-Denied {
    param([string]$Witness,[string]$Value)
    if($Value -eq 'ALLOW') {throw "Unexpected ALLOW: $Witness"}
    Write-Output $Witness
}
try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    Set-TestAcl $root @('/inheritance:r','/grant:r',"$($systemSid):(OI)(CI)F","$($adminSid):(OI)(CI)F")
    Set-TestAcl $root @('/setowner',$adminSid)
    Set-Content -LiteralPath $leaf -Value '{"probeOnly":true}' -NoNewline -Encoding Ascii
    Set-TestAcl $leaf @('/inheritance:r','/grant:r',"$($systemSid):F","$($adminSid):F")
    Set-TestAcl $leaf @('/setowner',$adminSid)
    $dirResult=[ClassMeshPolicyHandleAttestation]::Check($root,$true)
    $fileResult=[ClassMeshPolicyHandleAttestation]::Check($leaf,$false)
    if($dirResult -ne 'ALLOW' -or $fileResult -ne 'ALLOW') {
        throw "Positive failed: dir=$dirResult file=$fileResult"
    }
    'PROTECTED_FILE_ALLOW'
    Set-TestAcl $leaf @('/grant',"$($userSid):M")
    Assert-Denied 'USER_WRITABLE_FILE_DENIED' ([ClassMeshPolicyHandleAttestation]::Check($leaf,$false))
    Set-TestAcl $leaf @('/remove:g',$userSid)
    Set-TestAcl $root @('/grant',"$($userSid):(OI)(CI)M")
    Assert-Denied 'USER_WRITABLE_DIRECTORY_DENIED' ([ClassMeshPolicyHandleAttestation]::Check($root,$true))
    Set-TestAcl $root @('/remove:g',$userSid)
    Set-TestAcl $leaf @('/setowner',('*'+$identity.User.Value))
    Assert-Denied 'WRONG_OWNER_DENIED' ([ClassMeshPolicyHandleAttestation]::Check($leaf,$false))
    Set-TestAcl $leaf @('/setowner',$adminSid)
    New-Item -ItemType SymbolicLink -Path $link -Target $leaf -ErrorAction Stop | Out-Null
    if([ClassMeshPolicyHandleAttestation]::Check($link,$false) -ne 'REPARSE_DENIED') {
        throw 'Native handle followed/accepted symlink'
    }
    'LEAF_REPARSE_DENIED'
    Assert-Denied 'MISSING_FILE_DENIED' ([ClassMeshPolicyHandleAttestation]::Check((Join-Path $root 'missing.json'),$false))
}finally{
    if(Test-Path -LiteralPath $root) {Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop}
    'CLEANUP_COMPLETE'
}
