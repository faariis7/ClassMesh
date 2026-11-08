if (-not ('ClassMeshIdentityBoundedOutput' -as [type])) {
    Add-Type -TypeDefinition @'
using System.IO;
using System.Threading.Tasks;
public static class ClassMeshIdentityBoundedOutput {
    public static Task<string> Read(TextReader reader, int limit) {
        return reader.ReadToEndAsync();
    }
}
'@
}
