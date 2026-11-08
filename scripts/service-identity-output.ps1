if (-not ('ClassMeshIdentityBoundedOutput' -as [type])) {
    Add-Type -TypeDefinition @'
using System.IO;
using System.Threading.Tasks;
using System.Text;
public static class ClassMeshIdentityBoundedOutput {
    public static async Task<string> Read(TextReader reader, int limit) {
        var output = new StringBuilder();
        var buffer = new char[512];
        while (true) {
            var count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            if (count == 0) return output.ToString();
            if (output.Length + count > limit) throw new InvalidDataException("identity output exceeded limit");
            output.Append(buffer, 0, count);
        }
    }
}
'@
}
