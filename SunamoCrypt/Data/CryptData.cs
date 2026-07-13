// variables names: ok
namespace SunamoCrypt.Data;

public class CryptData : ICrypt
{
    public required List<byte> Salt { get; set; }
    public required List<byte> InitializationVector { get; set; }
    public required string Passphrase { get; set; }
}
