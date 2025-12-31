// variables names: ok
namespace SunamoCrypt.Data;

public class CryptData : ICrypt
{
    public List<byte> Salt { get; set; }
    public List<byte> InitializationVector { get; set; }
    public string Passphrase { get; set; }
}
