// variables names: ok
namespace SunamoCrypt.Data;

/// <summary>
/// Data holder for cryptographic operations
/// </summary>
public class CryptData : ICrypt
{
    /// <summary>
    /// Salt value for encryption
    /// </summary>
    public required List<byte> Salt { get; set; }
    /// <summary>
    /// Initialization vector for encryption
    /// </summary>
    public required List<byte> InitializationVector { get; set; }
    /// <summary>
    /// Passphrase for encryption
    /// </summary>
    public required string Passphrase { get; set; }
}
