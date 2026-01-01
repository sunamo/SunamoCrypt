// variables names: ok
namespace SunamoCrypt._public.SunamoInterfaces.Interfaces;

/// <summary>
/// Interface for cryptographic operations
/// </summary>
public interface ICrypt
{
    /// <summary>
    /// Salt value for encryption
    /// </summary>
    List<byte> Salt { get; set; }
    /// <summary>
    /// Initialization vector for encryption
    /// </summary>
    List<byte> InitializationVector { get; set; }
    /// <summary>
    /// Passphrase for encryption
    /// </summary>
    string Passphrase { get; set; }
}