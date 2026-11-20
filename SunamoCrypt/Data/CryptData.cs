namespace SunamoCrypt.Data;

/// <summary>
/// Represents the crypt data type.
/// </summary>
public class CryptData : ICrypt
{
    /// <summary>
    /// Gets or sets the salt.
    /// </summary>
    public required List<byte> Salt { get; set; }
    /// <summary>
    /// Gets or sets the initialization vector.
    /// </summary>
    public required List<byte> InitializationVector { get; set; }
    /// <summary>
    /// Gets or sets the passphrase.
    /// </summary>
    public required string Passphrase { get; set; }
}
