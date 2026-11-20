namespace SunamoCrypt._public.SunamoInterfaces.Interfaces;

/// <summary>
/// Represents the i crypt type.
/// </summary>
public interface ICrypt
{
    /// <summary>
    /// Gets or sets the salt.
    /// </summary>
    List<byte> Salt { get; set; }
    /// <summary>
    /// Gets or sets the initialization vector.
    /// </summary>
    List<byte> InitializationVector { get; set; }
    /// <summary>
    /// Gets or sets the passphrase.
    /// </summary>
    string Passphrase { get; set; }
}