namespace SunamoCrypt.Enums;

// Symmetric encryption providers.
/// <summary>
/// Represents the provider type.
/// </summary>
public enum Provider
{
    // The Data Encryption Standard provider supports a 64 bit key only
    /// <summary>
    /// The DES value.
    /// </summary>
    DES,
    // The Rivest Cipher 2 provider supports keys ranging from 40 to 128 bits, default is 128 bits
    /// <summary>
    /// The RC 2 value.
    /// </summary>
    RC2,
    // The Rijndael (also known as AES) provider supports keys of 128, 192, or 256 bits with a default of 256 bits
    /// <summary>
    /// The rijndael value.
    /// </summary>
    Rijndael,
    // The TripleDES provider (also known as 3DES) supports keys of 128 or 192 bits with a default of 192 bits
    /// <summary>
    /// The triple DES value.
    /// </summary>
    TripleDES
}
