namespace SunamoCrypt.Enums;

// Symmetric encryption providers.
public enum Provider
{
    // The Data Encryption Standard provider supports a 64 bit key only
    DES,
    // The Rivest Cipher 2 provider supports keys ranging from 40 to 128 bits, default is 128 bits
    RC2,
    // The Rijndael (also known as AES) provider supports keys of 128, 192, or 256 bits with a default of 256 bits
    Rijndael,
    // The TripleDES provider (also known as 3DES) supports keys of 128 or 192 bits with a default of 192 bits
    TripleDES
}
