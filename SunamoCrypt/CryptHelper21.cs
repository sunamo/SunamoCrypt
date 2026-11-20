namespace SunamoCrypt;

public partial class CryptHelper2
{
    /// <summary>
    /// Decrypt rijndael.
    /// </summary>
    /// <param name="cipherTextBytes">The cipher text bytes.</param>
    /// <returns>The decrypt rijndael result.</returns>
    public static List<byte> DecryptRijndael(List<byte> cipherTextBytes)
    {
        return DecryptRijndael(cipherTextBytes, Passphrase!, Salt16!, InitializationVectorRijndael!);
    }

    /// <summary>
    /// Decrypt rijndael.
    /// </summary>
    /// <param name="plainText">The plain text.</param>
    /// <param name="salt">The salt.</param>
    /// <returns>The decrypt rijndael result.</returns>
    public static string DecryptRijndael(string plainText, List<byte> salt)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptRijndael(BTS2.ClearEndingsBytes(BTS2.ConvertFromUtf8ToBytes(plainText)), Passphrase!, salt, InitializationVectorRijndael!));
    }

    /// <summary>
    /// Decrypt rijndael.
    /// </summary>
    /// <param name="cipherTextBytes">The cipher text bytes.</param>
    /// <param name="salt">The salt.</param>
    /// <returns>The decrypt rijndael result.</returns>
    public static List<byte> DecryptRijndael(List<byte> cipherTextBytes, List<byte> salt)
    {
        return DecryptRijndael(cipherTextBytes, Passphrase!, salt, InitializationVectorRijndael!);
    }

    /// <summary>
    /// Decrypt rijndael.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The decrypt rijndael result.</returns>
    public static string DecryptRijndael(string text)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptRijndael(BTS2.ConvertFromUtf8ToBytes(text)));
    }

    /// <summary>
    /// Encrypt rijndael.
    /// </summary>
    /// <param name="plainTextBytes">The plain text bytes.</param>
    /// <param name="salt">The salt.</param>
    /// <returns>The encrypt rijndael result.</returns>
    public static List<byte> EncryptRijndael(List<byte> plainTextBytes, List<byte> salt)
    {
        return EncryptRijndael(plainTextBytes, Passphrase!, salt, InitializationVectorRijndael!);
    }

    /// <summary>
    /// Encrypt rijndael.
    /// </summary>
    /// <param name="plainTextBytes">The plain text bytes.</param>
    /// <returns>The encrypt rijndael result.</returns>
    public static List<byte> EncryptRijndael(List<byte> plainTextBytes)
    {
        return EncryptRijndael(plainTextBytes, Passphrase!, Salt16!, InitializationVectorRijndael!);
    }

    /// <summary>
    /// Encrypt rijndael.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The encrypt rijndael result.</returns>
    public static string EncryptRijndael(string text)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptRijndael(BTS2.ConvertFromUtf8ToBytes(text)));
    }

    /// <summary>
    /// Encrypt RC 2.
    /// </summary>
    /// <param name="plainTextBytes">The plain text bytes.</param>
    /// <returns>The encrypt RC 2 result.</returns>
    public static List<byte> EncryptRC2(List<byte> plainTextBytes)
    {
        return EncryptRC2(plainTextBytes, Passphrase!, Salt16!, InitializationVectorRc2!);
    }

    /// <summary>
    /// Encrypt RC 2.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The encrypt RC 2 result.</returns>
    public static string EncryptRC2(string text)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptRC2(BTS2.ConvertFromUtf8ToBytes(text)));
    }

    /// <summary>
    /// Encrypt RC 2.
    /// </summary>
    /// <param name="plainTextBytes">The plain text bytes.</param>
    /// <param name="passPhrase">The pass phrase.</param>
    /// <param name="saltValueBytes">The salt value bytes.</param>
    /// <param name="initVectorBytes">The init vector bytes.</param>
    /// <returns>The encrypt RC 2 result.</returns>
    public static List<byte> EncryptRC2(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "SHA1";
        var keySize = 128;
        var passwordIterations = 2; // Can be any number
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = RC2.Create();
        symmetricKey.Mode = CipherMode.CBC;
        var encryptor = symmetricKey.CreateEncryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        // Define memory stream which will be used to hold encrypted data.
        var memoryStream = new MemoryStream();
        // Define cryptographic stream (always use Write mode for encryption).
        var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
        // Start encrypting.
        cryptoStream.Write(plainTextBytes.ToArray(), 0, plainTextBytes.Count);
        // Finish encrypting.
        cryptoStream.FlushFinalBlock();
        // Convert our encrypted data from a memory stream into a byte array.
        var cipherTextBytes = memoryStream.ToArray().ToList();
        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();
        return cipherTextBytes;
    }

    /// <summary>
    /// Decrypt RC 2.
    /// </summary>
    /// <param name="cipherTextBytes">The cipher text bytes.</param>
    /// <returns>The decrypt RC 2 result.</returns>
    public static List<byte> DecryptRC2(List<byte> cipherTextBytes)
    {
        return DecryptRC2(cipherTextBytes, Passphrase!, Salt16!, InitializationVectorRc2!);
    }

    /// <summary>
    /// Decrypt RC 2.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The decrypt RC 2 result.</returns>
    public static string DecryptRC2(string text)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptRC2(BTS2.ConvertFromUtf8ToBytes(text)));
    }

    /// <summary>
    /// Decrypt RC 2.
    /// </summary>
    /// <param name="cipherTextBytes">The cipher text bytes.</param>
    /// <param name="passPhrase">The pass phrase.</param>
    /// <param name="saltValueBytes">The salt value bytes.</param>
    /// <param name="initVectorBytes">The init vector bytes.</param>
    /// <returns>The decrypt RC 2 result.</returns>
    public static List<byte> DecryptRC2(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "SHA1";
        var keySize = 128;
        var passwordIterations = 2; // Can be any number
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = RC2.Create();
        symmetricKey.Mode = CipherMode.CBC;
        var decryptor = symmetricKey.CreateDecryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        // Define memory stream which will be used to hold encrypted data.
        var memoryStream = new MemoryStream(cipherTextBytes.ToArray());
        // Define cryptographic stream (always use Read mode for encryption).
        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        var plainTextBytes = new List<byte>(cipherTextBytes.Count);
        // Start decrypting.
        _ = cryptoStream.Read(plainTextBytes.ToArray(), 0, plainTextBytes.Count);
        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();
        return plainTextBytes;
    }

    // Uses A1 hash algorithm, 128-bit key size, and 2 password iterations (hardcoded internally).
    // All parameters must match those used during encryption.
    /// <summary>
    /// Decrypt rijndael.
    /// </summary>
    /// <param name="cipherTextBytes">The cipher text bytes.</param>
    /// <param name="passPhrase">The pass phrase.</param>
    /// <param name="saltValueBytes">The salt value bytes.</param>
    /// <param name="initVectorBytes">The init vector bytes.</param>
    /// <returns>The decrypt rijndael result.</returns>
    public static List<byte> DecryptRijndael(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        if (cipherTextBytes.Count == 0)
            return new List<byte>();
        var hashAlgorithm = "SHA1";
        var keySize = 128;
        var passwordIterations = 2; // Can be any number

        // First, we must create a password, from which the key will be
        // derived. This password will be generated from the specified
        // passphrase and salt value. The password will be created using
        // the specified hash algorithm. Password creation can be done in
        // several iterations.
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        // Use the password to generate pseudo-random bytes for the encryption
        // key. Specify the size of the key in bytes (instead of bits).
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = Aes.Create();
        // It is reasonable to set encryption mode to Cipher Block Chaining
        // (CBC). Use default options for other symmetric key parameters.
        symmetricKey.Mode = CipherMode.CBC;
        // CFB - remove padding zero, CBC - keep padding zero
        // Generate decryptor from the existing key bytes and initialization
        // vector. Key size will be defined based on the number of the key
        // bytes.
        var decryptor = symmetricKey.CreateDecryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        // Define memory stream which will be used to hold encrypted data.
        var memoryStream = new MemoryStream(cipherTextBytes.ToArray());
        // Define cryptographic stream (always use Read mode for encryption).
        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        // Since at this point we don't know what the size of decrypted data
        // plaintext is never longer than ciphertext.
        // Here must be byte[], otherwise cryptoStream.Close() throw a exception
        var plainTextBytes = new byte[cipherTextBytes.Count];
        // Start decrypting.
        _ = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();
        // Convert decrypted data into a string.
        // Let us assume that the original plaintext string was UTF8-encoded.
        return plainTextBytes.ToList();
    }
}
