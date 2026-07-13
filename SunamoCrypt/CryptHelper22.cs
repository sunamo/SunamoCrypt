namespace SunamoCrypt;

// EN: Variable names have been checked and replaced with self-descriptive names
// CZ: Nazvy promennych byly zkontrolovany a nahrazeny samopopisnymi nazvy
public partial class CryptHelper2
{
    // Uses A1 hash algorithm, 128-bit key size, and 2 password iterations (hardcoded internally)
    public static List<byte> EncryptRijndael(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "SHA1";
        var keySize = 128;
        var passwordIterations = 2; // Can be any number
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = new List<byte>(password.GetBytes(keySize / 8));
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = Aes.Create();
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
}
