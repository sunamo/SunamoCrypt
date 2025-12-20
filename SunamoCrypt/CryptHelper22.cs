// EN: Variable names have been checked and replaced with self-descriptive names
// CZ: Názvy proměnných byly zkontrolovány a nahrazeny samopopisnými názvy
namespace SunamoCrypt;
public partial class CryptHelper2
{
    /// <summary>
    ///     Encrypts specified plaintext using Rijndael symmetric key algorithm
    ///     and returns a base64-encoded result.
    /// </summary>
    /// <param name = "plainText">
    ///     Plaintext value to be encrypted.
    /// </param>
    /// <param name = "passPhrase">
    ///     Passphrase from which a pseudo-random password will be derived. The
    ///     derived password will be used to generate the encryption key.
    ///     Passphrase can be any string. In this example we assume that this
    ///     passphrase is an ASCII string.
    /// </param>
    /// <param name = "saltValue">
    ///     Salt value used along with passphrase to generate password. Salt can
    ///     be any string. In this example we assume that salt is an ASCII string.
    /// </param>
    /// <param name = "hashAlgorithm">
    ///     Hash algorithm used to generate password. Allowed values are: "MD5" and
    ///     "A1". SHA1 hashes are a bit slower, but more secure than MD5 hashes.
    /// </param>
    /// <param name = "passwordIterations">
    ///     Number of iterations used to generate password. One or two iterations
    ///     should be enough.
    /// </param>
    /// <param name = "initVector">
    ///     Initialization vector (or IV). This value is required to encrypt the
    ///     first block of plaintext data. For RijndaelManaged public class IV must be
    ///     exactly 16 ASCII characters long.
    /// </param>
    /// <param name = "keySize">
    ///     Size of encryption key in bits. Allowed values are: 128, 192, and 256.
    ///     Longer keys are more secure than shorter keys.
    /// </param>
    /// <returns>
    ///     Encrypted value formatted as a base64-encoded string.
    /// </returns>
    public static List<byte> EncryptRijndael(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Může bý jakékoliv číslo
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = new List<byte>(password.GetBytes(keySize / 8));
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = new RijndaelManaged();
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