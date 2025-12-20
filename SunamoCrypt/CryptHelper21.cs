// EN: Variable names have been checked and replaced with self-descriptive names
// CZ: Názvy proměnných byly zkontrolovány a nahrazeny samopopisnými názvy
namespace SunamoCrypt;
public partial class CryptHelper2
{
    public static List<byte> DecryptRijndael(List<byte> plainTextBytes)
    {
        return DecryptRijndael(plainTextBytes, _pp, _s16, _ivRijn);
    }

    /// <summary>
    ///     Pokud chci bajty, musím si je znovu převést a nebo odkomentovat metodu níže
    /// </summary>
    /// <param name = "plainTextBytes"></param>
    /// <param name = "salt"></param>
    public static string DecryptRijndael(string plainText, List<byte> salt)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptRijndael(BTS2.ClearEndingsBytes(BTS2.ConvertFromUtf8ToBytes(plainText)), _pp, salt, _ivRijn));
    }

    public static List<byte> DecryptRijndael(List<byte> plainTextBytes, List<byte> salt)
    {
        return DecryptRijndael(plainTextBytes, _pp, salt, _ivRijn);
    }

    public static string DecryptRijndael(string p)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptRijndael(BTS2.ConvertFromUtf8ToBytes(p)));
    }

    public static List<byte> EncryptRijndael(List<byte> plainTextBytes, List<byte> salt)
    {
        return EncryptRijndael(plainTextBytes, _pp, salt, _ivRijn);
    }

    public static List<byte> EncryptRijndael(List<byte> plainTextBytes)
    {
        return EncryptRijndael(plainTextBytes, _pp, _s16, _ivRijn);
    }

    public static string EncryptRijndael(string p)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptRijndael(BTS2.ConvertFromUtf8ToBytes(p)));
    }

    public static List<byte> EncryptRC2(List<byte> plainTextBytes)
    {
        return EncryptRC2(plainTextBytes, _pp, _s16, _ivRc2);
    }

    public static string EncryptRC2(string p)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptRC2(BTS2.ConvertFromUtf8ToBytes(p)));
    }

    public static List<byte> EncryptRC2(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Může bý jakékoliv číslo
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = new RC2CryptoServiceProvider();
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

    public static List<byte> DecryptRC2(List<byte> plainTextBytes)
    {
        return DecryptRC2(plainTextBytes, _pp, _s16, _ivRc2);
    }

    public static string DecryptRC2(string p)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptRC2(BTS2.ConvertFromUtf8ToBytes(p)));
    }

    public static List<byte> DecryptRC2(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Může bý jakékoliv číslo
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = new RC2CryptoServiceProvider();
        symmetricKey.Mode = CipherMode.CBC;
        var decryptor = symmetricKey.CreateDecryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        // Define memory stream which will be used to hold encrypted data.
        var memoryStream = new MemoryStream(cipherTextBytes.ToArray());
        // Define cryptographic stream (always use Read mode for encryption).
        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        var plainTextBytes = new List<byte>(cipherTextBytes.Count());
        // Start decrypting.
        var decryptedByteCount = cryptoStream.Read(plainTextBytes.ToArray(), 0, plainTextBytes.Count);
        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();
        return plainTextBytes;
    }

    /// <summary>
    ///     Decrypts specified ciphertext using Rijndael symmetric key algorithm.
    /// </summary>
    /// <param name = "cipherText">
    ///     Base64-formatted ciphertext value.
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
    ///     Decrypted string value.
    /// </returns>
    /// <remarks>
    ///     Most of the logic in this function is similar to the Encrypt
    ///     logic. In order for decryption to work, all parameters of this function
    ///     - except cipherText value - must match the corresponding parameters of
    ///     the Encrypt function which was called to generate the
    ///     ciphertext.
    /// </remarks>
    /// d
    public static List<byte> DecryptRijndael(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        if (cipherTextBytes.Count == 0)
            return new List<byte>();
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Může bý jakékoliv číslo
        // zkusit tuhle větev jestli funguje a jestli to nebude mršit
        if (false)
        {
        //PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        //List<byte> keyBytes = password.GetBytes(keySize / 8).ToList();
        //// Create uninitialized Rijndael encryption object.
        //RijndaelManaged symmetricKey = new RijndaelManaged();
        //symmetricKey.Mode = CipherMode.CBC;
        //ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        //// Define memory stream which will be used to hold encrypted data.
        //MemoryStream memoryStream = new MemoryStream(cipherTextBytes.ToArray());
        //// Define cryptographic stream (always use Read mode for encryption).
        //CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        //List<byte> plainTextBytes = new List<byte>(cipherTextBytes.Count());
        //// Start decrypting.
        //int decryptedByteCount = cryptoStream.Read(plainTextBytes.ToArray(), 0, plainTextBytes.Count);
        //// Close both streams.
        //memoryStream.Close();
        //cryptoStream.Close();
        //return plainTextBytes;
        }

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
        var symmetricKey = new RijndaelManaged();
        // It is reasonable to set encryption mode to Cipher Block Chaining
        // (CBC). Use default options for other symmetric key parameters.
        symmetricKey.Mode = CipherMode.CBC;
        // CFB - remove padding zero, CBC - keep padding zero
        //symmetricKey.Mode = CipherMode.CFB;
        // Generate decryptor from the existing key bytes and initialization 
        // vector. Key size will be defined based on the number of the key 
        // bytes.
        var decryptor = symmetricKey.CreateDecryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        // Define memory stream which will be used to hold encrypted data.
        var memoryStream = new MemoryStream(cipherTextBytes.ToArray());
        // Define cryptographic stream (always use Read mode for encryption).
        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        // Since at this point we don't know what the size of decrypted data
        // will be, allocate the buffer long enough to hold ciphertext;
        // plaintext is never longer than ciphertext.
        // Here must be byte[], otherwise cryptoStream.Close() throw a exception
        var plainTextBytes = new byte[cipherTextBytes.Count];
        // Start decrypting.
        var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();
        // Convert decrypted data into a string. 
        // Let us assume that the original plaintext string was UTF8-encoded.
        return plainTextBytes.ToList();
    }
}