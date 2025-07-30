namespace SunamoCrypt;

public class CryptHelper2
{
    /// <summary>
    ///     RSA není uspůsobeno pro velké bloky dat, proto max, ale opravdu MAXimální velikost je 64bajtů
    /// </summary>
    private const int RSA_BLOCKSIZE = 64;

    private const int velikostKliceAsym = 1024;
    private static readonly bool s_OAEP = false;

    private static Type type = typeof(CryptHelper2);
    public static string xEncryptedTextIsAnInvalidLength = "EncryptedTextIsAnInvalidLength";

    /// <summary>
    ///     Před použitím jednoduchých metod musíš nastavit tuto proměnnou
    /// </summary>
    public static List<byte> _s16 = null;

    public static string _pp = null;
    public static List<byte> _ivRijn = null;
    public static List<byte> _ivRc2 = null;
    public static List<byte> _ivTrip = null;

    public static string EncryptRSA(string inputString, int dwKeySize, string xmlString)
    {
        // TODO: Add Proper Exception Handlers
        var rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
        rsaCryptoServiceProvider.FromXmlString(xmlString);
        var keySize = dwKeySize / 8;
        var bytes = Encoding.UTF32.GetBytes(inputString).ToList();
        var maxLength = keySize - 42;
        var dataLength = bytes.Count;
        var iterations = dataLength / maxLength;
        var stringBuilder = new StringBuilder();
        for (var i = 0; i <= iterations; i++)
        {
            var tempBytes =
                new List<byte>(dataLength - maxLength * i > maxLength ? maxLength : dataLength - maxLength * i);
            Buffer.BlockCopy(bytes.ToArray(), maxLength * i, tempBytes.ToArray(), 0, tempBytes.Count);
            var encryptedBytes = rsaCryptoServiceProvider.Encrypt(tempBytes.ToArray(), true).ToList();
            encryptedBytes.Reverse();
            stringBuilder.Append(Convert.ToBase64String(encryptedBytes.ToArray()));
        }

        return stringBuilder.ToString();
    }

    public static string DecryptRSA(string inputString, int dwKeySize, string xmlString)
    {
        // TODO: Add Proper Exception Handlers
        var rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
        rsaCryptoServiceProvider.FromXmlString(xmlString);
        var base64BlockSize = dwKeySize / 8 % 3 != 0 ? dwKeySize / 8 / 3 * 4 + 4 : dwKeySize / 8 / 3 * 4;
        var iterations = inputString.Count() / base64BlockSize;
        var arrayList = new ArrayList();
        for (var i = 0; i < iterations; i++)
        {
            var encryptedBytes = Convert.FromBase64String(inputString.Substring(base64BlockSize * i, base64BlockSize))
                .ToList();
            encryptedBytes.Reverse();
            arrayList.AddRange(rsaCryptoServiceProvider.Decrypt(encryptedBytes.ToArray(), true));
        }

        return null;
    }

    public static
#if ASYNC
        async Task<List<byte>>
#else
      List<byte>
#endif
        EncryptRSA(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes,
            string xmlSouborKlíče, int velikostKliče)
    {
        //CspParameters csp = new CspParameters();
        var rsa = new RSACryptoServiceProvider(velikostKliče, VratCspParameters(true));
        rsa.PersistKeyInCsp = false;
        rsa.FromXmlString(
#if ASYNC
            await
#endif
                File.ReadAllTextAsync(xmlSouborKlíče));
        //int nt = rsa.ExportParameters(true).Modulus.Count;
        var lastBlockLength = plainTextBytes.Count % RSA_BLOCKSIZE;
        decimal bc = plainTextBytes.Count / RSA_BLOCKSIZE;
        var blockCount = (int)Math.Floor(bc);
        var hasLastBlock = false;
        if (lastBlockLength != 0)
        {
            //We need to create a final block for the remaining characters
            blockCount += 1;
            hasLastBlock = true;
        }

        var vr = new List<byte>();
        for (var blockIndex = 0; blockIndex <= blockCount - 1; blockIndex++)
        {
            var thisBlockLength = 0;
            //If this is the last block and we have a remainder, then set the length accordingly
            if (blockCount == blockIndex + 1 && hasLastBlock)
                thisBlockLength = lastBlockLength;
            else
                thisBlockLength = RSA_BLOCKSIZE;

            var startChar = blockIndex * RSA_BLOCKSIZE;
            //Define the block that we will be working on
            var currentBlock = new List<byte>(thisBlockLength);
            Array.Copy(plainTextBytes.ToArray(), startChar, currentBlock.ToArray(), 0, thisBlockLength);
            var encryptedBlock = rsa.Encrypt(currentBlock.ToArray(), s_OAEP).ToList();
            vr.AddRange(encryptedBlock);
        }

        rsa.Clear();
        return vr;
        //return rsa.Encrypt(plainTextBytesBytes, false);
    }

    public static RSAParameters GetRSAParametersFromXml(string p)
    {
        var rp = new RSAParameters();
        var xd = new XmlDocument();
        xd.Load(p);
        // Je lepší to číst v Ascii protože to bude po jednom bytu číst
        var kod = Encoding.UTF8;
        rp.D = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/D").InnerText);
        rp.DP = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/DP").InnerText);
        rp.DQ = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/DQ").InnerText);
        rp.Exponent = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/Exponent").InnerText);
        rp.InverseQ = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/InverseQ").InnerText);
        rp.Modulus = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/Modulus").InnerText);
        rp.P = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/P").InnerText);
        rp.Q = Convert.FromBase64String(xd.SelectSingleNode("RSAKeyValue/Q").InnerText);
        return rp;
    }

    // TODO: Umožnit export do key containery a v případě potřeby to z něho vytáhnout.
    public static
#if ASYNC
        async Task<List<byte>>
#else
      List<byte>
#endif
        DecryptRSA(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes,
            string xmlSouborKlíče, int velikostKliče)
    {
        var rsa = new RSACryptoServiceProvider(velikostKliče, VratCspParameters(false));
        rsa.PersistKeyInCsp = false;
        rsa.FromXmlString(
#if ASYNC
            await
#endif
                File.ReadAllTextAsync(xmlSouborKlíče));
        //bool b = rsa.PublicOnly;
        if (cipherTextBytes.Count % RSA_BLOCKSIZE != 0) throw new Exception(xEncryptedTextIsAnInvalidLength);

        //Calculate the number of blocks we will have to work on
        var blockCount = cipherTextBytes.Count / RSA_BLOCKSIZE;
        var vr = new List<byte>();
        for (var blockIndex = 0; blockIndex < blockCount; blockIndex++)
        {
            var startChar = blockIndex * RSA_BLOCKSIZE;
            //Define the block that we will be working on
            var currentBlockBytes = new List<byte>(RSA_BLOCKSIZE);
            Array.Copy(cipherTextBytes.ToArray(), startChar, currentBlockBytes.ToArray(), 0, RSA_BLOCKSIZE);
            var currentBlockDecrypted = rsa.Decrypt(currentBlockBytes.ToArray(), s_OAEP).ToList();
            vr.AddRange(currentBlockDecrypted);
        }

        //Release all resources held by the RSA service provider
        rsa.Clear();
        return vr;
        //return rsa.Decrypt(cipherTextBytes, false);
    }

#pragma warning disable
    private static CspParameters VratCspParameters(bool b)
#pragma warning restore
    {
        var csp = new CspParameters();
        return csp;
    }

    public static List<byte> EncryptTripleDES(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes,
        List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Může bý jakékoliv číslo
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = new TripleDESCryptoServiceProvider();
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

    public static List<byte> EncryptTripleDES(List<byte> plainTextBytes)
    {
        return EncryptTripleDES(plainTextBytes, _pp, _s16, _ivTrip);
    }

    public static string EncryptTripleDES(string p)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptTripleDES(BTS2.ConvertFromUtf8ToBytes(p)));
    }

    public static List<byte> DecryptTripleDES(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes,
        List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Může bý jakékoliv číslo
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = new TripleDESCryptoServiceProvider();
        symmetricKey.Mode = CipherMode.CBC;
        var decryptor = symmetricKey.CreateDecryptor(keyBytes.ToArray(), initVectorBytes.ToArray());
        // Define memory stream which will be used to hold encrypted data.
        var memoryStream = new MemoryStream(cipherTextBytes.ToArray());
        // Define cryptographic stream (always use Read mode for encryption).
        var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
        var plainTextBytes = new List<byte>(cipherTextBytes.Count);
        // Start decrypting.
        var decryptedByteCount = cryptoStream.Read(plainTextBytes.ToArray(), 0, plainTextBytes.Count);
        // Close both streams.
        memoryStream.Close();
        cryptoStream.Close();
        return plainTextBytes;
    }

    public static List<byte> DecryptTripleDES(List<byte> plainTextBytes)
    {
        return DecryptTripleDES(plainTextBytes, _pp, _s16, _ivTrip);
    }

    public static string DecryptTripleDES(string p)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(p)));
    }

    public static List<byte> DecryptRijndael(List<byte> plainTextBytes)
    {
        return DecryptRijndael(plainTextBytes, _pp, _s16, _ivRijn);
    }

    /// <summary>
    ///     Pokud chci bajty, musím si je znovu převést a nebo odkomentovat metodu níže
    /// </summary>
    /// <param name="plainTextBytes"></param>
    /// <param name="salt"></param>
    public static string DecryptRijndael(string plainText, List<byte> salt)
    {
        return BTS2.ConvertFromBytesToUtf8(
            DecryptRijndael(BTS2.ClearEndingsBytes(BTS2.ConvertFromUtf8ToBytes(plainText)), _pp, salt, _ivRijn));
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

    public static List<byte> EncryptRC2(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes,
        List<byte> initVectorBytes)
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

    public static List<byte> DecryptRC2(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes,
        List<byte> initVectorBytes)
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
    /// <param name="cipherText">
    ///     Base64-formatted ciphertext value.
    /// </param>
    /// <param name="passPhrase">
    ///     Passphrase from which a pseudo-random password will be derived. The
    ///     derived password will be used to generate the encryption key.
    ///     Passphrase can be any string. In this example we assume that this
    ///     passphrase is an ASCII string.
    /// </param>
    /// <param name="saltValue">
    ///     Salt value used along with passphrase to generate password. Salt can
    ///     be any string. In this example we assume that salt is an ASCII string.
    /// </param>
    /// <param name="hashAlgorithm">
    ///     Hash algorithm used to generate password. Allowed values are: "MD5" and
    ///     "A1". SHA1 hashes are a bit slower, but more secure than MD5 hashes.
    /// </param>
    /// <param name="passwordIterations">
    ///     Number of iterations used to generate password. One or two iterations
    ///     should be enough.
    /// </param>
    /// <param name="initVector">
    ///     Initialization vector (or IV). This value is required to encrypt the
    ///     first block of plaintext data. For RijndaelManaged public class IV must be
    ///     exactly 16 ASCII characters long.
    /// </param>
    /// <param name="keySize">
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
    public static List<byte> DecryptRijndael(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes,
        List<byte> initVectorBytes)
    {
        if (cipherTextBytes.Count == 0) return new List<byte>();

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

    /// <summary>
    ///     Encrypts specified plaintext using Rijndael symmetric key algorithm
    ///     and returns a base64-encoded result.
    /// </summary>
    /// <param name="plainText">
    ///     Plaintext value to be encrypted.
    /// </param>
    /// <param name="passPhrase">
    ///     Passphrase from which a pseudo-random password will be derived. The
    ///     derived password will be used to generate the encryption key.
    ///     Passphrase can be any string. In this example we assume that this
    ///     passphrase is an ASCII string.
    /// </param>
    /// <param name="saltValue">
    ///     Salt value used along with passphrase to generate password. Salt can
    ///     be any string. In this example we assume that salt is an ASCII string.
    /// </param>
    /// <param name="hashAlgorithm">
    ///     Hash algorithm used to generate password. Allowed values are: "MD5" and
    ///     "A1". SHA1 hashes are a bit slower, but more secure than MD5 hashes.
    /// </param>
    /// <param name="passwordIterations">
    ///     Number of iterations used to generate password. One or two iterations
    ///     should be enough.
    /// </param>
    /// <param name="initVector">
    ///     Initialization vector (or IV). This value is required to encrypt the
    ///     first block of plaintext data. For RijndaelManaged public class IV must be
    ///     exactly 16 ASCII characters long.
    /// </param>
    /// <param name="keySize">
    ///     Size of encryption key in bits. Allowed values are: 128, 192, and 256.
    ///     Longer keys are more secure than shorter keys.
    /// </param>
    /// <returns>
    ///     Encrypted value formatted as a base64-encoded string.
    /// </returns>
    public static List<byte> EncryptRijndael(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes,
        List<byte> initVectorBytes)
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