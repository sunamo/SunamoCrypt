namespace SunamoCrypt;

public partial class CryptHelper2
{
    /// <summary>
    ///     RSA není uspůsobeno pro velké bloky dat, proto max, ale opravdu MAXimální velikost je 64bajtů
    /// </summary>
    private const int RSA_BLOCKSIZE = 64;
    private const int AsymmetricKeySize = 1024;
    private static readonly bool s_OAEP = false;
    public static string xEncryptedTextIsAnInvalidLength = "EncryptedTextIsAnInvalidLength";
    /// <summary>
    ///     Před použitím jednoduchých metod musíš nastavit tuto proměnnou
    /// </summary>
    public static List<byte> _s16 = null;
    public static string _pp = null;
    public static List<byte> _ivRijn = null;
    public static List<byte> _ivRc2 = null;
    public static List<byte> _ivTrip = null;
    public static string EncryptRSA(string text, int dwKeySize, string xmlString)
    {
        // TODO: Add Proper Exception Handlers
        var rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
        rsaCryptoServiceProvider.FromXmlString(xmlString);
        var keySize = dwKeySize / 8;
        var bytes = Encoding.UTF32.GetBytes(text).ToList();
        var maxLength = keySize - 42;
        var dataLength = bytes.Count;
        var iterations = dataLength / maxLength;
        var stringBuilder = new StringBuilder();
        for (var i = 0; i <= iterations; i++)
        {
            var tempBytes = new List<byte>(dataLength - maxLength * i > maxLength ? maxLength : dataLength - maxLength * i);
            Buffer.BlockCopy(bytes.ToArray(), maxLength * i, tempBytes.ToArray(), 0, tempBytes.Count);
            var encryptedBytes = rsaCryptoServiceProvider.Encrypt(tempBytes.ToArray(), true).ToList();
            encryptedBytes.Reverse();
            stringBuilder.Append(Convert.ToBase64String(encryptedBytes.ToArray()));
        }

        return stringBuilder.ToString();
    }

    public static string DecryptRSA(string text, int dwKeySize, string xmlString)
    {
        // TODO: Add Proper Exception Handlers
        var rsaCryptoServiceProvider = new RSACryptoServiceProvider(dwKeySize);
        rsaCryptoServiceProvider.FromXmlString(xmlString);
        var base64BlockSize = dwKeySize / 8 % 3 != 0 ? dwKeySize / 8 / 3 * 4 + 4 : dwKeySize / 8 / 3 * 4;
        var iterations = text.Count() / base64BlockSize;
        var arrayList = new ArrayList();
        for (var i = 0; i < iterations; i++)
        {
            var encryptedBytes = Convert.FromBase64String(text.Substring(base64BlockSize * i, base64BlockSize)).ToList();
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
    EncryptRSA(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes, string xmlKeyFile, int keySize)
    {
        //CspParameters csp = new CspParameters();
        var rsa = new RSACryptoServiceProvider(keySize, VratCspParameters(true));
        rsa.PersistKeyInCsp = false;
        rsa.FromXmlString(
#if ASYNC
            await
#endif
        File.ReadAllTextAsync(xmlKeyFile));
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

    public static RSAParameters GetRSAParametersFromXml(string xmlFilePath)
    {
        var rp = new RSAParameters();
        var xd = new XmlDocument();
        xd.Load(xmlFilePath);
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
    DecryptRSA(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes, string xmlKeyFile, int keySize)
    {
        var rsa = new RSACryptoServiceProvider(keySize, VratCspParameters(false));
        rsa.PersistKeyInCsp = false;
        rsa.FromXmlString(
#if ASYNC
            await
#endif
        File.ReadAllTextAsync(xmlKeyFile));
        //bool b = rsa.PublicOnly;
        if (cipherTextBytes.Count % RSA_BLOCKSIZE != 0)
            throw new Exception(xEncryptedTextIsAnInvalidLength);
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
    private static CspParameters VratCspParameters(bool isEncrypting)
#pragma warning restore
    {
        var csp = new CspParameters();
        return csp;
    }

    public static List<byte> EncryptTripleDES(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
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

    public static string EncryptTripleDES(string text)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text)));
    }

    public static List<byte> DecryptTripleDES(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
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

    public static List<byte> DecryptTripleDES(List<byte> cipherTextBytes)
    {
        return DecryptTripleDES(cipherTextBytes, _pp, _s16, _ivTrip);
    }

    public static string DecryptTripleDES(string cipherTextBytes)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(cipherTextBytes)));
    }
}