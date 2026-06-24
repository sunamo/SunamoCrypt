namespace SunamoCrypt;

public partial class CryptHelper2
{
    // RSA is not suitable for large blocks of data, therefore the maximum block size is 64 bytes
    private const int RsaBlockSize = 64;
    private const int AsymmetricKeySize = 1024;
    private static readonly bool IsOaep = false;
    public static string EncryptedTextIsAnInvalidLength = "EncryptedTextIsAnInvalidLength";
    // 16-byte salt for encryption (must be set before using convenience methods)
    public static List<byte>? Salt16 = null;
    // Passphrase for encryption (must be set before using convenience methods)
    public static string? Passphrase = null;
    public static List<byte>? InitializationVectorRijndael = null;
    public static List<byte>? InitializationVectorRc2 = null;
    public static List<byte>? InitializationVectorTripleDes = null;

    public static string EncryptRSA(string text, int keySize, string xmlString)
    {
        // TODO: Add Proper Exception Handlers
        var rsaCryptoServiceProvider = new RSACryptoServiceProvider(keySize);
        rsaCryptoServiceProvider.FromXmlString(xmlString);
        var keySizeInBytes = keySize / 8;
        var bytes = Encoding.UTF32.GetBytes(text).ToList();
        var maxLength = keySizeInBytes - 42;
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

    public static string DecryptRSA(string text, int keySize, string xmlString)
    {
        // TODO: Add Proper Exception Handlers
        var rsaCryptoServiceProvider = new RSACryptoServiceProvider(keySize);
        rsaCryptoServiceProvider.FromXmlString(xmlString);
        var base64BlockSize = keySize / 8 % 3 != 0 ? keySize / 8 / 3 * 4 + 4 : keySize / 8 / 3 * 4;
        var iterations = text.Count() / base64BlockSize;
        var arrayList = new ArrayList();
        for (var i = 0; i < iterations; i++)
        {
            var encryptedBytes = Convert.FromBase64String(text.Substring(base64BlockSize * i, base64BlockSize)).ToList();
            encryptedBytes.Reverse();
            arrayList.AddRange(rsaCryptoServiceProvider.Decrypt(encryptedBytes.ToArray(), true));
        }

        return null!;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static
        async Task<List<byte>>
    EncryptRSA(List<byte> plainTextBytes, string xmlKeyFile, int keySize)
    {
        //CspParameters csp = new CspParameters();
        var rsa = new RSACryptoServiceProvider(keySize, GetCspParameters(true));
        rsa.PersistKeyInCsp = false;
        rsa.FromXmlString(
            await FileAsync.ReadAllTextAsync(xmlKeyFile)
        );
        //int nt = rsa.ExportParameters(true).Modulus.Count;
        var lastBlockLength = plainTextBytes.Count % RsaBlockSize;
        decimal blockCountDecimal = plainTextBytes.Count / RsaBlockSize;
        var blockCount = (int)Math.Floor(blockCountDecimal);
        var hasLastBlock = false;
        if (lastBlockLength != 0)
        {
            //We need to create a final block for the remaining characters
            blockCount += 1;
            hasLastBlock = true;
        }

        var result = new List<byte>();
        for (var blockIndex = 0; blockIndex <= blockCount - 1; blockIndex++)
        {
            var thisBlockLength = 0;
            //If this is the last block and we have a remainder, then set the length accordingly
            if (blockCount == blockIndex + 1 && hasLastBlock)
                thisBlockLength = lastBlockLength;
            else
                thisBlockLength = RsaBlockSize;
            var startChar = blockIndex * RsaBlockSize;
            //Define the block that we will be working on
            var currentBlock = new List<byte>(thisBlockLength);
            Array.Copy(plainTextBytes.ToArray(), startChar, currentBlock.ToArray(), 0, thisBlockLength);
            var encryptedBlock = rsa.Encrypt(currentBlock.ToArray(), IsOaep).ToList();
            result.AddRange(encryptedBlock);
        }

        rsa.Clear();
        return result;
    //return rsa.Encrypt(plainTextBytesBytes, false);
    }

    public static RSAParameters GetRSAParametersFromXml(string xmlFilePath)
    {
        var rsaParameters = new RSAParameters();
        var xmlDocument = new XmlDocument();
        xmlDocument.Load(xmlFilePath);
        rsaParameters.D = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/D")?.InnerText ?? throw new InvalidOperationException("D node not found"));
        rsaParameters.DP = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/DP")?.InnerText ?? throw new InvalidOperationException("DP node not found"));
        rsaParameters.DQ = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/DQ")?.InnerText ?? throw new InvalidOperationException("DQ node not found"));
        rsaParameters.Exponent = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/Exponent")?.InnerText ?? throw new InvalidOperationException("Exponent node not found"));
        rsaParameters.InverseQ = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/InverseQ")?.InnerText ?? throw new InvalidOperationException("InverseQ node not found"));
        rsaParameters.Modulus = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/Modulus")?.InnerText ?? throw new InvalidOperationException("Modulus node not found"));
        rsaParameters.P = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/P")?.InnerText ?? throw new InvalidOperationException("P node not found"));
        rsaParameters.Q = Convert.FromBase64String(xmlDocument.SelectSingleNode("RSAKeyValue/Q")?.InnerText ?? throw new InvalidOperationException("Q node not found"));
        return rsaParameters;
    }

    // TODO: Enable export to key container and extract from it if needed.
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static
        async Task<List<byte>>
    DecryptRSA(List<byte> cipherTextBytes, string xmlKeyFile, int keySize)
    {
        var rsa = new RSACryptoServiceProvider(keySize, GetCspParameters(false));
        rsa.PersistKeyInCsp = false;
        rsa.FromXmlString(
            await FileAsync.ReadAllTextAsync(xmlKeyFile)
        );
        //bool b = rsa.PublicOnly;
        if (cipherTextBytes.Count % RsaBlockSize != 0)
            throw new Exception(EncryptedTextIsAnInvalidLength);
        //Calculate the number of blocks we will have to work on
        var blockCount = cipherTextBytes.Count / RsaBlockSize;
        var result = new List<byte>();
        for (var blockIndex = 0; blockIndex < blockCount; blockIndex++)
        {
            var startChar = blockIndex * RsaBlockSize;
            //Define the block that we will be working on
            var currentBlockBytes = new List<byte>(RsaBlockSize);
            Array.Copy(cipherTextBytes.ToArray(), startChar, currentBlockBytes.ToArray(), 0, RsaBlockSize);
            var currentBlockDecrypted = rsa.Decrypt(currentBlockBytes.ToArray(), IsOaep).ToList();
            result.AddRange(currentBlockDecrypted);
        }

        //Release all resources held by the RSA service provider
        rsa.Clear();
        return result;
    //return rsa.Decrypt(cipherTextBytes, false);
    }

#pragma warning disable
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static CspParameters GetCspParameters(bool isEncrypting)
#pragma warning restore
    {
        var csp = new CspParameters();
        return csp;
    }

    public static List<byte> EncryptTripleDES(List<byte> plainTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Can be any number
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = TripleDES.Create();
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
        return EncryptTripleDES(plainTextBytes, Passphrase!, Salt16!, InitializationVectorTripleDes!);
    }

    public static string EncryptTripleDES(string text)
    {
        return BTS2.ConvertFromBytesToUtf8(EncryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text)));
    }

    public static List<byte> DecryptTripleDES(List<byte> cipherTextBytes, string passPhrase, List<byte> saltValueBytes, List<byte> initVectorBytes)
    {
        var hashAlgorithm = "A1";
        var keySize = 128;
        var passwordIterations = 2; // Can be any number
        var password = new PasswordDeriveBytes(passPhrase, saltValueBytes.ToArray(), hashAlgorithm, passwordIterations);
        var keyBytes = password.GetBytes(keySize / 8).ToList();
        // Create uninitialized Rijndael encryption object.
        var symmetricKey = TripleDES.Create();
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

    public static List<byte> DecryptTripleDES(List<byte> cipherTextBytes)
    {
        return DecryptTripleDES(cipherTextBytes, Passphrase!, Salt16!, InitializationVectorTripleDes!);
    }

    public static string DecryptTripleDES(string cipherText)
    {
        return BTS2.ConvertFromBytesToUtf8(DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(cipherText)));
    }
}
