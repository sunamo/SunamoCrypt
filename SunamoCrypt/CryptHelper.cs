// variables names: ok
namespace SunamoCrypt;

/// <summary>
/// Cryptographic helper for encryption and decryption operations
/// </summary>
public class CryptHelper : ICryptHelper
{
    private readonly ICryptBytes _crypt;

    /// <summary>
    /// Initializes a new instance of the CryptHelper class
    /// </summary>
    /// <param name="provider">Encryption provider to use</param>
    /// <param name="salt">Salt value for encryption</param>
    /// <param name="initializationVector">Initialization vector</param>
    /// <param name="passphrase">Passphrase for encryption</param>
    public CryptHelper(Provider provider, List<byte> salt, List<byte> initializationVector, string passphrase)
    {
        switch (provider)
        {
            case Provider.DES:
                throw new Exception("DES symmetric encryption is not supported.");
            case Provider.RC2:
                //crypt = new CryptHelper.RC2();
                break;
            case Provider.Rijndael:
                _crypt = new RijndaelBytes();
                break;
            case Provider.TripleDES:
                //crypt = new CryptHelper.TripleDES();
                break;
            default:
                ThrowEx.NotImplementedCase(provider);
                break;
        }

        _crypt!.InitializationVector = initializationVector;
        _crypt!.Passphrase = passphrase;
        _crypt!.Salt = salt;
    }


    /// <summary>
    /// Decrypts the specified data
    /// </summary>
    /// <param name="data">Data to decrypt</param>
    /// <returns>Decrypted data</returns>
    public List<byte> Decrypt(List<byte> data)
    {
        return _crypt.Decrypt(data);
    }

    /// <summary>
    /// Encrypts the specified data
    /// </summary>
    /// <param name="data">Data to encrypt</param>
    /// <returns>Encrypted data</returns>
    public List<byte> Encrypt(List<byte> data)
    {
        return _crypt.Encrypt(data);
    }

    /// <summary>
    /// Copies cryptographic data from one instance to another
    /// </summary>
    /// <param name="to">Destination instance</param>
    /// <param name="from">Source instance</param>
    public static void ApplyCryptData(ICrypt to, ICrypt from)
    {
        to.InitializationVector = from.InitializationVector;
        to.Passphrase = from.Passphrase;
        to.Salt = from.Salt;
    }

    /// <summary>
    ///     Used for common apps settings
    ///     Fast
    ///     Rijndael was code name, actually is calling as Advanced Encryption Standard(AES)
    ///     was in 2001 approved by NIST, in 2002 was started to use as federal standard USA
    /// </summary>
    public class RijndaelBytes : ICryptBytes, ICrypt
    {
        /// <summary>
        /// Singleton instance of RijndaelBytes
        /// </summary>
        public static RijndaelBytes Instance = null!;

        static RijndaelBytes()
        {
            Instance = new RijndaelBytes();
        }

        /// <summary>
        /// Salt value for encryption
        /// </summary>
        public List<byte> Salt { get; set; } = null!;

        /// <summary>
        /// Initialization vector for encryption
        /// </summary>
        public List<byte> InitializationVector { get; set; } = null!;

        /// <summary>
        /// Passphrase for encryption
        /// </summary>
        public string Passphrase { get; set; } = null!;

        /// <summary>
        /// Decrypts the specified data using Rijndael algorithm
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <returns>Decrypted data</returns>
        public List<byte> Decrypt(List<byte> data)
        {
            return CryptHelper2.DecryptRijndael(data, Instance.Passphrase, Instance.Salt, Instance.InitializationVector);
        }

        /// <summary>
        /// Encrypts the specified data using Rijndael algorithm
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted data</returns>
        public List<byte> Encrypt(List<byte> data)
        {
            return CryptHelper2.EncryptRijndael(data, Instance.Passphrase, Instance.Salt, Instance.InitializationVector);
        }
    }

    /// <summary>
    /// Rijndael string encryption class
    /// </summary>
    public class Rijndael : ICryptString
    {
        /// <summary>
        /// Rijndael bytes encryption instance
        /// </summary>
        public RijndaelBytes RijndaelBytes = new();

        /// <summary>
        /// Decrypts the specified text
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <returns>Decrypted text</returns>
        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(RijndaelBytes.Decrypt(BTS2.ConvertFromUtf8ToBytes(text)));
        }

        /// <summary>
        /// Encrypts the specified text
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>Encrypted text</returns>
        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(RijndaelBytes.Encrypt(BTS2.ConvertFromUtf8ToBytes(text)));
        }
    }

    /// <summary>
    ///     DES use length of key 56 bit which make it vunverable to hard attacks
    ///     Very slow, AES/Rijandel is too much better
    /// </summary>
    public class TripleDES : ICryptString
    {
        private List<byte> initializationVector = null!;
        private string passphrase = null!;
        private List<byte> salt = null!;

        /// <summary>
        /// Salt value for encryption
        /// </summary>
        public List<byte> Salt
        {
            set => salt = value;
        }

        /// <summary>
        /// Initialization vector for encryption
        /// </summary>
        public List<byte> InitializationVector
        {
            set => initializationVector = value;
        }

        /// <summary>
        /// Passphrase for encryption
        /// </summary>
        public string Passphrase
        {
            set => passphrase = value;
        }

        /// <summary>
        /// Decrypts the specified text
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <returns>Decrypted text</returns>
        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text), passphrase, salt,
                initializationVector));
        }

        /// <summary>
        /// Encrypts the specified text
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>Encrypted text</returns>
        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.EncryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text), passphrase, salt,
                initializationVector));
        }
    }

    /// <summary>
    ///     Designed by Ronald R. Rivest in 1987 which designed another: RC4, RC5, RC6
    ///     In 1996 was source code published, the same as in RC4
    ///     then use is not recomended
    /// </summary>
    public class RC2 : ICrypt
    {
        /// <summary>
        /// Salt value for encryption
        /// </summary>
        public List<byte> Salt { get; set; } = null!;

        /// <summary>
        /// Initialization vector for encryption
        /// </summary>
        public List<byte> InitializationVector { get; set; } = null!;

        /// <summary>
        /// Passphrase for encryption
        /// </summary>
        public string Passphrase { get; set; } = null!;

        /// <summary>
        /// Decrypts the specified text
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <returns>Decrypted text</returns>
        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptRC2(BTS2.ConvertFromUtf8ToBytes(text), Passphrase, Salt, InitializationVector));
        }

        /// <summary>
        /// Encrypts the specified text
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>Encrypted text</returns>
        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.EncryptRC2(BTS2.ConvertFromUtf8ToBytes(text), Passphrase, Salt, InitializationVector));
        }
    }

    /// <summary>
    ///     Not working great
    ///     Must convert to bytes and transfer in bytes, also through network
    /// </summary>
    public class RijndaelString : ICryptString
    {
        /// <summary>
        /// Singleton instance of RijndaelString
        /// </summary>
        public static RijndaelString Instance = new();
        private readonly Rijndael rijndael = new();

        /// <summary>
        /// Encrypts the specified text
        /// </summary>
        /// <param name="text">Text to encrypt</param>
        /// <returns>Encrypted text</returns>
        public string Encrypt(string text)
        {
            return rijndael.Encrypt(text);
        }

        /// <summary>
        /// Decrypts the specified text
        /// </summary>
        /// <param name="text">Text to decrypt</param>
        /// <returns>Decrypted text</returns>
        public string Decrypt(string text)
        {
            return rijndael.Decrypt(text);
        }
    }
}