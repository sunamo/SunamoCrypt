namespace SunamoCrypt;

/// <summary>
/// Represents the crypt helper type.
/// </summary>
public class CryptHelper : ICryptHelper
{
    private readonly ICryptBytes _crypt;

    /// <summary>
    /// Initializes a new instance of the crypt helper class.
    /// </summary>
    /// <param name="provider">The provider.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="initializationVector">The initialization vector.</param>
    /// <param name="passphrase">The passphrase.</param>
    public CryptHelper(Provider provider, List<byte> salt, List<byte> initializationVector, string passphrase)
    {
        switch (provider)
        {
            case Provider.DES:
                throw new Exception("DES symmetric encryption is not supported.");
            case Provider.RC2:
                break;
            case Provider.Rijndael:
                _crypt = new RijndaelBytes();
                break;
            case Provider.TripleDES:
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
    /// Decrypt.
    /// </summary>
    /// <param name="data">The data.</param>
    /// <returns>The decrypt result.</returns>
    public List<byte> Decrypt(List<byte> data)
    {
        return _crypt.Decrypt(data);
    }

    /// <summary>
    /// Encrypt.
    /// </summary>
    /// <param name="data">The data.</param>
    /// <returns>The encrypt result.</returns>
    public List<byte> Encrypt(List<byte> data)
    {
        return _crypt.Encrypt(data);
    }

    /// <summary>
    /// Apply crypt data.
    /// </summary>
    /// <param name="to">The to.</param>
    /// <param name="from">The from.</param>
    public static void ApplyCryptData(ICrypt to, ICrypt from)
    {
        to.InitializationVector = from.InitializationVector;
        to.Passphrase = from.Passphrase;
        to.Salt = from.Salt;
    }

    // Used for common apps settings
    // Fast
    // Rijndael was code name, actually is calling as Advanced Encryption Standard(AES)
    // was in 2001 approved by NIST, in 2002 was started to use as federal standard USA
    /// <summary>
    /// Represents the rijndael bytes type.
    /// </summary>
    public class RijndaelBytes : ICryptBytes, ICrypt
    {
        /// <summary>
        /// The instance.
        /// </summary>
        public static RijndaelBytes Instance = null!;

        static RijndaelBytes()
        {
            Instance = new RijndaelBytes();
        }

        /// <summary>
        /// Gets or sets the salt.
        /// </summary>
        public List<byte> Salt { get; set; } = null!;
        /// <summary>
        /// Gets or sets the initialization vector.
        /// </summary>
        public List<byte> InitializationVector { get; set; } = null!;
        /// <summary>
        /// Gets or sets the passphrase.
        /// </summary>
        public string Passphrase { get; set; } = null!;

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The decrypt result.</returns>
        public List<byte> Decrypt(List<byte> data)
        {
            return CryptHelper2.DecryptRijndael(data, Instance.Passphrase, Instance.Salt, Instance.InitializationVector);
        }

        /// <summary>
        /// Encrypt.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The encrypt result.</returns>
        public List<byte> Encrypt(List<byte> data)
        {
            return CryptHelper2.EncryptRijndael(data, Instance.Passphrase, Instance.Salt, Instance.InitializationVector);
        }
    }

    /// <summary>
    /// Represents the rijndael type.
    /// </summary>
    public class Rijndael : ICryptString
    {
        /// <summary>
        /// The rijndael bytes.
        /// </summary>
        public RijndaelBytes RijndaelBytes = new();

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="data">The data.</param>
        /// <returns>The decrypt result.</returns>
        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(RijndaelBytes.Decrypt(BTS2.ConvertFromUtf8ToBytes(text)));
        }

        /// <summary>
        /// Encrypt.
        /// </summary>
        /// <returns>The encrypt result.</returns>
        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(RijndaelBytes.Encrypt(BTS2.ConvertFromUtf8ToBytes(text)));
        }
    }

    // DES use length of key 56 bit which make it vulnerable to hard attacks
    // Very slow, AES/Rijandel is too much better
    /// <summary>
    /// Represents the triple DES type.
    /// </summary>
    public class TripleDES : ICryptString
    {
        private List<byte> initializationVector = null!;
        private string passphrase = null!;
        private List<byte> salt = null!;

        /// <summary>
        /// The salt.
        /// </summary>
        public List<byte> Salt
        {
            set => salt = value;
        }

        /// <summary>
        /// The initialization vector.
        /// </summary>
        public List<byte> InitializationVector
        {
            set => initializationVector = value;
        }

        /// <summary>
        /// The passphrase.
        /// </summary>
        public string Passphrase
        {
            set => passphrase = value;
        }

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <returns>The decrypt result.</returns>
        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text), passphrase, salt,
                initializationVector));
        }

        /// <summary>
        /// Encrypt.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <returns>The encrypt result.</returns>
        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.EncryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text), passphrase, salt,
                initializationVector));
        }
    }

    // Designed by Ronald R. Rivest in 1987 which designed another: RC4, RC5, RC6
    // In 1996 was source code published, the same as in RC4
    // then use is not recommended
    /// <summary>
    /// Represents the RC 2 type.
    /// </summary>
    public class RC2 : ICrypt
    {
        /// <summary>
        /// Gets or sets the salt.
        /// </summary>
        public List<byte> Salt { get; set; } = null!;
        /// <summary>
        /// Gets or sets the initialization vector.
        /// </summary>
        public List<byte> InitializationVector { get; set; } = null!;
        /// <summary>
        /// Gets or sets the passphrase.
        /// </summary>
        public string Passphrase { get; set; } = null!;

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <returns>The decrypt result.</returns>
        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptRC2(BTS2.ConvertFromUtf8ToBytes(text), Passphrase, Salt, InitializationVector));
        }

        /// <summary>
        /// Encrypt.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <returns>The encrypt result.</returns>
        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.EncryptRC2(BTS2.ConvertFromUtf8ToBytes(text), Passphrase, Salt, InitializationVector));
        }
    }

    // Not working great
    // Must convert to bytes and transfer in bytes, also through network
    /// <summary>
    /// Represents the rijndael string type.
    /// </summary>
    public class RijndaelString : ICryptString
    {
        /// <summary>
        /// The instance.
        /// </summary>
        public static RijndaelString Instance = new();
        private readonly Rijndael rijndael = new();

        /// <summary>
        /// Encrypt.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <returns>The encrypt result.</returns>
        public string Encrypt(string text)
        {
            return rijndael.Encrypt(text);
        }

        /// <summary>
        /// Decrypt.
        /// </summary>
        /// <param name="text">The text.</param>
        /// <returns>The decrypt result.</returns>
        public string Decrypt(string text)
        {
            return rijndael.Decrypt(text);
        }
    }
}
