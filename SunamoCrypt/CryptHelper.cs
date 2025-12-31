namespace SunamoCrypt;

public class CryptHelper : ICryptHelper
{
    private readonly ICryptBytes _crypt;

    public CryptHelper(Provider provider, List<byte> salt, List<byte> initializationVector, string passphrase)
    {
        switch (provider)
        {
            case Provider.DES:
                throw new Exception("Symetrick\u00E9 \u0161ifrov\u00E1n\u00ED DES nen\u00ED podporov\u00E1no.");
                break;
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

        _crypt.InitializationVector = initializationVector;
        _crypt.Passphrase = passphrase;
        _crypt.Salt = salt;
    }


    public List<byte> Decrypt(List<byte> data)
    {
        return _crypt.Decrypt(data);
    }

    public List<byte> Encrypt(List<byte> data)
    {
        return _crypt.Encrypt(data);
    }

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
        public static RijndaelBytes Instance;

        static RijndaelBytes()
        {
            Instance = new RijndaelBytes();
            //_.RijndaelBytesEncrypt = Instance.Encrypt;
            //_.RijndaelBytesDecrypt = Instance.Decrypt;
        }

        public List<byte> Salt { get; set; }

        public List<byte> InitializationVector { get; set; }

        public string Passphrase { get; set; }

        public List<byte> Decrypt(List<byte> data)
        {
            return CryptHelper2.DecryptRijndael(data, Instance.Passphrase, Instance.Salt, Instance.InitializationVector);
        }

        public List<byte> Encrypt(List<byte> data)
        {
            return CryptHelper2.EncryptRijndael(data, Instance.Passphrase, Instance.Salt, Instance.InitializationVector);
        }
    }

    public class Rijndael : ICryptString
    {
        public RijndaelBytes rijndaelBytes = new();

        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(rijndaelBytes.Decrypt(BTS2.ConvertFromUtf8ToBytes(text)));
        }

        public string Encrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(rijndaelBytes.Encrypt(BTS2.ConvertFromUtf8ToBytes(text)));
        }
    }

    /// <summary>
    ///     DES use length of key 56 bit which make it vunverable to hard attacks
    ///     Very slow, AES/Rijandel is too much better
    /// </summary>
    public class TripleDES : ICryptString
    {
        private List<byte> initializationVector;
        private string passphrase;
        private List<byte> salt;

        public List<byte> Salt
        {
            set => salt = value;
        }

        public List<byte> InitializationVector
        {
            set => initializationVector = value;
        }

        public string Passphrase
        {
            set => passphrase = value;
        }

        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(text), passphrase, salt,
                initializationVector));
        }


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
        public List<byte> Salt { get; set; }

        public List<byte> InitializationVector { get; set; }

        public string Passphrase { get; set; }

        public string Decrypt(string text)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptRC2(BTS2.ConvertFromUtf8ToBytes(text), Passphrase, Salt, InitializationVector));
        }

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
        public static RijndaelString Instance = new();
        private readonly Rijndael rijndael = new();

        public string Encrypt(string text)
        {
            return rijndael.Encrypt(text);
        }

        public string Decrypt(string text)
        {
            return rijndael.Decrypt(text);
        }
    }
}