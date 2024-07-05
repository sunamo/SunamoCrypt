namespace SunamoCrypt;

public class CryptHelper : ICryptHelper
{
    private ICryptBytes _crypt = null;

    public static void ApplyCryptData(ICrypt to, ICrypt from)
    {
        to.iv = from.iv;
        to.pp = from.pp;
        to.s = from.s;
    }

    static Type type = typeof(CryptHelper);

    public CryptHelper(Provider provider, List<byte> s, List<byte> iv, string pp)
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
                _crypt = new CryptHelper.RijndaelBytes();
                break;
            case Provider.TripleDES:
                //crypt = new CryptHelper.TripleDES();
                break;
            default:
                ThrowEx.NotImplementedCase(provider);
                break;
        }
        _crypt.iv = iv;
        _crypt.pp = pp;
        _crypt.s = s;
    }

    /// <summary>
    /// Used for common apps settings
    /// Fast
    /// Rijndael was code name, actually is calling as Advanced Encryption Standard(AES)
    /// was in 2001 approved by NIST, in 2002 was started to use as federal standard USA
    /// 
    /// </summary>
    public class RijndaelBytes : ICryptBytes, ICrypt
    {
        static RijndaelBytes()
        {
            Instance = new RijndaelBytes();
            //_.RijndaelBytesEncrypt = Instance.Encrypt;
            //_.RijndaelBytesDecrypt = Instance.Decrypt;
        }

        public static RijndaelBytes Instance = null;

        public List<byte> s
        {
            set; get;
        }

        public List<byte> iv
        {
            set; get;
        }

        public string pp
        {
            set; get;
        }

        public List<byte> Decrypt(List<byte> v)
        {
            return CryptHelper2.DecryptRijndael(v, Instance.pp, Instance.s, Instance.iv);
        }

        public List<byte> Encrypt(List<byte> v)
        {
            return CryptHelper2.EncryptRijndael(v, Instance.pp, Instance.s, Instance.iv);
        }
    }

    public class Rijndael : ICryptString
    {
        public RijndaelBytes rijndaelBytes = new RijndaelBytes();

        public string Decrypt(string v)
        {
            return BTS2.ConvertFromBytesToUtf8(rijndaelBytes.Decrypt(BTS2.ConvertFromUtf8ToBytes(v)));
        }

        public string Encrypt(string v)
        {
            return BTS2.ConvertFromBytesToUtf8(rijndaelBytes.Encrypt(BTS2.ConvertFromUtf8ToBytes(v)));
        }
    }

    /// <summary>
    /// DES use length of key 56 bit which make it vunverable to hard attacks
    /// Very slow, AES/Rijandel is too much better
    /// </summary>
    public class TripleDES : ICryptString
    {
        private List<byte> _s = null;
        private List<byte> _iv = null;
        private string _pp = null;

        public List<byte> s
        {
            set { _s = value; }
        }

        public List<byte> iv
        {
            set { _iv = value; }
        }

        public string pp
        {
            set { _pp = value; }
        }

        public string Decrypt(string v)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptTripleDES(BTS2.ConvertFromUtf8ToBytes(v), _pp, _s, _iv));
        }



        public string Encrypt(string v)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.EncryptTripleDES(BTS2.ConvertFromUtf8ToBytes(v), _pp, _s, _iv));
        }
    }

    /// <summary>
    /// Designed by Ronald R. Rivest in 1987 which designed another: RC4, RC5, RC6
    /// In 1996 was source code published, the same as in RC4
    /// then use is not recomended
    /// </summary>
    public class RC2 : ICrypt
    {


        public List<byte> s
        { set; get; }

        public List<byte> iv
        {
            set; get;
        }

        public string pp
        {
            set; get;
        }

        public string Decrypt(string v)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.DecryptRC2(BTS2.ConvertFromUtf8ToBytes(v), pp, s, iv));
        }

        public string Encrypt(string v)
        {
            return BTS2.ConvertFromBytesToUtf8(CryptHelper2.EncryptRC2(BTS2.ConvertFromUtf8ToBytes(v), pp, s, iv));
        }
    }

    /// <summary>
    /// Not working great
    /// Must convert to bytes and transfer in bytes, also through network
    /// </summary>
    public class RijndaelString : ICryptString
    {
        Rijndael rijndael = new Rijndael();

        public static RijndaelString Instance = new RijndaelString();

        public string Encrypt(string v)
        {
            return rijndael.Encrypt(v);
        }

        public string Decrypt(string v)
        {
            return rijndael.Decrypt(v);
        }
    }




    public List<byte> Decrypt(List<byte> v)
    {
        return _crypt.Decrypt(v);
    }

    public List<byte> Encrypt(List<byte> v)
    {
        return _crypt.Encrypt(v);
    }
}
