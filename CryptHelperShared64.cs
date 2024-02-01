namespace SunamoCrypt;
using SunamoUnderscore;

public partial class CryptHelper
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
            _.RijndaelBytesEncrypt = Instance.Encrypt;
            _.RijndaelBytesDecrypt = Instance.Decrypt;
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
}
