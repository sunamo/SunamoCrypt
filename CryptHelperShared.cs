namespace SunamoCrypt;

public partial class CryptHelper : ICryptHelper
{
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
}
