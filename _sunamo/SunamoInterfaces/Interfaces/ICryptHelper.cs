namespace SunamoCrypt;


internal interface ICryptHelper
{
    List<byte> Decrypt(List<byte> v);
    List<byte> Encrypt(List<byte> v);
}