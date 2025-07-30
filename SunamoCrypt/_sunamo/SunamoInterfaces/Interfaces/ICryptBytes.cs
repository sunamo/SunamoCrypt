namespace SunamoCrypt._sunamo.SunamoInterfaces.Interfaces;


internal interface ICryptBytes : ICrypt
{
    List<byte> Decrypt(List<byte> v);
    List<byte> Encrypt(List<byte> v);
}