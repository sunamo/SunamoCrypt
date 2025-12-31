namespace SunamoCrypt._sunamo.SunamoInterfaces.Interfaces;

internal interface ICryptBytes : ICrypt
{
    List<byte> Decrypt(List<byte> data);
    List<byte> Encrypt(List<byte> data);
}