namespace SunamoCrypt._sunamo.SunamoInterfaces.Interfaces;

internal interface ICryptHelper
{
    List<byte> Decrypt(List<byte> data);
    List<byte> Encrypt(List<byte> data);
}