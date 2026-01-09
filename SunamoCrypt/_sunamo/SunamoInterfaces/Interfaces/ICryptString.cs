// variables names: ok
namespace SunamoCrypt._sunamo.SunamoInterfaces.Interfaces;

internal interface ICryptString
{
    string Decrypt(string text);
    string Encrypt(string text);
}