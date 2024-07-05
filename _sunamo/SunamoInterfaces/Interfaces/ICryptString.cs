namespace SunamoCrypt._sunamo.SunamoInterfaces.Interfaces;


internal interface ICryptString
{
    string Decrypt(string v);
    string Encrypt(string v);
}