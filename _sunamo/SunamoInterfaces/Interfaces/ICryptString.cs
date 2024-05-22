namespace SunamoCrypt;


internal interface ICryptString
{
    string Decrypt(string v);
    string Encrypt(string v);
}