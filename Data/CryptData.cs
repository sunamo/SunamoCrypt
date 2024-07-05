namespace SunamoCrypt.Data;

public class CryptData : ICrypt
{
    public List<byte> s { get; set; }
    public List<byte> iv { get; set; }
    public string pp { get; set; }
}
