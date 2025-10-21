// EN: Variable names have been checked and replaced with self-descriptive names
// CZ: Názvy proměnných byly zkontrolovány a nahrazeny samopopisnými názvy
namespace SunamoCrypt.Data;

public class CryptData : ICrypt
{
    public List<byte> s { get; set; }
    public List<byte> iv { get; set; }
    public string pp { get; set; }
}
