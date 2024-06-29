namespace SunamoCrypt;


public interface ICrypt
{
    List<byte> s { set; get; }
    List<byte> iv { set; get; }
    string pp { set; get; }
}