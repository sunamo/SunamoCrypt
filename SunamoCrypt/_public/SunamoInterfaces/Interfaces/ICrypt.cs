// variables names: ok
namespace SunamoCrypt._public.SunamoInterfaces.Interfaces;


public interface ICrypt
{
    List<byte> Salt { get; set; }
    List<byte> InitializationVector { get; set; }
    string Passphrase { get; set; }
}