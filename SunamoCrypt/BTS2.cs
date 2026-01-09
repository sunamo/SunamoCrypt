// variables names: ok
namespace SunamoCrypt;

/// <summary>
/// EN: Byte-Text-String conversion utilities
/// CZ: Utilita pro konverzi mezi bajty, textem a řetězci
/// </summary>
public class BTS2
{
    /// <summary>
    /// Converts UTF-8 string to bytes
    /// </summary>
    /// <param name="text">Text to convert</param>
    /// <returns>List of bytes</returns>
    public static List<byte> ConvertFromUtf8ToBytes(string text)
    {
        return Encoding.UTF8.GetBytes(text).ToList();
    }

    /// <summary>
    /// Converts bytes to UTF-8 string
    /// </summary>
    /// <param name="bytes">Bytes to convert</param>
    /// <returns>UTF-8 encoded string</returns>
    public static string ConvertFromBytesToUtf8(List<byte> bytes)
    {
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    /// <summary>
    /// Removes trailing zero bytes from the byte list
    /// </summary>
    /// <param name="bytes">Byte list to process</param>
    /// <returns>Byte list without trailing zeros</returns>
    public static List<byte> ClearEndingsBytes(List<byte> bytes)
    {
        var result = new List<byte>();
        var shouldAdd = false;
        for (var i = bytes.Count - 1; i >= 0; i--)
            if (!shouldAdd && bytes[i] != 0)
            {
                shouldAdd = true;
                result.Insert(0, bytes[i]);
            }
            else if (shouldAdd)
            {
                result.Insert(0, bytes[i]);
            }

        if (result.Count == 0)
        {
            for (var i = 0; i < bytes.Count; i++) bytes[i] = 0;
            return bytes;
        }

        return result;
    }
}