namespace SunamoCrypt;

/// <summary>
/// Represents the BTS 2 type.
/// </summary>
public class BTS2
{
    /// <summary>
    /// Convert from utf 8 to bytes.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns>The convert from utf 8 to bytes result.</returns>
    public static List<byte> ConvertFromUtf8ToBytes(string text)
    {
        return Encoding.UTF8.GetBytes(text).ToList();
    }

    /// <summary>
    /// Convert from bytes to utf 8.
    /// </summary>
    /// <param name="bytes">The bytes.</param>
    /// <returns>The convert from bytes to utf 8 result.</returns>
    public static string ConvertFromBytesToUtf8(List<byte> bytes)
    {
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    /// <summary>
    /// Clear endings bytes.
    /// </summary>
    /// <param name="bytes">The bytes.</param>
    /// <returns>The clear endings bytes result.</returns>
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