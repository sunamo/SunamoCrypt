namespace SunamoCrypt;

public class BTS2
{
    public static List<byte> ConvertFromUtf8ToBytes(string text)
    {
        return Encoding.UTF8.GetBytes(text).ToList();
    }

    public static string ConvertFromBytesToUtf8(List<byte> bytes)
    {
        //NH.RemoveEndingZeroPadding(bytes);
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    public static List<byte> ClearEndingsBytes(List<byte> bytes)
    {
        var result = new List<byte>();
        var shouldAdd = false;
        for (var i = bytes.Count - 1; i >= 0; i--)
            if (!shouldAdd && bytes[i] != 0)
            {
                shouldAdd = true;
                var currentByte = bytes[i];
                result.Insert(0, currentByte);
            }
            else if (shouldAdd)
            {
                var currentByte = bytes[i];
                result.Insert(0, currentByte);
            }

        if (result.Count == 0)
        {
            for (var i = 0; i < bytes.Count; i++) bytes[i] = 0;
            return bytes;
        }

        return result;
    }
}