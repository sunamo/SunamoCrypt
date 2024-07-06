namespace SunamoCrypt;


internal class BTS2
{
    
    public static List<byte> ConvertFromUtf8ToBytes(string vstup)
    {
        return Encoding.UTF8.GetBytes(vstup).ToList();
    }

    public static string ConvertFromBytesToUtf8(List<byte> bajty)
    {
        //NHSH.RemoveEndingZeroPadding(bajty);
        return Encoding.UTF8.GetString(bajty.ToArray());
    }

    public static List<byte> ClearEndingsBytes(List<byte> plainTextBytes)
    {
        List<byte> bytes = new List<byte>();
        bool pridavat = false;
        for (int i = plainTextBytes.Count - 1; i >= 0; i--)
        {
            if (!pridavat && plainTextBytes[i] != 0)
            {
                pridavat = true;
                byte pridat = plainTextBytes[i];
                bytes.Insert(0, pridat);
            }
            else if (pridavat)
            {
                byte pridat = plainTextBytes[i];
                bytes.Insert(0, pridat);
            }
        }
        if (bytes.Count == 0)
        {
            for (int i = 0; i < plainTextBytes.Count; i++)
            {
                plainTextBytes[i] = 0;
            }
            return plainTextBytes;
        }
        return bytes;
    }
}
