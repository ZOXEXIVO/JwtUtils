namespace JwtUtils.Utils.Strings;

public static class Base64Utils
{
    /// <summary>
    /// Make string representable for web (as cookie / header value)
    /// </summary>
    /// <param name="buffer"></param>
    /// <returns></returns>
    public static Span<char> FixForWeb(this Span<char> buffer)
    {
        int endIdx = buffer.Length - 1;

        while (buffer[endIdx] == '=' && endIdx > 0)
        {
            endIdx--;
        }

        for (int i = 0; i <= endIdx; i++)
        {
            ref var item = ref buffer[i];

            switch (item)
            {
                case '+':
                    item = '-';
                    break;
                case '/':
                    item = '_';
                    break;
            }
        }

        return buffer.Slice(0, endIdx + 1);
    }
    
    public static Span<char> UnfixForWeb(this Span<char> buffer, int bufferLength)
    {
        for (int i = 0; i < bufferLength; i++)
        {
            ref var item = ref buffer[i];

            switch (item)
            {
                case '-':
                    item = '+';
                    break;
                case '_':
                    item = '/';
                    break;
            }
        }
        
        switch (bufferLength % 4)
        {
            case 2:
            {
                buffer[bufferLength] = '=';
                buffer[bufferLength+1] = '=';

                return buffer.Slice(0, bufferLength + 2);
            }
            case 3:
            {
                buffer[bufferLength] = '=';

                return buffer.Slice(0, bufferLength + 1);
            }
        }

        return buffer.Slice(bufferLength);
    }
}