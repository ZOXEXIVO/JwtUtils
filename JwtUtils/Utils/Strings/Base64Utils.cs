using System.Buffers;
using System.Buffers.Text;
using System.Text;
using JwtUtils.Exceptions;

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

        while ((buffer[endIdx] == '=' || buffer[endIdx] == 0)  && endIdx > 0)
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

    public static string ConvertToFixedBase64(Span<byte> buffer)
    {
        byte[] bytesToBase64Buffer = null;
        char[] charsArray = null;
        
        try
        {
            bytesToBase64Buffer = ArrayPool<byte>.Shared.Rent(Base64.GetMaxEncodedToUtf8Length(buffer.Length));

            if (Base64.EncodeToUtf8(buffer, bytesToBase64Buffer, out _, out var bytesWritten) !=
                OperationStatus.Done)
            {
                throw new JwtUtilsException("Base64 encoding failed");
            }

            var actualBytesBuffer = bytesToBase64Buffer.AsSpan().Slice(0, bytesWritten);
            
            var base64CharsCount = Encoding.UTF8.GetMaxByteCount(bytesWritten);

            charsArray = ArrayPool<char>.Shared.Rent(base64CharsCount + 2);

            var actualCharsCount = Encoding.UTF8.GetChars(actualBytesBuffer, charsArray);

            return new string( charsArray.AsSpan(0, actualCharsCount).FixForWeb());
        }
        finally
        {
            if (bytesToBase64Buffer != null)
            {
                ArrayPool<byte>.Shared.Return(bytesToBase64Buffer);
            }
            
            if (charsArray != null)
            {
                ArrayPool<char>.Shared.Return(charsArray);
            }
        }
    }
}