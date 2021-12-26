using System.Buffers;
using System.Buffers.Text;
using System.Text;
using JwtUtils.Exceptions;

namespace JwtUtils.Utils;

internal static class Base64Utils
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

        return buffer.Slice(0, bufferLength);
    }

    public static (IMemoryOwner<char> Memory, int Bytes) ConvertToFixedBase64(Span<byte> buffer)
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

            var fixedBase64String = charsArray.AsSpan(0, actualCharsCount).FixForWeb();

            var resultPooledString = MemoryPool<char>.Shared.Rent(fixedBase64String.Length);
            
            fixedBase64String.CopyTo(resultPooledString.Memory.Span);

            return (resultPooledString, fixedBase64String.Length);
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

    public static (IMemoryOwner<byte> Memory, int Bytes) ConvertFromFixedBase64(ReadOnlySpan<char> buffer)
    {
        char[] bufferCopy = null;
        byte[] byteBuffer = null;

        var bufferLengthWithExtraSpace = buffer.Length + 2; 
        
        try
        {
            bufferCopy = ArrayPool<char>.Shared.Rent(bufferLengthWithExtraSpace);
            
            buffer.CopyTo( bufferCopy);

            var unfixedBuffer = bufferCopy.AsSpan().UnfixForWeb(buffer.Length);
            
            byteBuffer = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(unfixedBuffer.Length));
           
            var encodedBytesLength = Encoding.UTF8.GetBytes(unfixedBuffer, byteBuffer);

            var actualBytesBuffer = byteBuffer.AsSpan().Slice(0, encodedBytesLength);
            
            var resultBufferLength = Base64.GetMaxDecodedFromUtf8Length(encodedBytesLength);
            
            var resultBuffer = MemoryPool<byte>.Shared.Rent(resultBufferLength);

            var encodingState = Base64.DecodeFromUtf8(actualBytesBuffer, resultBuffer.Memory.Span, out _,  out var base64DecodedBytes);
            if (encodingState != OperationStatus.Done)
            {
                throw new JwtUtilsException($"Base64 decoding failed: {encodingState}");
            }

            return (resultBuffer, base64DecodedBytes);
        }
        finally
        {
            if (bufferCopy != null)
            {
                ArrayPool<char>.Shared.Return(bufferCopy);
            }
            
            if (byteBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(byteBuffer);
            }
        }
    }
    
    public static (IMemoryOwner<char> Memory, int Bytes) DecodeFixedBase64(ReadOnlySpan<char> buffer)
    {
        char[] bufferCopy = null;
        byte[] byteBuffer = null;
        byte[] encodingByteBuffer = null;
        
        var bufferLengthWithExtraSpace = buffer.Length + 2; 
        
        try
        {
            bufferCopy = ArrayPool<char>.Shared.Rent(bufferLengthWithExtraSpace);
            
            buffer.CopyTo( bufferCopy);

            var unfixedBuffer = bufferCopy.AsSpan().Slice(0, bufferLengthWithExtraSpace).UnfixForWeb(buffer.Length);
            
            byteBuffer = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(unfixedBuffer.Length));
           
            var encodedBytesLength = Encoding.UTF8.GetBytes(unfixedBuffer, byteBuffer);

            var actualBytesBuffer = byteBuffer.AsSpan().Slice(0, encodedBytesLength);
            
            var resultBufferLength = Base64.GetMaxDecodedFromUtf8Length(encodedBytesLength);
            
            encodingByteBuffer = ArrayPool<byte>.Shared.Rent(resultBufferLength);

            var encodingState = Base64.DecodeFromUtf8(actualBytesBuffer, encodingByteBuffer, out var bytesWritten,  out var base64DecodedBytes);
            if (encodingState != OperationStatus.Done)
            {
                throw new JwtUtilsException($"Base64 decoding failed: {encodingState}");
            }

            var finalCharCount = Encoding.UTF8.GetMaxCharCount(base64DecodedBytes);
     
            var resultBuffer = MemoryPool<char>.Shared.Rent(finalCharCount);

            var utfEncodedLength = Encoding.UTF8.GetChars(encodingByteBuffer.AsSpan().Slice(0, base64DecodedBytes), resultBuffer.Memory.Span);
            
            return (resultBuffer, utfEncodedLength);
        }
        finally
        {
            if (bufferCopy != null)
            {
                ArrayPool<char>.Shared.Return(bufferCopy);
            }
            
            if (byteBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(byteBuffer);
            }
            
            if (encodingByteBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(encodingByteBuffer);
            }
        }
    }
}