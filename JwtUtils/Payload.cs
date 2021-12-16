using System.Buffers;
using System.Buffers.Text;
using System.Text;
using JwtUtils.Extensions;

namespace JwtUtils;

public class Payload
{
    public static (IMemoryOwner<char> PayloadMemory, int ActualLength) Create(Dictionary<string, object> payload)
    {
        var jsonPayload = payload.ToJson();
        
        int maxBytes = Encoding.UTF8.GetMaxByteCount(jsonPayload.Length);
            
        Span<byte> byteBuffer = stackalloc byte[maxBytes];
               
        var bytesCount = Encoding.UTF8.GetBytes(jsonPayload, byteBuffer);

        var bytesPayload = byteBuffer.Slice(0, bytesCount);

        byte[] bytesToBase64Buffer = null;
        try
        {
            bytesToBase64Buffer = ArrayPool<byte>.Shared.Rent(Base64.GetMaxEncodedToUtf8Length(bytesCount));

            if (Base64.EncodeToUtf8(bytesPayload, bytesToBase64Buffer, out _, out var bytesWritten) !=
                OperationStatus.Done)
            {
                throw new InvalidOperationException("Base64 encoding problem");
            }

            var actualBytesBuffer = bytesToBase64Buffer.AsSpan().Slice(0, bytesWritten);
            
            var base64CharsCount = Encoding.UTF8.GetMaxByteCount(bytesWritten);

            var base64Data = MemoryPool<char>.Shared.Rent(base64CharsCount + 2);

            var actualCharsCount = Encoding.UTF8.GetChars(actualBytesBuffer, base64Data.Memory.Span);
            
            return (base64Data, actualCharsCount);
        }
        finally
        {
            if (bytesToBase64Buffer != null)
            {
                ArrayPool<byte>.Shared.Return(bytesToBase64Buffer);
            }
        }
    }
}