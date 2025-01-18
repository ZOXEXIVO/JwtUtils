using System.Buffers;
using System.Buffers.Text;
using System.Text;
using JwtUtils.Exceptions;
using JwtUtils.Symmetric.Algorithms;
using JwtUtils.Utils;

namespace JwtUtils.Symmetric;

internal static class SymmetricSignature
{
    public static (IMemoryOwner<char> Memory, int Bytes) Create(ReadOnlySpan<char> payload, string tokenSecret, string algorithm)
    {
        var maxBytesCount = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] byteBuffer = null;

        try
        {
            byteBuffer = ArrayPool<byte>.Shared.Rent(maxBytesCount);

            using var hashAlgorithm = PooledHmac.Get(algorithm, tokenSecret);

            Span<byte> hashBuffer = stackalloc byte[hashAlgorithm.PooledObject.HashSize];

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, byteBuffer);

            if (!hashAlgorithm.PooledObject.TryComputeHash(byteBuffer.AsSpan()[..bytesRetrieved], hashBuffer, out var bytesWritten))
            {
                throw new JwtUtilsException($"Compute hash with algorithm {algorithm} failed");
            }

            var actualHashData = hashBuffer[..bytesWritten];

            var maxEncoded = Base64.GetMaxEncodedToUtf8Length(actualHashData.Length);

            Span<byte> resultBuffer = stackalloc byte[maxEncoded];

            actualHashData.CopyTo(resultBuffer);

            return Base64Utils.ConvertToFixedBase64(hashBuffer[..bytesWritten]);
        }
        finally
        {
            if (byteBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(byteBuffer);
            }
        }
    }
}