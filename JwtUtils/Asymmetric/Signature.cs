using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Asymmetric.Algorithms;
using JwtUtils.Symmetric.Algorithms;

namespace JwtUtils.Asymmetric;

internal class AsymmetricSignature
{
    public static string Create(ReadOnlySpan<char> payload, string privatePemKey, RSA rsa, string algorithm)
    {
        var maxBytesCount = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] byteBuffer = null;

        try
        {
            byteBuffer = ArrayPool<byte>.Shared.Rent(maxBytesCount);

            using var rsaAlgorithm = rsa ?? PooledRsa.Get(algorithm, privatePemKey);

            Span<byte> hashBuffer = stackalloc byte[hashAlgorithm.PooledObject.HashSize];

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, byteBuffer);

            var actualBuffer = byteBuffer.AsSpan().Slice(0, bytesRetrieved);

            if (!hashAlgorithm.PooledObject.TryComputeHash(actualBuffer, hashBuffer, out int bytesWritten))
            {
                throw new InvalidOperationException();
            }

            var actualHashData = hashBuffer.Slice(0, bytesWritten);

            var maxEncoded = Base64.GetMaxEncodedToUtf8Length(actualHashData.Length);

            Span<byte> resultBuffer = stackalloc byte[maxEncoded];

            actualHashData.CopyTo(resultBuffer);

            return Convert.ToBase64String(hashBuffer.Slice(0, bytesWritten));
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