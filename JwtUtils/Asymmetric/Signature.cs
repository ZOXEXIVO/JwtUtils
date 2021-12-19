using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Asymmetric.Algorithms;
using JwtUtils.Exceptions;
using JwtUtils.Symmetric.Algorithms;
using JwtUtils.Utils.Strings;

namespace JwtUtils.Asymmetric;

internal class AsymmetricSignature
{
    public static string FromPem(ReadOnlySpan<char> payload, string privatePemKey, string algorithm)
    {
        var maxBytesCount = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] byteBuffer = null;

        try
        {
            byteBuffer = ArrayPool<byte>.Shared.Rent(maxBytesCount);

            using var rsaAlgorithm = PooledRsa.Get(privatePemKey);

            Span<byte> hashBuffer = stackalloc byte[rsaAlgorithm.PooledObject.KeySize];

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, byteBuffer);

            var actualBuffer = byteBuffer.AsSpan().Slice(0, bytesRetrieved);

            if (!rsaAlgorithm.PooledObject.TrySignData(actualBuffer, hashBuffer,  GetAlgorithm(), RSASignaturePadding.Pkcs1, out var hashBytesWritten))
            {
                throw new InvalidOperationException();
            }

            var actualHashData = hashBuffer.Slice(0, hashBytesWritten);

            var maxEncoded = Base64.GetMaxEncodedToUtf8Length(actualHashData.Length);

            Span<byte> resultBuffer = stackalloc byte[maxEncoded];

            actualHashData.CopyTo(resultBuffer);

            return Base64Utils.ConvertToFixedBase64(hashBuffer.Slice(0, hashBytesWritten));
        }
        finally
        {
            if (byteBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(byteBuffer);
            }
        }

        HashAlgorithmName GetAlgorithm()
        {
            switch (algorithm)
            {
                case "RS256":
                    return HashAlgorithmName.SHA256;
                case "RS384":
                    return HashAlgorithmName.SHA384;
                case "RS512":
                    return HashAlgorithmName.SHA512;
            }

            throw new JwtUtilsException($"Unknown RSA algorithm: {algorithm}");
        }
    }
}