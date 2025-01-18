using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Asymmetric.Algorithms;
using JwtUtils.Exceptions;
using JwtUtils.Utils;

namespace JwtUtils.Asymmetric;

internal static class AsymmetricSignature
{
    public static (IMemoryOwner<char> Memory, int Bytes) FromRSA(ReadOnlySpan<char> payload, RSA rsaAlgorithm,
        string algorithm)
    {
        var maxBytesCount = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] byteBuffer = null;

        try
        {
            byteBuffer = ArrayPool<byte>.Shared.Rent(maxBytesCount);

            Span<byte> hashBuffer = stackalloc byte[rsaAlgorithm.KeySize];

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, byteBuffer);

            var actualBuffer = byteBuffer.AsSpan()[..bytesRetrieved];

            if (!rsaAlgorithm.TrySignData(actualBuffer, hashBuffer, GetAlgorithm(), RSASignaturePadding.Pkcs1,
                    out var hashBytesWritten))
            {
                throw new JwtUtilsException($"Compute hash with algorithm {algorithm} failed");
            }

            var actualHashData = hashBuffer[..hashBytesWritten];

            var maxEncoded = Base64.GetMaxEncodedToUtf8Length(actualHashData.Length);

            Span<byte> resultBuffer = stackalloc byte[maxEncoded];

            actualHashData.CopyTo(resultBuffer);

            return Base64Utils.ConvertToFixedBase64(hashBuffer[..hashBytesWritten]);
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
            return algorithm switch
            {
                "RS256" => HashAlgorithmName.SHA256,
                "RS384" => HashAlgorithmName.SHA384,
                "RS512" => HashAlgorithmName.SHA512,
                _ => throw new JwtUtilsException($"Unknown RSA algorithm: {algorithm}")
            };
        }
    }

    public static bool ValidateSignature(ReadOnlySpan<char> payload, ReadOnlySpan<char> signature, string publicPemKey,
        string algorithm)
    {
        byte[] payloadBuffer = null;

        try
        {
            var decodedSignature = Base64Utils.ConvertFromFixedBase64(signature);
            using (decodedSignature.Memory)
            {
                using var rsaAlgorithm = PooledRsa.GetPublicRsa(publicPemKey);

                var payloadBytesLength = Encoding.UTF8.GetMaxByteCount(payload.Length);

                payloadBuffer = ArrayPool<byte>.Shared.Rent(payloadBytesLength);

                var actualPayloadBuffer = payloadBuffer.AsSpan()[..Encoding.UTF8.GetBytes(payload, payloadBuffer)];

                var decodedSignatureBytes = decodedSignature.Memory.Memory.Span[..decodedSignature.Bytes];

                return rsaAlgorithm.PooledObject.VerifyData(actualPayloadBuffer, decodedSignatureBytes, GetAlgorithm(),
                    RSASignaturePadding.Pkcs1);
            }
        }
        finally
        {
            if (payloadBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(payloadBuffer);
            }
        }

        HashAlgorithmName GetAlgorithm()
        {
            return algorithm switch
            {
                "RS256" => HashAlgorithmName.SHA256,
                "RS384" => HashAlgorithmName.SHA384,
                "RS512" => HashAlgorithmName.SHA512,
                _ => throw new JwtUtilsException($"Unknown RSA algorithm: {algorithm}")
            };
        }
    }
}