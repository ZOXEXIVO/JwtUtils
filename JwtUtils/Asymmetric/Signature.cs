using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Exceptions;
using JwtUtils.Utils;

namespace JwtUtils.Asymmetric;

internal class AsymmetricSignature
{
    public static (IMemoryOwner<char> Memory, int Bytes) FromRSA(ReadOnlySpan<char> payload, RSA rsaAlgorithm, string algorithm)
    {
        var maxBytesCount = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] byteBuffer = null;

        try
        {
            byteBuffer = ArrayPool<byte>.Shared.Rent(maxBytesCount);

            Span<byte> hashBuffer = stackalloc byte[rsaAlgorithm.KeySize];

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, byteBuffer);

            var actualBuffer = byteBuffer.AsSpan().Slice(0, bytesRetrieved);

            if (!rsaAlgorithm.TrySignData(actualBuffer, hashBuffer, GetAlgorithm(algorithm), RSASignaturePadding.Pkcs1, out var hashBytesWritten))
            {
                throw new JwtUtilsException($"Compute hash with algorithm {algorithm} failed");
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
        
        HashAlgorithmName GetAlgorithm(string algorithm)
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

    public static bool ValidateSignature(ReadOnlySpan<char> payload, ReadOnlySpan<char> signature, string publicPemKey, string algorithm)
    {
        byte[] payloadBuffer = null;

        try
        {
            var decodedSignature = Base64Utils.ConvertFromFixedBase64(signature);
            using (decodedSignature.Memory)
            {
                using var rsaAlgorithm = Algorithms.PooledRsa.GetPublicRsa(publicPemKey);

                var payloadBytesLength = Encoding.UTF8.GetMaxByteCount(payload.Length);
            
                payloadBuffer = ArrayPool<byte>.Shared.Rent(payloadBytesLength);

                var actualPayloadBuffer = payloadBuffer.AsSpan().Slice(0, Encoding.UTF8.GetBytes(payload, payloadBuffer));

                var decodedSignatureBytes = decodedSignature.Memory.Memory.Span.Slice(0, decodedSignature.Bytes);
                
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