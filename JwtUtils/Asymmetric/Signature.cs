using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using JwtUtils.Asymmetric.Algorithms;
using JwtUtils.Exceptions;
using JwtUtils.Utils.Strings;

namespace JwtUtils.Asymmetric;

internal class AsymmetricSignature
{
    public static (IMemoryOwner<char> Memory, int Bytes) FromPrivatePem(ReadOnlySpan<char> payload, string privatePemKey, string algorithm)
    {
        var maxBytesCount = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] byteBuffer = null;

        try
        {
            byteBuffer = ArrayPool<byte>.Shared.Rent(maxBytesCount);

            using var rsaAlgorithm = PooledRsa.GetPrivateRsa(privatePemKey);

            Span<byte> hashBuffer = stackalloc byte[rsaAlgorithm.PooledObject.KeySize];

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, byteBuffer);

            var actualBuffer = byteBuffer.AsSpan().Slice(0, bytesRetrieved);

            if (!rsaAlgorithm.PooledObject.TrySignData(actualBuffer, hashBuffer,  GetAlgorithm(), RSASignaturePadding.Pkcs1, out var hashBytesWritten))
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
    
    public static bool VerifySignature(ReadOnlySpan<char> payload, ReadOnlySpan<char> signature, string publicPemKey, string algorithm)
    {
        char[] signatureBuffer = null;
        byte[] payloadBuffer = null;

        try
        {
            signatureBuffer = ArrayPool<char>.Shared.Rent(signature.Length + 2);

            signature.CopyTo(signatureBuffer);

            var decodedSignature = signatureBuffer.AsSpan().UnfixForWeb(signature.Length);
            var decodedSignatureLength = Encoding.UTF8.GetMaxByteCount(decodedSignature.Length);
            
            Span<byte> decodedSignatureBuffer = stackalloc byte[decodedSignatureLength];
            var decodedSignatureBytesRetrieved =  Encoding.UTF8.GetBytes(decodedSignature, decodedSignatureBuffer);

            var decodedSignatureSpan = decodedSignatureBuffer.Slice(0, decodedSignatureBytesRetrieved);
            
            using var rsaAlgorithm = PooledRsa.GetPublicRsa(publicPemKey);

            var payloadBytesLength = Encoding.UTF8.GetMaxByteCount(payload.Length);
            
            payloadBuffer = ArrayPool<byte>.Shared.Rent(payloadBytesLength);

            var bytesRetrieved = Encoding.UTF8.GetBytes(payload, payloadBuffer);

            var actualPayloadBuffer = payloadBuffer.AsSpan().Slice(0, bytesRetrieved);

            return rsaAlgorithm.PooledObject.VerifyHash(actualPayloadBuffer, decodedSignatureSpan, GetAlgorithm(),
                RSASignaturePadding.Pkcs1);
        }
        finally
        {
            if (signatureBuffer != null)
            {
                ArrayPool<char>.Shared.Return(signatureBuffer);
            }
            
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