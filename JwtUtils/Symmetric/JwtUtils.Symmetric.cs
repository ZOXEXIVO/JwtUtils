using System.Buffers;
using JwtUtils.Extensions;
using JwtUtils.Symmetric;
using JwtUtils.Symmetric.Constants;
using JwtUtils.Utils;

// ReSharper disable once CheckNamespace
namespace JwtUtils;

// ReSharper disable once InconsistentNaming
public static partial class JWT
{
    // ReSharper disable once InconsistentNaming
    public static partial class HS256
    {
        private const string Algorithm = SymmetricAlgorithms.Hs256;

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret, string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(jsonSerializedPayload, tokenSecret, Algorithm, kid);
        }

        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, string tokenSecret, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(jsonSerializedPayload, tokenSecret, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, string tokenSecret, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(rawPayload, tokenSecret, Algorithm, kid);
        }

        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tokenSecret"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string tokenSecret)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.ValidateSymmetric(token, tokenSecret, Algorithm);
        }
    }

    // ReSharper disable once InconsistentNaming
    public static partial class HS384
    {
        private const string Algorithm = SymmetricAlgorithms.Hs384;

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret, string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(jsonSerializedPayload, tokenSecret, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, string tokenSecret, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(jsonSerializedPayload, tokenSecret, Algorithm, kid);
        }

        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, string tokenSecret, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(rawPayload, tokenSecret, Algorithm, kid);
        }
        
        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tokenSecret"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string tokenSecret)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.ValidateSymmetric(token, tokenSecret, Algorithm);
        }
    }

    // ReSharper disable once InconsistentNaming
    public static partial class HS512
    {
        private const string Algorithm = SymmetricAlgorithms.Hs512;

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret, string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(jsonSerializedPayload, tokenSecret, Algorithm, kid);
        }

        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, string tokenSecret, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(jsonSerializedPayload, tokenSecret, Algorithm, kid);
        }

        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="tokenSecret"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, string tokenSecret, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateSymmetric(rawPayload, tokenSecret, Algorithm, kid);
        }
        
        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tokenSecret"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string tokenSecret)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.ValidateSymmetric(token, tokenSecret, Algorithm);
        }
    }

    private static string CreateSymmetric(ReadOnlySpan<char> tokenPayload, string tokenSecret, string algorithm,
        string kid = null)
    {
        var header = Header.Create(algorithm, kid);

        var payloadData = Payload.Create(tokenPayload);

        using (payloadData.PayloadMemory)
        {
            var payload = payloadData.PayloadMemory.Memory.Span[..payloadData.ActualLength].FixForWeb();

            var signaturePayloadLength = header.Length + 1 + payload.Length;

            using (var headerPayloadBuffer = MemoryPool<char>.Shared.Rent(signaturePayloadLength))
            {
                var writeSpan = headerPayloadBuffer.Memory.Span;

                header.AsSpan().CopyTo(writeSpan);
                writeSpan = writeSpan[header.Length..];

                writeSpan[0] = '.';
                writeSpan = writeSpan[1..];

                payload.CopyTo(writeSpan);

                var signaturePayload = headerPayloadBuffer.Memory.Span[..signaturePayloadLength];

                var signature = SymmetricSignature.Create(signaturePayload, tokenSecret, algorithm);
                using (signature.Memory)
                {
                    int tokenLength = signaturePayloadLength + 1 + signature.Bytes;

                    using (var resultMemoryBuffer = MemoryPool<char>.Shared.Rent(tokenLength))
                    {
                        var resultSpan = resultMemoryBuffer.Memory.Span;

                        signaturePayload.CopyTo(resultSpan);
                        resultSpan = resultSpan[signaturePayload.Length..];

                        resultSpan[0] = '.';
                        resultSpan = resultSpan[1..];

                        signature.Memory.Memory.Span[..signature.Bytes].CopyTo(resultSpan);

                        return new string(resultMemoryBuffer.Memory.Span[..tokenLength]);
                    }
                }
            }
        }
    }

    private static bool ValidateSymmetric(ReadOnlySpan<char> token, string tokenSecret, string algorithm)
    {
        var lastIndex = token.LastIndexOf('.');

        var payload = token[..lastIndex];
        var signature = token[(lastIndex + 1)..];

        var computedSignature = SymmetricSignature.Create(payload, tokenSecret, algorithm);
        using (computedSignature.Memory)
        {
            var computedSignatureBytes = computedSignature.Memory.Memory.Span[..computedSignature.Bytes];
            return computedSignatureBytes.SequenceEqual(signature);
        }
    }
}