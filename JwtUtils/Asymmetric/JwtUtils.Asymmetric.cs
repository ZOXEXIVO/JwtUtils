// ReSharper disable once CheckNamespace

using System.Buffers;
using System.Security.Cryptography;
using JwtUtils.Asymmetric;
using JwtUtils.Asymmetric.Algorithms;
using JwtUtils.Asymmetric.Constants;
using JwtUtils.Extensions;
using JwtUtils.Utils;

// ReSharper disable once CheckNamespace
namespace JwtUtils;

// ReSharper disable once InconsistentNaming
public static partial class JWT
{
    // ReSharper disable once InconsistentNaming
    public static partial class RS256
    {
        private const string Algorithm = AsymmetricAlgorithms.Rs256;

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, string privatePemKey,
            string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, privatePemKey, Algorithm, kid);
        }

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, RSA rsa,
            string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, rsa, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, string privatePemKey, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, privatePemKey, Algorithm, kid);
        }

        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, RSA rsa, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, rsa, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, string privatePemKey, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(rawPayload, privatePemKey, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, RSA rsa, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(rawPayload, rsa, Algorithm, kid);
        }
        
        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string publicKey)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.ValidateAsymmetric(token, publicKey, Algorithm);
        }
    }

    // ReSharper disable once InconsistentNaming
    public static partial class RS384
    {
        private const string Algorithm = AsymmetricAlgorithms.Rs384;

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, string privatePemKey,
            string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, privatePemKey, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, RSA rsa,
            string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, rsa, Algorithm, kid);
        }

        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, string privatePemKey, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, privatePemKey, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, RSA rsa, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, rsa, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, string privatePemKey, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(rawPayload, privatePemKey, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, RSA rsa, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(rawPayload, rsa, Algorithm, kid);
        }


        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string publicKey)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.ValidateAsymmetric(token, publicKey, Algorithm);
        }
    }

    // ReSharper disable once InconsistentNaming
    public static partial class RS512
    {
        private const string Algorithm = AsymmetricAlgorithms.Rs512;

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, string privatePemKey,
            string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, privatePemKey, Algorithm, kid);
        }

        /// <summary>
        /// Create token from Dictionary(string, object) payload
        /// </summary>
        /// <param name="tokenPayload"></param>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <returns></returns>
        public static string Create(Dictionary<string, object> tokenPayload, RSA rsa,
            string kid = null)
        {
            var jsonSerializedPayload = tokenPayload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, rsa, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, string privatePemKey, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, privatePemKey, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with typed object that will be serialized with System.Text.Json 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create<T>(T payload, RSA rsa, string kid = null)
        {
            var jsonSerializedPayload = payload.ToJson();
            
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(jsonSerializedPayload, rsa, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="privatePemKey"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, string privatePemKey, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(rawPayload, privatePemKey, Algorithm, kid);
        }
        
        /// <summary>
        /// Create token with string payload AS IS
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="kid"></param>
        /// <param name="rawPayload"></param>
        /// <typeparam name="T"></typeparam>
        /// <returns></returns>
        public static string Create(string rawPayload, RSA rsa, string kid = null)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.CreateAsymmetric(rawPayload, rsa, Algorithm, kid);
        }

        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string publicKey)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return JWT.ValidateAsymmetric(token, publicKey, Algorithm);
        }
    }

    private static string CreateAsymmetric(ReadOnlySpan<char> tokenPayload, RSA rsaAlgorithm, string algorithm,
        string kid)
    {
        var header = Header.Create(algorithm, kid);
        var payloadData = Payload.Create(tokenPayload);

        using (payloadData.PayloadMemory)
        {
            var payload = payloadData.PayloadMemory.Memory.Span[..payloadData.ActualLength].FixForWeb();

            var signaturePayloadLength = header.Length + 1 + payload.Length;

            Span<char> headerPayloadBuffer = stackalloc char[signaturePayloadLength];
            
            var writeSpan = headerPayloadBuffer;

            header.AsSpan().CopyTo(writeSpan);
            writeSpan = writeSpan[header.Length..];

            writeSpan[0] = '.';
            writeSpan = writeSpan[1..];

            payload.CopyTo(writeSpan);

            var signaturePayload = headerPayloadBuffer[..signaturePayloadLength];

            var signature = AsymmetricSignature.FromRSA(signaturePayload, rsaAlgorithm, algorithm);
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

    private static string CreateAsymmetric(ReadOnlySpan<char> tokenPayload, string privatePemKey, string algorithm,
        string kid)
    {
        using var rsaAlgorithm = PooledRsa.GetPrivateRsa(privatePemKey);
        return CreateAsymmetric(tokenPayload, rsaAlgorithm.PooledObject, algorithm, kid);
    }

    private static bool ValidateAsymmetric(ReadOnlySpan<char> token, string publicPemKey, string algorithm)
    {
        var lastIndex = token.LastIndexOf('.');

        var payload = token[..lastIndex];
        var signature = token[(lastIndex + 1)..];

        return AsymmetricSignature.ValidateSignature(payload, signature, publicPemKey, algorithm);
    }
}