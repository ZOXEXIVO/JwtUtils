// ReSharper disable once CheckNamespace

using System.Buffers;
using JwtUtils.Asymmetric;
using JwtUtils.Asymmetric.Constants;
using JwtUtils.Extensions;
using JwtUtils.Utils.Strings;

// ReSharper disable once CheckNamespace
namespace JwtUtils;

public static partial class AsymmetricToken
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
            return AsymmetricToken.Create(jsonSerializedPayload, privatePemKey, Algorithm, kid);
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
            return AsymmetricToken.Create(jsonSerializedPayload, tokenSecret, Algorithm, kid);
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
            if (privatePemKey == null) throw new ArgumentNullException(nameof(privatePemKey));
            return AsymmetricToken.Create(rawPayload, privatePemKey, Algorithm, kid);
        }

        /// <summary>
        /// Read token payload to Dictionary(string,object)
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static Dictionary<string, object> Read(ReadOnlySpan<char> token)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return PayloadExt.ReadPayload<Dictionary<string, object>>(token);
        }

        /// <summary>
        /// Read token payload to your custom type object with System.Text.Json
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static T Read<T>(ReadOnlySpan<char> token)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return PayloadExt.ReadPayload<T>(token);
        }

        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string publicKey)
        {
            return AsymmetricToken.ValidateSignature(token, publicKey, Algorithm);
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
            return AsymmetricToken.Create(jsonSerializedPayload, privatePemKey, Algorithm, kid);
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
            return AsymmetricToken.Create(jsonSerializedPayload, tokenSecret, Algorithm, kid);
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
            return AsymmetricToken.Create(rawPayload, privatePemKey, Algorithm, kid);
        }

        /// <summary>
        /// Read token payload to Dictionary(string,object)
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static Dictionary<string, object> Read(ReadOnlySpan<char> token)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return PayloadExt.ReadPayload<Dictionary<string, object>>(token);
        }

        /// <summary>
        /// Read token payload to your custom type object with System.Text.Json
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static T Read<T>(ReadOnlySpan<char> token)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return PayloadExt.ReadPayload<T>(token);
        }

        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string publicKey)
        {
            return AsymmetricToken.ValidateSignature(token, publicKey, Algorithm);
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
            return AsymmetricToken.Create(jsonSerializedPayload, privatePemKey, Algorithm, kid);
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
            return AsymmetricToken.Create(jsonSerializedPayload, tokenSecret, Algorithm, kid);
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
            return AsymmetricToken.Create(rawPayload, privatePemKey, Algorithm, kid);
        }

        /// <summary>
        /// Read token payload to Dictionary(string,object)
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static Dictionary<string, object> Read(ReadOnlySpan<char> token)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return PayloadExt.ReadPayload<Dictionary<string, object>>(token);
        }

        /// <summary>
        /// Read token payload to your custom type object with System.Text.Json
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static T Read<T>(ReadOnlySpan<char> token)
        {
            // ReSharper disable once ArrangeStaticMemberQualifier
            return PayloadExt.ReadPayload<T>(token);
        }

        /// <summary>
        /// Validate token signature
        /// </summary>
        /// <param name="token"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool ValidateSignature(ReadOnlySpan<char> token, string publicKey)
        {
            return AsymmetricToken.ValidateSignature(token, publicKey, Algorithm);
        }
    }

    private static string Create(ReadOnlySpan<char> tokenPayload, string privatePemKey, string algorithm,
        string kid)
    {
        var header = Header.Create(algorithm, kid);

        var payloadData = Payload.Create(tokenPayload);

        using (payloadData.PayloadMemory)
        {
            var payload = payloadData.PayloadMemory.Memory.Span.Slice(0, payloadData.ActualLength).FixForWeb();

            var signaturePayloadLength = header.Length + 1 + payload.Length;

            using (var headerPayloadBuffer = MemoryPool<char>.Shared.Rent(signaturePayloadLength))
            {
                var writeSpan = headerPayloadBuffer.Memory.Span;

                header.AsSpan().CopyTo(writeSpan);
                writeSpan = writeSpan.Slice(header.Length);

                writeSpan[0] = '.';
                writeSpan = writeSpan.Slice(1);

                payload.CopyTo(writeSpan);

                var signaturePayload = headerPayloadBuffer.Memory.Span.Slice(0, signaturePayloadLength);

                var signature = AsymmetricSignature.FromPrivatePem(signaturePayload, privatePemKey, algorithm);
                using (signature.Memory)
                {
                    int tokenLength = signaturePayloadLength + 1 + signature.Bytes;

                    using (var resultMemoryBuffer = MemoryPool<char>.Shared.Rent(tokenLength))
                    {
                        var resultSpan = resultMemoryBuffer.Memory.Span;

                        signaturePayload.CopyTo(resultSpan);
                        resultSpan = resultSpan.Slice(signaturePayload.Length);

                        resultSpan[0] = '.';
                        resultSpan = resultSpan.Slice(1);

                        signature.Memory.Memory.Span.Slice(0, signature.Bytes).CopyTo(resultSpan);

                        return new String(resultMemoryBuffer.Memory.Span.Slice(0, tokenLength));
                    }
                }
            }
        }
    }

    private static bool ValidateSignature(ReadOnlySpan<char> token, string publicPemKey, string algorithm)
    {
        var lastIndex = token.LastIndexOf('.');

        var payload = token.Slice(0, lastIndex);
        var signature = token.Slice(lastIndex + 1);

        return AsymmetricSignature.ValidateSignature(payload, signature, publicPemKey, algorithm);
    }
}