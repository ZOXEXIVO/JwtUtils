// ReSharper disable once CheckNamespace

using System.Buffers;
using JwtUtils.Asymmetric;
using JwtUtils.Asymmetric.Constants;
using JwtUtils.Extensions;
using JwtUtils.Utils.Strings;

// ReSharper disable once CheckNamespace
namespace JwtUtils;

public partial class JwtUtils
{
    public static partial class Asymmetric
    {
        public static partial class Token
        {
            // ReSharper disable once InconsistentNaming
            public static partial class RS256
            {
                private const string Algorithm = AsymmetricAlgorithms.Rs256;

                public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret)
                {
                    var jsonSerializedPayload = tokenPayload.ToJson();
                    return Token.Create(jsonSerializedPayload, tokenSecret, Algorithm);
                }
                
                public static string Create(string rawPayload, string tokenSecret)
                {
                    return Token.Create(rawPayload, tokenSecret, Algorithm);
                }
                
                public static bool Validate(ReadOnlySpan<char> token, string publicKey)
                {
                    return Token.Validate(token, publicKey, Algorithm);
                }
            }
            
            // ReSharper disable once InconsistentNaming
            public static partial class RS384
            {
                private const string Algorithm = AsymmetricAlgorithms.Rs384;

                public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret)
                {
                    var jsonSerializedPayload = tokenPayload.ToJson();
                    return Token.Create(jsonSerializedPayload, tokenSecret, Algorithm);
                }
                
                public static string Create(string rawPayload, string tokenSecret)
                {
                    return Token.Create(rawPayload, tokenSecret, Algorithm);
                }
                
                public static bool Validate(ReadOnlySpan<char> token, string publicKey)
                {
                    return Token.Validate(token, publicKey, Algorithm);
                }
            }
            
            // ReSharper disable once InconsistentNaming
            public static partial class RS512
            {
                private const string Algorithm = AsymmetricAlgorithms.Rs512;

                public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret)
                {
                    var jsonSerializedPayload = tokenPayload.ToJson();
                    return Token.Create(jsonSerializedPayload, tokenSecret, Algorithm);
                }
                
                public static string Create(string rawPayload, string tokenSecret)
                {
                    return Token.Create(rawPayload, tokenSecret, Algorithm);
                }
                
                public static bool Validate(ReadOnlySpan<char> token, string publicKey)
                {
                    return Token.Validate(token, publicKey, Algorithm);
                }
            }
            
            private static string Create(ReadOnlySpan<char> tokenPayload, string privatePemKey, string algorithm)
            {
                var header = Header.Create(algorithm);

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
            
            private static bool Validate(ReadOnlySpan<char> token, string publicPemKey, string algorithm)
            {
                var lastIndex = token.LastIndexOf('.');

                var payload = token.Slice(0, lastIndex);
                var signature = token.Slice(lastIndex + 1);
                
                return AsymmetricSignature.VerifySignature(payload, signature, publicPemKey, algorithm);
            }
        }
    }
}