using System.Buffers;
using JwtUtils.Extensions;
using JwtUtils.Symmetric;
using JwtUtils.Symmetric.Constants;
using JwtUtils.Utils.Strings;

// ReSharper disable once CheckNamespace
namespace JwtUtils;

public partial class JwtUtils
{
    public static partial class Symmetric
    {
        public static partial class Token
        {
            // ReSharper disable once InconsistentNaming
            public static partial class HS256
            {
                private const string Algorithm = SymmetricAlgorithms.Hs256;

                public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret)
                {
                    var serializedPayload = tokenPayload.ToJson();
                    return Token.Create(serializedPayload, tokenSecret, Algorithm);
                }
                
                public static string Create(string rawPayload, string tokenSecret)
                {
                    return Token.Create(rawPayload, tokenSecret, Algorithm);
                }
                
                public static bool Validate(ReadOnlySpan<char> token, string tokenSecret)
                {
                    return Token.Validate(token, tokenSecret, Algorithm);
                }
            }

            // ReSharper disable once InconsistentNaming
            public static partial class HS384
            {
                private const string Algorithm = SymmetricAlgorithms.Hs384;
                
                public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret)
                {
                    var serializedPayload = tokenPayload.ToJson();
                    return Token.Create(serializedPayload, tokenSecret, Algorithm);
                }
                
                public static string Create(string rawPayload, string tokenSecret)
                {
                    return Token.Create(rawPayload, tokenSecret, Algorithm);
                }
                
                public static bool Validate(ReadOnlySpan<char> token, string tokenSecret)
                {
                    return Token.Validate(token, tokenSecret, Algorithm);
                }
            }

            // ReSharper disable once InconsistentNaming
            public static partial class HS512
            {
                private const string Algorithm = SymmetricAlgorithms.Hs512;
                
                public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret)
                {
                    var serializedPayload = tokenPayload.ToJson();
                    return Token.Create(serializedPayload, tokenSecret, Algorithm);
                }
                
                public static string Create(string rawPayload, string tokenSecret)
                {
                    return Token.Create(rawPayload, tokenSecret, Algorithm);
                }
                
                public static bool Validate(ReadOnlySpan<char> token, string tokenSecret)
                {
                    return Token.Validate(token, tokenSecret, Algorithm);
                }
            }
            
            private static string Create(ReadOnlySpan<char> tokenPayload, string tokenSecret, string algorithm)
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

                        var signature = SymmetricSignature.Create(signaturePayload, tokenSecret, algorithm);
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

            private static bool Validate(ReadOnlySpan<char> token, string tokenSecret, string algorithm)
            {
                var lastIndex = token.LastIndexOf('.');

                var payload = token.Slice(0, lastIndex);
                var signature = token.Slice(lastIndex + 1);
                
                var computedSignature = SymmetricSignature.Create(payload, tokenSecret, algorithm);
                using (computedSignature.Memory)
                {
                    var computedSignatureBytes = computedSignature.Memory.Memory.Span.Slice(0, computedSignature.Bytes);
                    return computedSignatureBytes.SequenceEqual(signature);
                }
            }
        }
    }
}