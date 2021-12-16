using System.Buffers;
using JwtUtils.Symmetric;
using JwtUtils.Utils.Strings;

// ReSharper disable once CheckNamespace
namespace JwtUtils;

public partial class JwtUtils
{
    public static partial class Symmetric
    {
        public static string Create(Dictionary<string, object> tokenPayload, string tokenSecret, string algorithm = "HS256")
        {
            var header = SymmetricHeader.Create(algorithm);

            var payloadData = Payload.Create(tokenPayload);
            
            using(payloadData.PayloadMemory)
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
                    
                    int tokenLength = signaturePayloadLength + 1 + signature.Length;

                    using (var resultMemoryBuffer = MemoryPool<char>.Shared.Rent(tokenLength))
                    {
                        var resultSpan = resultMemoryBuffer.Memory.Span;
                        
                        signaturePayload.CopyTo(resultSpan);
                        resultSpan = resultSpan.Slice(signaturePayload.Length);

                        resultSpan[0] = '.';
                        resultSpan = resultSpan.Slice(1);
                    
                        signature.CopyTo(resultSpan);

                        return new String(resultMemoryBuffer.Memory.Span.Slice(0, tokenLength));
                    }
                }
            }
        }
    }
}

