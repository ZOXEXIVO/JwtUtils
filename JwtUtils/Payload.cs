﻿using System.Buffers;
using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using JwtUtils.Exceptions;
using JwtUtils.Utils;

namespace JwtUtils;

internal class Payload
{
    public static T Read<T>(ReadOnlySpan<char> token)
    {
        var payload = ExtractPayload(token);
        var decodedPayload = PrepareForDecoding(payload);
        using (decodedPayload.PayloadMemory)
        {
            var actualPayloadBuffer = decodedPayload.PayloadMemory.Memory.Span[..decodedPayload.ActualLength];

            return JsonSerializer.Deserialize<T>(actualPayloadBuffer);
        }
    }

    private static ReadOnlySpan<char> ExtractPayload(ReadOnlySpan<char> token)
    {
        var firstIndex = token.IndexOf('.');
        var lastIndex = token.LastIndexOf('.');

        if (firstIndex == -1 || lastIndex == -1)
        {
            throw new JwtUtilsException("JWT is not well-formed");
        }
        
        if (firstIndex == lastIndex)
        {
            throw new JwtUtilsException("JWT is not well-formed");
        }
        
        return token.Slice(firstIndex + 1, lastIndex - firstIndex - 1);
    }

    private static (IMemoryOwner<char> PayloadMemory, int ActualLength) PrepareForDecoding(ReadOnlySpan<char> payload)
    {
        return Base64Utils.DecodeFixedBase64(payload);
    }

    public static (IMemoryOwner<char> PayloadMemory, int ActualLength) Create(ReadOnlySpan<char> payload)
    {
        int maxBytes = Encoding.UTF8.GetMaxByteCount(payload.Length);

        byte[] payloadBuffer = null;
        byte[] bytesToBase64Buffer = null;
        try
        {
            payloadBuffer = ArrayPool<byte>.Shared.Rent(maxBytes);

            var bytesCount = Encoding.UTF8.GetBytes(payload, payloadBuffer);

            var bytesPayload = payloadBuffer.AsSpan()[..bytesCount];

            bytesToBase64Buffer = ArrayPool<byte>.Shared.Rent(Base64.GetMaxEncodedToUtf8Length(bytesCount));

            if (Base64.EncodeToUtf8(bytesPayload, bytesToBase64Buffer, out _, out var bytesWritten) !=
                OperationStatus.Done)
            {
                throw new JwtUtilsException("Base64 encoding failed");
            }

            var actualBytesBuffer = bytesToBase64Buffer.AsSpan()[..bytesWritten];

            var base64CharsCount = Encoding.UTF8.GetMaxByteCount(bytesWritten);

            var base64Data = MemoryPool<char>.Shared.Rent(base64CharsCount + 2);

            var actualCharsCount = Encoding.UTF8.GetChars(actualBytesBuffer, base64Data.Memory.Span);

            return (base64Data, actualCharsCount);
        }
        finally
        {
            if (payloadBuffer != null)
            {
                ArrayPool<byte>.Shared.Return(payloadBuffer);
            }
            
            if (bytesToBase64Buffer != null)
            {
                ArrayPool<byte>.Shared.Return(bytesToBase64Buffer);
            }
        }
    }
}