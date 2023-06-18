using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AsconDotNet;

public static class AsconPrf
{
    public const int KeySize = 16;
    public const int TagSize = 16;
    private const int BlockSize = 32;
    private const int Rate = 16;
    private static ulong x0, x1, x2, x3, x4;

    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, bool macMode = false)
    {
        if (macMode && tag.Length > TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be between 1 and {TagSize} bytes long."); }
        if (tag.Length == 0) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be greater than 0 bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> iv = stackalloc byte[8];
        iv.Clear();
        iv[0] = (byte)(key.Length * 8);
        iv[1] = Rate * 8;
        iv[2] = 128 + 12;
        iv[7] = (byte)(macMode ? TagSize * 8 : 0);

        x0 = BinaryPrimitives.ReadUInt64BigEndian(iv);
        x1 = BinaryPrimitives.ReadUInt64BigEndian(key[..8]);
        x2 = BinaryPrimitives.ReadUInt64BigEndian(key[8..]);
        x3 = 0;
        x4 = 0;
        Permutation(rounds: 12);

        int i = 0;
        Span<byte> padding = stackalloc byte[BlockSize];
        while (i + BlockSize <= message.Length) {
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i, 8));
            x1 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 8, 8));
            x2 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 16, 8));
            x3 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 24, 8));
            Permutation(rounds: 12);
            i += BlockSize;
        }
        padding.Clear();
        message[i..].CopyTo(padding);
        padding[message.Length % BlockSize] = 0x80;
        x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[..8]);
        x1 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[8..16]);
        x2 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[16..24]);
        x3 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[24..]);
        x4 ^= 1;

        Permutation(rounds: 12);
        i = 0;
        while (i + Rate <= tag.Length) {
            BinaryPrimitives.WriteUInt64BigEndian(tag.Slice(i, 8), x0);
            BinaryPrimitives.WriteUInt64BigEndian(tag.Slice(i + 8, 8), x1);
            Permutation(rounds: 12);
            i += Rate;
        }
        if (tag.Length % Rate != 0) {
            BinaryPrimitives.WriteUInt64BigEndian(padding[..8], x0);
            BinaryPrimitives.WriteUInt64BigEndian(padding[8..16], x1);
            padding[..(tag.Length % Rate)].CopyTo(tag[i..]);
        }
        x0 = 0; x1 = 0; x2 = 0; x3 = 0; x4 = 0;
        CryptographicOperations.ZeroMemory(padding);
    }

    public static bool VerifyTag(ReadOnlySpan<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key, bool macMode = false)
    {
        Span<byte> computedTag = stackalloc byte[tag.Length];
        ComputeTag(computedTag, message, key, macMode);
        bool valid = CryptographicOperations.FixedTimeEquals(tag, computedTag);
        CryptographicOperations.ZeroMemory(computedTag);
        return valid;
    }

    private static void Permutation(int rounds)
    {
        ulong t0, t1, t2, t3, t4;
        for (ulong i = (ulong)(12 - rounds); i < 12; i++) {
            x2 ^= ((0xf - i) << 4) | i;

            x0 ^= x4; x4 ^= x3; x2 ^= x1;
            t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4;
            t0 =~ t0; t1 =~ t1; t2 =~ t2; t3 =~ t3; t4 =~ t4;
            t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
            x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
            x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 =~ x2;

            x0 ^= ulong.RotateRight(x0, 19) ^ ulong.RotateRight(x0, 28);
            x1 ^= ulong.RotateRight(x1, 61) ^ ulong.RotateRight(x1, 39);
            x2 ^= ulong.RotateRight(x2, 1) ^ ulong.RotateRight(x2, 6);
            x3 ^= ulong.RotateRight(x3, 10) ^ ulong.RotateRight(x3, 17);
            x4 ^= ulong.RotateRight(x4, 7) ^ ulong.RotateRight(x4, 41);
        }
    }
}
