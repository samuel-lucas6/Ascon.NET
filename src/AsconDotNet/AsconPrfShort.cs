using System.Buffers.Binary;
using System.Security.Cryptography;

namespace AsconDotNet;

public static class AsconPrfShort
{
    public const int OutputSize = 16;
    public const int InputSize = 16;
    public const int KeySize = 16;
    private static ulong x0, x1, x2, x3, x4;

    public static void DeriveKey(Span<byte> output, ReadOnlySpan<byte> input, ReadOnlySpan<byte> key)
    {
        if (output.Length is > OutputSize or 0) { throw new ArgumentOutOfRangeException(nameof(output), output.Length, $"{nameof(output)} must be between 1 and {OutputSize} bytes long."); }
        if (input.Length > InputSize) { throw new ArgumentOutOfRangeException(nameof(input), input.Length, $"{nameof(input)} must be equal to or less than {InputSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> iv = stackalloc byte[8];
        iv.Clear();
        iv[0] = (byte)(key.Length * 8);
        iv[1] = (byte)(input.Length * 8);
        iv[2] = 64 + 12;
        iv[3] = (byte)(output.Length * 8);
        ulong k0 = BinaryPrimitives.ReadUInt64BigEndian(key[..8]);
        ulong k1 = BinaryPrimitives.ReadUInt64BigEndian(key[8..]);

        x0 = BinaryPrimitives.ReadUInt64BigEndian(iv);
        x1 = k0;
        x2 = k1;
        x3 = 0;
        x4 = 0;

        Span<byte> padding = stackalloc byte[InputSize];
        padding.Clear();
        input.CopyTo(padding);
        x3 = BinaryPrimitives.ReadUInt64BigEndian(padding[..8]);
        x4 = BinaryPrimitives.ReadUInt64BigEndian(padding[8..]);

        Permutation(rounds: 12);
        x3 ^= k0;
        x4 ^= k1;
        BinaryPrimitives.WriteUInt64BigEndian(padding[..8], x3);
        BinaryPrimitives.WriteUInt64BigEndian(padding[8..], x4);
        padding[..output.Length].CopyTo(output);
        x0 = 0; x1 = 0; x2 = 0; x3 = 0; x4 = 0;
        CryptographicOperations.ZeroMemory(padding);
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
