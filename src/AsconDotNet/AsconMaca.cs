using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace AsconDotNet;

public sealed class AsconMaca : IDisposable
{
    public const int KeySize = 16;
    public const int TagSize = 16;
    private const int BlockSize = 40;
    private const int Rate = 16;
    private static byte[] _buffer = new byte[BlockSize];
    private int _bytesBuffered;
    private static ulong x0, x1, x2, x3, x4;

    public AsconMaca(ReadOnlySpan<byte> key)
    {
        Initialize(key);
    }

    private static void Initialize(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        Span<byte> iv = stackalloc byte[8];
        iv.Clear();
        iv[0] = KeySize * 8;
        iv[1] = Rate * 8;
        iv[2] = 128 + 12;
        iv[3] = 12 - 8;
        iv[7] = TagSize * 8;

        x0 = BinaryPrimitives.ReadUInt64BigEndian(iv);
        x1 = BinaryPrimitives.ReadUInt64BigEndian(key[..8]);
        x2 = BinaryPrimitives.ReadUInt64BigEndian(key[8..]);
        x3 = 0;
        x4 = 0;
        Permutation(rounds: 12);
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        int i = 0;
        if (_bytesBuffered != 0 && _bytesBuffered + message.Length >= BlockSize) {
            Span<byte> b = _buffer;
            message[..(b.Length - _bytesBuffered)].CopyTo(b[_bytesBuffered..]);
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(b[..8]);
            x1 ^= BinaryPrimitives.ReadUInt64BigEndian(b[8..16]);
            x2 ^= BinaryPrimitives.ReadUInt64BigEndian(b[16..24]);
            x3 ^= BinaryPrimitives.ReadUInt64BigEndian(b[24..32]);
            x4 ^= BinaryPrimitives.ReadUInt64BigEndian(b[32..]);
            Permutation(rounds: 8);
            i += b.Length - _bytesBuffered;
            _bytesBuffered = 0;
            b.Clear();
        }

        while (i + BlockSize <= message.Length) {
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i, 8));
            x1 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 8, 8));
            x2 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 16, 8));
            x3 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 24, 8));
            x4 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i + 32, 8));
            Permutation(rounds: 8);
            i += BlockSize;
        }

        if (message.Length % BlockSize != 0) {
            message[i..].CopyTo(_buffer.AsSpan()[_bytesBuffered..]);
            _bytesBuffered += message.Length - i;
        }
    }

    public void Finalize(Span<byte> tag)
    {
        if (tag.Length is 0 or > TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be between 1 and {TagSize} bytes long."); }

        Span<byte> padding = stackalloc byte[BlockSize];
        padding.Clear();
        if (_bytesBuffered != 0) {
            _buffer.CopyTo(padding);
        }
        padding[_bytesBuffered] = 0x80;
        x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[..8]);
        x1 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[8..16]);
        x2 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[16..24]);
        x3 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[24..32]);
        x4 ^= BinaryPrimitives.ReadUInt64BigEndian(padding[32..]);
        x4 ^= 1;

        Permutation(rounds: 12);
        BinaryPrimitives.WriteUInt64BigEndian(padding[..8], x0);
        BinaryPrimitives.WriteUInt64BigEndian(padding[8..16], x1);
        padding[..tag.Length].CopyTo(tag);
        ZeroState();
        CryptographicOperations.ZeroMemory(padding);
    }

    public bool Verify(ReadOnlySpan<byte> tag)
    {
        if (tag.Length is 0 or > TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be between 1 and {TagSize} bytes long."); }

        Span<byte> computedTag = stackalloc byte[tag.Length];
        Finalize(computedTag);
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

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private void ZeroState()
    {
        x0 = 0;
        x1 = 0;
        x2 = 0;
        x3 = 0;
        x4 = 0;
        _bytesBuffered = 0;
        CryptographicOperations.ZeroMemory(_buffer);
    }

    public void Dispose()
    {
        ZeroState();
    }
}
