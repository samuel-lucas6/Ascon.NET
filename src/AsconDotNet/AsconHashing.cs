using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace AsconDotNet;

public sealed class AsconHashing : IDisposable
{
    public const int HashSize = 32;
    private const int Rate = 8;
    private const int aRounds = 12;
    private int _bRounds = 12;
    private bool _xof, _aVariant;
    private byte[] _buffer = new byte[Rate];
    private int _bytesBuffered;
    private ulong x0, x1, x2, x3, x4;

    public AsconHashing(bool xof = false, bool aVariant = false)
    {
        Initialize(xof, aVariant);
    }

    private void Initialize(bool xof, bool aVariant)
    {
        _xof = xof;
        _aVariant = aVariant;
        if (aVariant) {
            _bRounds = 8;
        }
        x0 = xof switch
        {
            false when !aVariant => 0x00400c0000000100,
            true when !aVariant => 0x00400c0000000000,
            false when aVariant => 0x00400c0400000100,
            true when aVariant => 0x00400c0400000000
        };
        x1 = 0;
        x2 = 0;
        x3 = 0;
        x4 = 0;
        Permutation(aRounds);
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        int i = 0;
        if (_bytesBuffered != 0 && _bytesBuffered + message.Length >= Rate) {
            Span<byte> b = _buffer.AsSpan();
            message[..(b.Length - _bytesBuffered)].CopyTo(b[_bytesBuffered..]);
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(b);
            Permutation(_bRounds);
            i += b.Length - _bytesBuffered;
            _bytesBuffered = 0;
            b.Clear();
        }

        while (i + Rate <= message.Length) {
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(message.Slice(i, Rate));
            Permutation(_bRounds);
            i += Rate;
        }

        if (message.Length % Rate != 0) {
            message[i..].CopyTo(_buffer.AsSpan()[_bytesBuffered..]);
            _bytesBuffered += message.Length - i;
        }
    }

    public void Finalize(Span<byte> hash)
    {
        if (!_xof && hash.Length != HashSize) { throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"{nameof(hash)} must be {HashSize} bytes long."); }
        if (_xof && hash.Length == 0) { throw new ArgumentOutOfRangeException(nameof(hash), hash.Length, $"{nameof(hash)} must be greater than 0 bytes long."); }

        Span<byte> padding = stackalloc byte[Rate];
        padding.Clear();
        if (_bytesBuffered != 0) {
            _buffer.CopyTo(padding);
        }
        padding[_bytesBuffered] = 0x80;
        x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding);
        Permutation(aRounds);

        int i = 0;
        while (i + Rate <= hash.Length) {
            BinaryPrimitives.WriteUInt64BigEndian(hash.Slice(i, Rate), x0);
            Permutation(_bRounds);
            i += Rate;
        }
        if (hash.Length % Rate != 0) {
            BinaryPrimitives.WriteUInt64BigEndian(padding, x0);
            padding[..(hash.Length % Rate)].CopyTo(hash[i..]);
        }
        ZeroState();
        CryptographicOperations.ZeroMemory(padding);
    }

    public void FinalizeAndReset(Span<byte> hash)
    {
        Finalize(hash);
        Initialize(_xof, _aVariant);
    }

    private void Permutation(int rounds)
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
