namespace AsconDotNetTests;

[TestClass]
public class AsconMacTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconmacv12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "eb1af688825d66bf2d53e135f9323315",
            "",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "81f3c3537c5595aaa0d5780b9f88a043",
            "00",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "46012c9120f4ebc3f8d55eb8b52ff921",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "a7915e83ee1aa71422cfd90868e22dc2",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "c531063cb12a426c5d41aeebbe0c08e5",
            "000102030405060708090a0b0c0d0e0f101112",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "892523d61028799c507d1644126f03ef",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "b07a8c3b23506040c9587c4cf8a0f4c3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
            "000102030405060708090a0b0c0d0e0f"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconMac.KeySize);
        Assert.AreEqual(16, AsconMac.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var ascon = new AsconMac(k);
        ascon.Update(m);
        ascon.Finalize(t);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var ascon = new AsconMac(k);
        if (m.Length > 1) {
            ascon.Update(m[..(m.Length / 2)]);
            ascon.Update(m[(m.Length / 2)..]);
        }
        else {
            ascon.Update(m);
        }
        ascon.Update(ReadOnlySpan<byte>.Empty);
        ascon.Finalize(t);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, AsconMac.KeySize)]
    [DataRow(AsconMac.TagSize + 1, 1, AsconMac.KeySize)]
    [DataRow(AsconMac.TagSize, 1, AsconMac.KeySize + 1)]
    [DataRow(AsconMac.TagSize, 1, AsconMac.KeySize - 1)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        if (keySize != AsconMac.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AsconMac(k));
        }
        else {
            using var ascon = new AsconMac(k);
            ascon.Update(m);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => ascon.Finalize(t));
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => ascon.Verify(t));
        }
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var ascon = new AsconMac(k);
        ascon.Update(m);
        bool valid = ascon.Verify(t);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Tampered(string tag, string message, string key)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(tag),
            Convert.FromHexString(message),
            Convert.FromHexString(key)
        };

        foreach (var param in parameters.Where(param => param.Length != 0)) {
            param[0]++;
            using var ascon = new AsconMac(parameters[2]);
            ascon.Update(parameters[1]);
            bool valid = ascon.Verify(parameters[0]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }
}
