namespace AsconDotNetTests;

[TestClass]
public class AsconPrfTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconprfv12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> PrfTestVectors()
    {
        yield return new object[]
        {
            "2a766fe9a4894073bc811b19d54ac33d",
            "",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "62dcf5fd8253089b765e2cf1a0d1a4fa",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "f26a56217d27d610adf1d2275343605f",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "87287b11bfbcc92d43e3667f7ac30c90",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "c7c311ec55bedcf585203f14d982fa9e",
            "000102030405060708090a0b0c0d0e0f101112",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "5674455f29416f5081d05ee3c31e286b",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "7bdfec4000247de739af590c4d620152",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
    }

    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconmacv12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> MacTestVectors()
    {
        yield return new object[]
        {
            "eb1af688825d66bf2d53e135f9323315",
            "",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "81f3c3537c5595aaa0d5780b9f88a043",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "46012c9120f4ebc3f8d55eb8b52ff921",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "a7915e83ee1aa71422cfd90868e22dc2",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "c531063cb12a426c5d41aeebbe0c08e5",
            "000102030405060708090a0b0c0d0e0f101112",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "892523d61028799c507d1644126f03ef",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "b07a8c3b23506040c9587c4cf8a0f4c3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { AsconPrf.TagSize + 1, 1, AsconPrf.KeySize, true };
        yield return new object[] { 0, 1, AsconPrf.KeySize, true };
        yield return new object[] { AsconPrf.TagSize, 1, AsconPrf.KeySize + 1, true };
        yield return new object[] { AsconPrf.TagSize, 1, AsconPrf.KeySize - 1, true };
        yield return new object[] { 0, 1, AsconPrf.KeySize, false };
        yield return new object[] { AsconPrf.TagSize, 1, AsconPrf.KeySize + 1, false };
        yield return new object[] { AsconPrf.TagSize, 1, AsconPrf.KeySize - 1, false };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconPrf.TagSize);
        Assert.AreEqual(16, AsconPrf.KeySize);
    }

    [TestMethod]
    [DynamicData(nameof(PrfTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(MacTestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key, bool macMode)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        AsconPrf.ComputeTag(t, m, k, macMode);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize, bool macMode)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrf.ComputeTag(t, m, k, macMode));
    }

    [TestMethod]
    [DynamicData(nameof(MacTestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Valid(string tag, string message, string key, bool macMode)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        bool valid = AsconPrf.VerifyTag(t, m, k, macMode);

        Assert.IsTrue(valid);
    }

    [TestMethod]
    [DynamicData(nameof(MacTestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Tampered(string tag, string message, string key, bool macMode)
    {
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(tag),
            Convert.FromHexString(message),
            Convert.FromHexString(key)
        };

        foreach (var param in parameters.Where(param => param.Length != 0)) {
            param[0]++;
            bool valid = AsconPrf.VerifyTag(parameters[0], parameters[1], parameters[2], macMode);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void VerifyTag_Invalid(int tagSize, int messageSize, int keySize, bool macMode)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrf.VerifyTag(t, m, k, macMode));
    }
}
