namespace AsconDotNetTests;

[TestClass]
public class AsconPrfTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconprfv12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "2a766fe9a4894073bc811b19d54ac33d",
            "",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "62dcf5fd8253089b765e2cf1a0d1a4fa",
            "00",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "f26a56217d27d610adf1d2275343605f",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "87287b11bfbcc92d43e3667f7ac30c90",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "c7c311ec55bedcf585203f14d982fa9e",
            "000102030405060708090a0b0c0d0e0f101112",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "5674455f29416f5081d05ee3c31e286b",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "7bdfec4000247de739af590c4d620152",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435",
            "000102030405060708090a0b0c0d0e0f"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconPrf.OutputSize);
        Assert.AreEqual(16, AsconPrf.KeySize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string output, string input, string key)
    {
        Span<byte> o = stackalloc byte[output.Length / 2];
        Span<byte> i = Convert.FromHexString(input);
        Span<byte> k = Convert.FromHexString(key);

        AsconPrf.DeriveKey(o, i, k);

        Assert.AreEqual(output, Convert.ToHexString(o).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, AsconPrf.KeySize)]
    [DataRow(AsconPrf.OutputSize, 1, AsconPrf.KeySize + 1)]
    [DataRow(AsconPrf.OutputSize, 1, AsconPrf.KeySize - 1)]
    public void DeriveKey_Invalid(int outputSize, int inputSize, int keySize)
    {
        var o = new byte[outputSize];
        var i = new byte[inputSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrf.DeriveKey(o, i, k));
    }
}
