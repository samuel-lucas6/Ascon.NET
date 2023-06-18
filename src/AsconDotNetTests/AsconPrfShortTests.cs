namespace AsconDotNetTests;

[TestClass]
public class AsconPrfShortTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconprfsv12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "5006eb1808193809f981151b19e59299",
            "",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "bde4e1a8fb90cd5a2f2dba6184b65395",
            "00",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "fae8d585fb0ecf5b465bbc9fdabdf722",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "bd03ea334bebefc4d7ddaef4b1df1485",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconPrfShort.OutputSize);
        Assert.AreEqual(16, AsconPrfShort.InputSize);
        Assert.AreEqual(16, AsconPrfShort.KeySize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string output, string input, string key)
    {
        Span<byte> o = stackalloc byte[output.Length / 2];
        Span<byte> i = Convert.FromHexString(input);
        Span<byte> k = Convert.FromHexString(key);

        AsconPrfShort.DeriveKey(o, i, k);

        Assert.AreEqual(output, Convert.ToHexString(o).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, AsconPrfShort.KeySize)]
    [DataRow(AsconPrfShort.OutputSize + 1, 1, AsconPrfShort.KeySize)]
    [DataRow(AsconPrfShort.OutputSize, AsconPrfShort.InputSize + 1, AsconPrfShort.KeySize)]
    [DataRow(AsconPrfShort.OutputSize, 1, AsconPrfShort.KeySize + 1)]
    [DataRow(AsconPrfShort.OutputSize, 1, AsconPrfShort.KeySize - 1)]
    public void DeriveKey_Invalid(int outputSize, int inputSize, int keySize)
    {
        var o = new byte[outputSize];
        var i = new byte[inputSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrfShort.DeriveKey(o, i, k));
    }
}
