namespace AsconDotNetTests;

[TestClass]
public class AsconPrfaTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/AsconPrfav12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "99fdc07ca98af6e6d282e84094cd79cf",
            "",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "08ae72db8e69d636b9964428dd5feb3f",
            "00",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "afce7b276310453cdeecaaab0107ae26",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "ed1ba2ca3d58b099acd54571217047e1",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "eab6e5c86cc4bc290a78353175871f95",
            "000102030405060708090a0b0c0d0e0f10111213141516",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "b53b6261d9bed0b09af484d9b2ff53d1",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "9424350bb35322258cf4654eae14cf34",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
            "000102030405060708090a0b0c0d0e0f"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconPrfa.OutputSize);
        Assert.AreEqual(16, AsconPrfa.KeySize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void DeriveKey_Valid(string output, string input, string key)
    {
        Span<byte> o = stackalloc byte[output.Length / 2];
        Span<byte> i = Convert.FromHexString(input);
        Span<byte> k = Convert.FromHexString(key);

        AsconPrfa.DeriveKey(o, i, k);

        Assert.AreEqual(output, Convert.ToHexString(o).ToLower());
    }

    [TestMethod]
    [DataRow(0, 1, AsconPrfa.KeySize)]
    [DataRow(AsconPrfa.OutputSize, 1, AsconPrfa.KeySize + 1)]
    [DataRow(AsconPrfa.OutputSize, 1, AsconPrfa.KeySize - 1)]
    public void DeriveKey_Invalid(int outputSize, int inputSize, int keySize)
    {
        var o = new byte[outputSize];
        var i = new byte[inputSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrfa.DeriveKey(o, i, k));
    }
}
