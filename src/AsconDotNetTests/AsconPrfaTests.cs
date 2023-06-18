namespace AsconDotNetTests;

[TestClass]
public class AsconPrfaaTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconprfav12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> PrfTestVectors()
    {
        yield return new object[]
        {
            "99fdc07ca98af6e6d282e84094cd79cf",
            "",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "08ae72db8e69d636b9964428dd5feb3f",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "afce7b276310453cdeecaaab0107ae26",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "ed1ba2ca3d58b099acd54571217047e1",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "eab6e5c86cc4bc290a78353175871f95",
            "000102030405060708090a0b0c0d0e0f10111213141516",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "b53b6261d9bed0b09af484d9b2ff53d1",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
        yield return new object[]
        {
            "9424350bb35322258cf4654eae14cf34",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
            "000102030405060708090a0b0c0d0e0f",
            false
        };
    }

    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconmacav12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> MacTestVectors()
    {
        yield return new object[]
        {
            "fddc38ec2e93f8b8524d88f6c5983d13",
            "",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "628a3773caae20b059fe89280e674735",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "aa8737292e60df602b1f304d206815b1",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "a27166dee13a2cea58dcc18877aaaaed",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "f08c1acea000f5a6283d793789689d48",
            "000102030405060708090a0b0c0d0e0f10111213141516",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "4743df62c9958fa1a281ea56ef121bf1",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
        yield return new object[]
        {
            "1de1e42d311fde4fcf0f6a1265941c47",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
            "000102030405060708090a0b0c0d0e0f",
            true
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { AsconPrfa.TagSize + 1, 1, AsconPrfa.KeySize, true };
        yield return new object[] { 0, 1, AsconPrfa.KeySize, true };
        yield return new object[] { AsconPrfa.TagSize, 1, AsconPrfa.KeySize + 1, true };
        yield return new object[] { AsconPrfa.TagSize, 1, AsconPrfa.KeySize - 1, true };
        yield return new object[] { 0, 1, AsconPrfa.KeySize, false };
        yield return new object[] { AsconPrfa.TagSize, 1, AsconPrfa.KeySize + 1, false };
        yield return new object[] { AsconPrfa.TagSize, 1, AsconPrfa.KeySize - 1, false };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconPrfa.TagSize);
        Assert.AreEqual(16, AsconPrfa.KeySize);
    }

    [TestMethod]
    [DynamicData(nameof(PrfTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(MacTestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key, bool macMode)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        AsconPrfa.ComputeTag(t, m, k, macMode);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize, bool macMode)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrfa.ComputeTag(t, m, k, macMode));
    }

    [TestMethod]
    [DynamicData(nameof(MacTestVectors), DynamicDataSourceType.Method)]
    public void VerifyTag_Valid(string tag, string message, string key, bool macMode)
    {
        Span<byte> t = Convert.FromHexString(tag);
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        bool valid = AsconPrfa.VerifyTag(t, m, k, macMode);

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
            bool valid = AsconPrfa.VerifyTag(parameters[0], parameters[1], parameters[2], macMode);
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AsconPrfa.VerifyTag(t, m, k, macMode));
    }
}
