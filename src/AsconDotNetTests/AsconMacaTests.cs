namespace AsconDotNetTests;

[TestClass]
public class AsconMacaaTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_auth/asconmacav12/LWC_AUTH_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "fddc38ec2e93f8b8524d88f6c5983d13",
            "",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "628a3773caae20b059fe89280e674735",
            "00",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "aa8737292e60df602b1f304d206815b1",
            "000102030405",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "a27166dee13a2cea58dcc18877aaaaed",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "f08c1acea000f5a6283d793789689d48",
            "000102030405060708090a0b0c0d0e0f10111213141516",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "4743df62c9958fa1a281ea56ef121bf1",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "1de1e42d311fde4fcf0f6a1265941c47",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627",
            "000102030405060708090a0b0c0d0e0f"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, AsconMaca.KeySize);
        Assert.AreEqual(16, AsconMaca.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var ascon = new AsconMaca(k);
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

        using var ascon = new AsconMaca(k);
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
    [DataRow(0, 1, AsconMaca.KeySize)]
    [DataRow(AsconMaca.TagSize + 1, 1, AsconMaca.KeySize)]
    [DataRow(AsconMaca.TagSize, 1, AsconMaca.KeySize + 1)]
    [DataRow(AsconMaca.TagSize, 1, AsconMaca.KeySize - 1)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        if (keySize != AsconMaca.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AsconMaca(k));
        }
        else {
            using var ascon = new AsconMaca(k);
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

        using var ascon = new AsconMaca(k);
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
            using var ascon = new AsconMaca(parameters[2]);
            ascon.Update(parameters[1]);
            bool valid = ascon.Verify(parameters[0]);
            param[0]--;
            Assert.IsFalse(valid);
        }
    }
}
