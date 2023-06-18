namespace AsconDotNetTests;

[TestClass]
public class AsconHashingTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconhashv12/LWC_HASH_KAT_256.txt
    public static IEnumerable<object[]> HashTestVectors()
    {
        yield return new object[]
        {
            false,
            false,
            "7346bc14f036e87ae03d0997913088f5f68411434b3cf8b54fa796a80d251f91",
            ""
        };
        yield return new object[]
        {
            false,
            false,
            "8dd446ada58a7740ecf56eb638ef775f7d5c0fd5f0c2bbbdfdec29609d3c43a2",
            "00"
        };
        yield return new object[]
        {
            false,
            false,
            "9c52142852beb6654907cc23cc5b171075d411ca80082aafd7dd0d09ba0bba1d",
            "000102030405"
        };
        yield return new object[]
        {
            false,
            false,
            "f4c6a44b29915d3d57cf928a18ec6226bb8dd6c1136acd24965f7e7780cd69cf",
            "0001020304050607"
        };
        yield return new object[]
        {
            false,
            false,
            "368946d5790a805945ace20df59352fc3575d524384f702d32175afac9534f1f",
            "000102030405060708090a0b0c"
        };
        yield return new object[]
        {
            false,
            false,
            "d4e56c4841e2a0069d4f07e61b2dca94fd6d3f9c0df78393e6e8292921bc841d",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            false,
            false,
            "2a4f6f2b6b3ec2a6c47ba08d18c8ea561b493c13ccb35803fa8b9fb00a0f1f35",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            false,
            false,
            "681496911e59fda6e6dc5f1786e9c8c744090da6c66e8807c9bd140c06dfb2b8",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"
        };
    }

    // https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconxofv12/LWC_HASH_KAT_256.txt
    public static IEnumerable<object[]> XofTestVectors()
    {
        yield return new object[]
        {
            true,
            false,
            "5d4cbde6350ea4c174bd65b5b332f8408f99740b81aa02735eaefbcf0ba0339e",
            ""
        };
        yield return new object[]
        {
            true,
            false,
            "b2edbb27ac8397a55bc83d137c151de9ede048338fe907f0d3629e717846fedc",
            "00"
        };
        yield return new object[]
        {
            true,
            false,
            "d7658b24b9886057b8827518a2a36715a1b73256e65d0493dd0af3e27387df40",
            "000102030405"
        };
        yield return new object[]
        {
            true,
            false,
            "18427d2d29df1e0202649f032f2080363fec5de72ecae11b4f98ccc75843e7cc",
            "0001020304050607"
        };
        yield return new object[]
        {
            true,
            false,
            "6e6823d3c04ea3bc20b43beceb5b42854ef840ee477b58709449bb8d8f63ee78",
            "000102030405060708090a0b0c"
        };
        yield return new object[]
        {
            true,
            false,
            "c861a89cfb1335f278c96cf7ffc9753c290cbe1a4e186d2923b496bb4ea5e519",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            true,
            false,
            "0b8e325b9bbf1bb43e77aa1eed93bee62b4ea1e4b0c5a696b2f5c5b09c968918",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            true,
            false,
            "9374cb79f0c1654af2de94455df4cca2ce11535e82b303875b4711ff47a6870b",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"
        };
    }

    // https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconhashav12/LWC_HASH_KAT_256.txt
    public static IEnumerable<object[]> HashaTestVectors()
    {
        yield return new object[]
        {
            false,
            true,
            "aecd027026d0675f9de7a8ad8ccf512db64b1edcf0b20c388a0c7cc617aaa2c4",
            ""
        };
        yield return new object[]
        {
            false,
            true,
            "5a55f0367763d334a3174f9c17fa476eb9196a22f10daf29505633572e7756e4",
            "00"
        };
        yield return new object[]
        {
            false,
            true,
            "c9832114b471fb2024f736c4ef3ff1802850ced13abd8a2f75cfa1f9d19490e2",
            "000102030405"
        };
        yield return new object[]
        {
            false,
            true,
            "be9332e10ad16137322968bbec1776ba3f4ecdc1183db7dbe1ac98bd66fce7b6",
            "0001020304050607"
        };
        yield return new object[]
        {
            false,
            true,
            "e1c07424ed45224af7412060078f8c0534155b6da3be5d5c1c6cd57391560500",
            "000102030405060708090a0b0c"
        };
        yield return new object[]
        {
            false,
            true,
            "ea1cb73639bfa0c6de4e60960f4f73510fe4481340f1d956a59e9dd2166f9a99",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            false,
            true,
            "3237cbcc617a2550583a50e8bad3dacda82562e06220150448c109008fa054a2",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            false,
            true,
            "c94bdd0afbadc4667d5257c39d331bf1afc4d5f65d98c3febfbc480d4e8b9366",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"
        };
    }

    // https://github.com/ascon/ascon-c/blob/main/crypto_hash/asconxofav12/LWC_HASH_KAT_256.txt
    public static IEnumerable<object[]> XofaTestVectors()
    {
        yield return new object[]
        {
            true,
            true,
            "7c10dffd6bb03be262d72fbe1b0f530013c6c4eadaabde278d6f29d579e3908d",
            ""
        };
        yield return new object[]
        {
            true,
            true,
            "965445c46c8e9b948edfef7b5879e06ab5f023770ea892fa4b54525008467ea3",
            "00"
        };
        yield return new object[]
        {
            true,
            true,
            "30bc8d20c4aa4df539e9e6b58a452cac9e5e98f94c6c90bf6c3bc9cf573eb9ed",
            "000102030405"
        };
        yield return new object[]
        {
            true,
            true,
            "91c72f6273b6ed444bf560f2fac99e8fedddf30162688b86553eb57f1c98c20e",
            "0001020304050607"
        };
        yield return new object[]
        {
            true,
            true,
            "f84e89a3e9070aaefe860d4983807e07d1fbf65dab2f1b8151347f828c9f0fc0",
            "000102030405060708090a0b0c"
        };
        yield return new object[]
        {
            true,
            true,
            "9424b7ae5fa72d3ee4a266112e7abc4092e815ae29fab26da666c1485ba92bdc",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            true,
            true,
            "42047aea031115f8465cbfac356ac23c4d71f84bd661c8aa7971f37118e520e6",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            true,
            true,
            "7ee1b3f0b5b5909b77e13a3f07c3dc795a2ef19ac0dc89a1e9c0fa53f3c1197e",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, AsconHashing.HashSize);
    }

    [TestMethod]
    [DynamicData(nameof(HashTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(XofTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(HashaTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(XofaTestVectors), DynamicDataSourceType.Method)]
    public void Hash_Valid(bool xof, bool aVariant, string hash, string message)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);

        using var ascon = new AsconHashing(xof, aVariant);
        ascon.Update(m);
        ascon.Finalize(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(HashTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(XofTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(HashaTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(XofaTestVectors), DynamicDataSourceType.Method)]
    public void HashAndReset_Valid(bool xof, bool aVariant, string hash, string message)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);

        using var ascon = new AsconHashing(xof, aVariant);
        ascon.Update(m);
        ascon.FinalizeAndReset(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());

        ascon.Update(m);
        ascon.Finalize(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(HashTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(XofTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(HashaTestVectors), DynamicDataSourceType.Method)]
    [DynamicData(nameof(XofaTestVectors), DynamicDataSourceType.Method)]
    public void IncrementalHash_Valid(bool xof, bool aVariant, string hash, string message)
    {
        Span<byte> h = stackalloc byte[hash.Length / 2];
        Span<byte> m = Convert.FromHexString(message);

        using var ascon = new AsconHashing(xof, aVariant);
        if (m.Length > 1) {
            ascon.Update(m[..(m.Length / 2)]);
            ascon.Update(m[(m.Length / 2)..]);
        }
        else {
            ascon.Update(m);
        }
        ascon.Update(ReadOnlySpan<byte>.Empty);
        ascon.Finalize(h);

        Assert.AreEqual(hash, Convert.ToHexString(h).ToLower());
    }

    [TestMethod]
    [DataRow(false, false, AsconHashing.HashSize + 1, 1)]
    [DataRow(false, false, AsconHashing.HashSize - 1, 1)]
    [DataRow(false, true, AsconHashing.HashSize + 1, 1)]
    [DataRow(false, true, AsconHashing.HashSize - 1, 1)]
    [DataRow(true, false, 0, 1)]
    [DataRow(true, true, 0, 1)]
    public void Hash_Invalid(bool xof, bool aVariant, int hashSize, int messageSize)
    {
        var h = new byte[hashSize];
        var m = new byte[messageSize];

        using var ascon = new AsconHashing(xof, aVariant);
        ascon.Update(m);

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ascon.Finalize(h));
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ascon.FinalizeAndReset(h));
    }
}
