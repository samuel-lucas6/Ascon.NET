namespace AsconDotNetTests;

[TestClass]
public class Ascon128aTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "7a834e6f09210957067b10fd831f0078",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "cc13a2922a77f0461652bbaddba24e11",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c"
        };
        yield return new object[]
        {
            "56c15eb024de91ca0165362a49b31ebd",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "b399034306e26e73e8b9c160ff5281b3",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f1011121314"
        };
        yield return new object[]
        {
            "6e490c898cd14e8316e149a6edfc3b16c23a4e",
            "000102",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "6e490cfed5b3546767350cd83c4acfbdb10f611b7d79278bd8067fc1bcdf39be",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "6e490cfed5b3546767350cd83c4acfbd4cfb4bd07abf5bc24db6518f49190647cb245d6c6a30b3acb0",
            "000102030405060708090a0b0c0d0e0f101112131415161718",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "e92ddc373c1745eb7e1f648baeae0f774787",
            "0001",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "00"
        };
        yield return new object[]
        {
            "52499ac9c84323a4ae24eaeccf45c137316d7ab17724ba67a85ecd3c0457c459",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "b7534c82a8d1d5b6b6d327fa143141478b1139e4800a19269418625516ee411700ff2650ab20d5e25b56a29435",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f101112"
        };
        yield return new object[]
        {
            "a55236ac020dbda74ce6ccd10c68c4d8514450a382bc87c68946d86a921dd88e2adddfbbe77d4112830e01960b9d38d5",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Ascon128a.TagSize, 1, Ascon128a.NonceSize, Ascon128a.KeySize, Ascon128a.TagSize };
        yield return new object[] { Ascon128a.TagSize, 0, Ascon128a.NonceSize + 1, Ascon128a.KeySize, Ascon128a.TagSize };
        yield return new object[] { Ascon128a.TagSize, 0, Ascon128a.NonceSize - 1, Ascon128a.KeySize, Ascon128a.TagSize };
        yield return new object[] { Ascon128a.TagSize, 0, Ascon128a.NonceSize, Ascon128a.KeySize + 1, Ascon128a.TagSize };
        yield return new object[] { Ascon128a.TagSize, 0, Ascon128a.NonceSize, Ascon128a.KeySize - 1, Ascon128a.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, Ascon128a.KeySize);
        Assert.AreEqual(16, Ascon128a.NonceSize);
        Assert.AreEqual(16, Ascon128a.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Ascon128a.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon128a.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Ascon128a.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length != 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => Ascon128a.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon128a.Decrypt(p, c, n, k, ad));
    }
}
