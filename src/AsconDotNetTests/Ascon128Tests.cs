namespace AsconDotNetTests;

[TestClass]
public class Ascon128Tests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon128v12/LWC_AEAD_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "e355159f292911f794cb1432a0103a8a",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "d72c225d6bc2075163bed863186ec886",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a"
        };
        yield return new object[]
        {
            "ef5763e75fe32f96d7863410ff0b4786",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "0ff1aef36526f368b9863d668ba72c8a",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213141516"
        };
        yield return new object[]
        {
            "bc18c3f4e39eca7222490d967c79bffc92",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "bc820dbdf7a4631c5b29884ad69175c3f58e28436dd71556d58dfa56ac890beb",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "bc820dbdf7a4631c5b29884ad69175c3389655ca817cdddddb4ee51c5c403b0ae24b7d8708",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "7763f8ba02b1e06bc3f2370da5b314302543e9d0",
            "00010203",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "00010203"
        };
        yield return new object[]
        {
            "1ee34125fdba17443d01da8a0eefb0454281d1d3b962418d2e1c8a6d14f3e8a2",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "2d134d2de994dec27e6314484b8ca9ff75dc667993e0ee22c4cc866744f0588e0d924f0a7ae482b017c36f60",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213141516171819"
        };
        yield return new object[]
        {
            "b96c78651b6246b0c3b1a5d373b0d5168dca4a96734cf0ddf5f92f8d15e30270279bf6a6cc3f2fc9350b915c292bdb8d",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Ascon128.TagSize, 1, Ascon128.NonceSize, Ascon128.KeySize, Ascon128.TagSize };
        yield return new object[] { Ascon128.TagSize, 0, Ascon128.NonceSize + 1, Ascon128.KeySize, Ascon128.TagSize };
        yield return new object[] { Ascon128.TagSize, 0, Ascon128.NonceSize - 1, Ascon128.KeySize, Ascon128.TagSize };
        yield return new object[] { Ascon128.TagSize, 0, Ascon128.NonceSize, Ascon128.KeySize + 1, Ascon128.TagSize };
        yield return new object[] { Ascon128.TagSize, 0, Ascon128.NonceSize, Ascon128.KeySize - 1, Ascon128.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, Ascon128.KeySize);
        Assert.AreEqual(16, Ascon128.NonceSize);
        Assert.AreEqual(16, Ascon128.TagSize);
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

        Ascon128.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon128.Encrypt(c, p, n, k, ad));
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

        Ascon128.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => Ascon128.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon128.Decrypt(p, c, n, k, ad));
    }
}
