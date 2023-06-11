namespace AsconDotNetTests;

[TestClass]
public class Ascon80pqTests
{
    // https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon80pqv12/LWC_AEAD_KAT_160_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "abb688efa0b9d56b33277a2c97d2146b",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "998dc6c464fc3e5f8241766a7094738a",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "00010203"
        };
        yield return new object[]
        {
            "b59e1cfbdb3ef7c32bcd3b8818074a90",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "3d1a7595f83946a7fb1c069e92390d33",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f101112131415"
        };
        yield return new object[]
        {
            "28aa80fff4ca3af32f60ebcaf63a4ccab7",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "2846418067ce9386b47f0584bf9eee3f818ca2b264f3bbfc40b773d0eb81f594",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "2846418067ce9386b47f0584bf9eee3f51a62969f03b39b24597385e9b17afa50c5fb197ce",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "8987022af6e736cb84b8e988085b09b9f6b08e6b",
            "00010203",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "00010203"
        };
        yield return new object[]
        {
            "1db9005057cfc7dcc273a6722b8be1bcdab849111cfd590f480f66be1d393841",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "7d4dd96f7e3fdacbfa6d9625b8c11e68f1ed3c146b4be92648b4954718d08743f8ad353ee379884787d6110d",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
        };
        yield return new object[]
        {
            "cc4e07e5fb13426effd17b0f51a6a830bf484c9651d77679971e8eb4a8edb5a00782a94c72b2b02d87dcf4af75db6996",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Ascon80pq.TagSize, 1, Ascon80pq.NonceSize, Ascon80pq.KeySize, Ascon80pq.TagSize };
        yield return new object[] { Ascon80pq.TagSize, 0, Ascon80pq.NonceSize + 1, Ascon80pq.KeySize, Ascon80pq.TagSize };
        yield return new object[] { Ascon80pq.TagSize, 0, Ascon80pq.NonceSize - 1, Ascon80pq.KeySize, Ascon80pq.TagSize };
        yield return new object[] { Ascon80pq.TagSize, 0, Ascon80pq.NonceSize, Ascon80pq.KeySize + 1, Ascon80pq.TagSize };
        yield return new object[] { Ascon80pq.TagSize, 0, Ascon80pq.NonceSize, Ascon80pq.KeySize - 1, Ascon80pq.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(20, Ascon80pq.KeySize);
        Assert.AreEqual(16, Ascon80pq.NonceSize);
        Assert.AreEqual(16, Ascon80pq.TagSize);
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

        Ascon80pq.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon80pq.Encrypt(c, p, n, k, ad));
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

        Ascon80pq.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => Ascon80pq.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon80pq.Decrypt(p, c, n, k, ad));
    }
}
