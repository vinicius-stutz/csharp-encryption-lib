using Encryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace EncryptionUnitTest
{
    [TestClass]
    public class UnitTest
    {
        private readonly string key1 = "Sample Programmer Key";
        private readonly string key2 = "A Crazy :o) Sample Programmer Key";

        [TestMethod]
        public void EncryptStringUsingDES()
        {
            string s = null;

            CryptService crip = new CryptService(CryptProvider.DES);
            crip.Key = key1;

            // Vai gerar a string XY0tce7dmMFhL31KjdPazmyWK6lA8Ueecj3NjzfJ+HRdTci8+n1yGg==
            s = crip.Encrypt("Exemplo de criptografia usando DES.");

            Assert.IsNotNull(s);
        }

        [TestMethod]
        public void DecryptStringUsingDES()
        {
            string s = null;

            CryptService crip = new CryptService(CryptProvider.DES);
            crip.Key = key1;

            s = crip.Decrypt("XY0tce7dmMFhL31KjdPazmyWK6lA8Ueecj3NjzfJ+HRdTci8+n1yGg==");

            Assert.AreEqual("Exemplo de criptografia usando DES.", s);
        }

        [TestMethod]
        public void EncryptStringUsingRijndael()
        {
            string s = null;

            CryptService crip = new CryptService(CryptProvider.Rijndael);
            crip.Key = key2;

            // Vai gerar a string 9p4GFRFMviNj2EofPB2hRZcbgrgi3SrJddPsxw2ukcxHx7b3TZUJO6t+0oEVaLOI
            s = crip.Encrypt("Exemplo de criptografia usando Rijndael.");

            Assert.IsNotNull(s);
        }

        [TestMethod]
        public void DecryptStringUsingRijndael()
        {
            string s = null;

            CryptService crip = new CryptService(CryptProvider.Rijndael);
            crip.Key = key2;

            s = crip.Decrypt("9p4GFRFMviNj2EofPB2hRZcbgrgi3SrJddPsxw2ukcxHx7b3TZUJO6t+0oEVaLOI");

            Assert.AreEqual("Exemplo de criptografia usando Rijndael.", s);
        }
    }
}
