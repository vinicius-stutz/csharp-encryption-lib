using System.Security.Cryptography;

namespace CryptexSharp.Service
{
    public class AesCryptoService : ICryptoService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public AesCryptoService(byte[] key, byte[] iv)
        {
            _key = key;
            _iv = iv;
        }

        public string Encrypt(string data)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentException($"'{nameof(data)}' cannot be null or empty.", nameof(data));
            }

            var bytes = System.Text.Encoding.UTF8.GetBytes(data);
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;

            using var encryptor = aes.CreateEncryptor();
            var encryptedData = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
            return Convert.ToBase64String(encryptedData);
        }

        public string Decrypt(byte[] encryptedData)
        {
            ArgumentNullException.ThrowIfNull(encryptedData);

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            using var decryptor = aes.CreateDecryptor();
            var data = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            return System.Text.Encoding.UTF8.GetString(data);
        }
    }
}