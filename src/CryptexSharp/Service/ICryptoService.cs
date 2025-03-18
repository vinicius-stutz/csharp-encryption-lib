namespace CryptexSharp.Service
{
    public interface ICryptoService
    {
        string Encrypt(string data);
        string Decrypt(byte[] encryptedData);
    }
}
