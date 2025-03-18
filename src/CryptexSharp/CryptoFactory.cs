using CryptexSharp.Service;

namespace CryptexSharp
{
	public static class CryptoFactory
	{
		/// <summary>
		/// Creates an instance of <see cref="ICryptoService"/> using AES encryption.
		/// </summary>
		/// <param name="key">The encryption key.</param>
		/// <param name="iv">The initialization vector.</param>
		/// <returns>An instance of <see cref="ICryptoService"/> configured for AES encryption.</returns>
		public static ICryptoService CreateAesService(byte[] key, byte[] iv)
		{
			return new AesCryptoService(key, iv);
		}
	}
}