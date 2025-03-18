using System.Security.Cryptography;
using CryptexSharp.Service;

#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
namespace CryptexSharp.Tests
{
	public class AesCryptoServiceTest
	{
		private readonly byte[] _key = new byte[32]; // 256-bit key
		private readonly byte[] _iv = new byte[16];  // 128-bit IV

		public AesCryptoServiceTest()
		{
			RandomNumberGenerator.Fill(_key);
			RandomNumberGenerator.Fill(_iv);
		}

		[Fact]
		public void Encrypt_ShouldReturnEncryptedData()
		{
			// Arrange
			var service = new AesCryptoService(_key, _iv);
			var data = "Olá! Meu nome é Vinícius Stutz.";

			// Act
			var encryptedData = service.Encrypt(data);

			// Assert
			Assert.NotNull(encryptedData);
			Assert.NotEmpty(encryptedData);
			Assert.NotEqual(System.Text.Encoding.UTF8.GetBytes(data), System.Text.Encoding.UTF8.GetBytes(encryptedData));
		}

		[Fact]
		public void Encrypt_EmptyString_ShouldReturnEncryptedData()
		{
			// Arrange
			var service = new AesCryptoService(_key, _iv);
			var data = string.Empty;

			Assert.Throws<ArgumentException>(() => service.Encrypt(data));
		}

		[Fact]
		public void Encrypt_NullString_ShouldThrowArgumentException()
		{
			// Arrange
			var service = new AesCryptoService(_key, _iv);

			// Act & Assert
			Assert.Throws<ArgumentException>(() => service.Encrypt(null));
		}
	}
}
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.