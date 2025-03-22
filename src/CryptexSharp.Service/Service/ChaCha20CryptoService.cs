// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using System.Security.Cryptography;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;
using Sodium;

namespace CryptexSharp.Core.Service;

public class ChaCha20CryptoService : ICryptoService
{
	private readonly ICryptoProvider _provider;
	private readonly byte[] _nonce;
	private readonly byte[] _key;

	public ChaCha20CryptoService(ICryptoProvider provider)
	{
		if (provider is null)
		{
			throw new ArgumentNullException(nameof(provider));
		}

		_provider = provider;
		_key = provider.GetKey(KeyType.Key);
		_nonce = provider.GetKey(KeyType.Nonce);
	}

	public ICryptoProvider Provider => _provider ?? throw new ArgumentNullException(nameof(_provider));

	/// <inheritdoc />
	public string Encrypt(string data)
	{
		if (string.IsNullOrEmpty(data))
		{
			throw new ArgumentException("Data cannot be null or empty.", nameof(data));
		}

		var plainBytes = System.Text.Encoding.UTF8.GetBytes(data);
		var encryptedBytes = SecretAeadChaCha20Poly1305.Encrypt(plainBytes, _nonce, _key);
		return Convert.ToBase64String(encryptedBytes);
	}

	/// <inheritdoc />
	public string Decrypt(byte[] encryptedData)
	{
		if (encryptedData == null || encryptedData.Length == 0)
		{
			throw new ArgumentException("Encrypted data cannot be null or empty.", nameof(encryptedData));
		}

		try
		{
			var decryptedBytes = SecretAeadChaCha20Poly1305.Decrypt(encryptedData, _nonce, _key);
			return System.Text.Encoding.UTF8.GetString(decryptedBytes);
		}
		catch (CryptographicException)
		{
			throw new InvalidOperationException("Decryption failed. Ensure the key, nonce, and data are correct.");
		}
	}

	/// <inheritdoc />
	public string Decrypt(string encryptedData)
	{
		if (string.IsNullOrEmpty(encryptedData))
		{
			throw new ArgumentException($"'{nameof(encryptedData)}' cannot be null or empty.", nameof(encryptedData));
		}

		return Decrypt(Convert.FromBase64String(encryptedData));
	}
}