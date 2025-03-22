// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using System.Security.Cryptography;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;

namespace CryptexSharp.Core.Provider;

/// <summary>
///  The `AesProvider` class is a C# class that extends the `BaseProvider` class and implements the
/// `IProvider` interface. This means that the `AesProvider` class inherits functionality from the
/// `BaseProvider` class and also provides its own implementation of the methods defined in the
/// `IProvider` interface.
/// </summary>
public class AesProvider : BaseProvider, ICryptoProvider
{
	/// <summary>
	/// The `public AesProvider(byte[]? key = null, byte[]? iv = null)` constructor in the `AesProvider`
	/// class is a parameterized constructor that allows for the initialization of the `AesProvider` object
	/// with optional key and initialization vector (IV) values.
	/// </summary>
	/// <param name="key">
	/// The `key` parameter is an optional byte array that represents the key value to be used for AES.
	/// </param>
	/// <param name="iv">
	/// The `iv` parameter is an optional byte array that represents the initialization vector (IV) value.
	/// </param>
	public AesProvider(byte[]? key = null, byte[]? iv = null)
	{
		if (key != null && iv != null)
		{
			_keys[KeyType.Key] = key;
			_keys[KeyType.IV] = iv;
		}
	}

	/// <inheritdoc />
	public override Dictionary<KeyType, byte[]> GenerateKeyPairs(int[]? sizes = null)
	{
		var keySize = sizes != null && sizes.Length > 0 ? sizes[0] : 256;

		if (keySize != 128 && keySize != 192 && keySize != 256)
		{
			throw new CryptographicException("AES key size must be 128, 192, or 256 bits.", nameof(keySize));
		}

		var key = new byte[keySize / 8];
		var iv = new byte[16]; // AES uses a fixed 16 bytes IV (128 bits)

		using (var rng = RandomNumberGenerator.Create())
		{
			rng.GetBytes(key);
			rng.GetBytes(iv);
		}

		foreach (var entry in new Dictionary<KeyType, byte[]>
		{
			{ KeyType.Key, key },
			{ KeyType.IV, iv }
		})
		{
			_keys[entry.Key] = entry.Value;
		}

		return _keys;
	}

	/// <inheritdoc />
	public override void ImportKeys(Dictionary<KeyType, byte[]> keys)
	{
		if (!keys.ContainsKey(KeyType.Key) && !keys.ContainsKey(KeyType.IV))
		{
			throw new CryptographicException("Invalid keys.");
		}

		foreach (var key in keys)
		{
			_keys[key.Key] = key.Value;
		}
	}

	/// <inheritdoc />
	public override void SetKey(KeyType keyType, byte[] value)
	{
		switch (value)
		{
			case not null:
				_keys[keyType] = value ?? throw new ArgumentNullException(nameof(value));

				if (_keys.Count == 2 && _keys.ContainsKey(KeyType.Key) && _keys.ContainsKey(KeyType.IV))
				{
					ImportKeys(_keys);
				}
				break;
			default: throw new ArgumentNullException(nameof(value));
		}
	}
}
