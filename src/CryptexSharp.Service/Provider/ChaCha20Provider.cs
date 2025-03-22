// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using System.Security.Cryptography;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;

namespace CryptexSharp.Core.Provider;

/// <summary>
/// The line `public class ChaCha20Provider : BaseProvider, IProvider` is declaring a class named
/// `ChaCha20Provider` that inherits from the `BaseProvider` class and implements the `IProvider`
/// interface. This means that the `ChaCha20Provider` class will inherit members and functionality from
/// the `BaseProvider` class and also implement the members defined in the `IProvider` interface. This
/// allows the `ChaCha20Provider` class to have access to the properties and methods defined in
/// `BaseProvider` and also ensures that it implements the required members specified by the `IProvider`
/// interface.
/// </summary>
public class ChaCha20Provider : BaseProvider, ICryptoProvider
{
	/// <summary>
	/// The `public ChaCha20Provider(byte[]? key = null, byte[]? nonce = null)` constructor in the
	/// `ChaCha20Provider` class is a constructor that allows for optional parameters `key` and `nonce` to
	/// be passed when creating an instance of the `ChaCha20Provider` class.
	/// </summary>
	/// <param name="key">
	/// The `key` parameter is an optional byte array that represents the key value to be used for ChaCha20.
	/// </param>
	/// <param name="nonce">
	/// The `nonce` parameter is an optional byte array that represents the nonce value to be used for ChaCha20.
	/// </param>
	public ChaCha20Provider(byte[]? key = null, byte[]? nonce = null)
	{
		if (key != null && nonce != null)
		{
			_keys[KeyType.Key] = key;
			_keys[KeyType.Nonce] = nonce;
		}
	}

	/// <inheritdoc />
	public override Dictionary<KeyType, byte[]> GenerateKeyPairs(int[]? sizes = null)
	{
		var key = new byte[32]; // ChaCha20 uses a 256 bits key (32 bytes)
		var nonce = new byte[12]; // ChaCha20 uses a 96 bits nonce (12 bytes)

		using var rng = RandomNumberGenerator.Create();
		rng.GetBytes(key);
		rng.GetBytes(nonce);

		foreach (var item in new Dictionary<KeyType, byte[]>
		{
			{ KeyType.Key, key },
			{ KeyType.Nonce, nonce }
		})
		{
			_keys[item.Key] = item.Value;
		}

		return _keys;
	}

	/// <inheritdoc />
	public override void ImportKeys(Dictionary<KeyType, byte[]> keys)
	{
		if (!keys.ContainsKey(KeyType.Key) && !keys.ContainsKey(KeyType.Nonce))
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

				if (_keys.Count == 2 && _keys.ContainsKey(KeyType.Key) && _keys.ContainsKey(KeyType.Nonce))
				{
					ImportKeys(_keys);
				}
				break;
			default: throw new ArgumentNullException(nameof(value));
		}
	}
}
