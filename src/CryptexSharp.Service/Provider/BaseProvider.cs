// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;

namespace CryptexSharp.Core.Provider;

/// <summary>
/// The `public class BaseProvider : IProvider` is defining a class named `BaseProvider` that implements
/// the `IProvider` interface. This means that the `BaseProvider` class must provide implementations for
/// all members defined in the `IProvider` interface. By implementing the `IProvider` interface, the
/// `BaseProvider` class is ensuring that it adheres to a specific contract defined by the interface,
/// which includes methods like `GenerateKeyPairs`, `GetKey`, `HasKey`, `ImportKeys`, and `SetKey`. */
/// </summary>
public class BaseProvider : ICryptoProvider
{
	/// <summary>
	/// The line `protected readonly Dictionary<KeyType, byte[]> _keys = [];` is declaring a protected
	///readonly field named `_keys` of type `Dictionary<KeyType, byte[]>`. This field is initialized as an
	///empty dictionary. The `protected` access modifier means that the field can only be accessed within
	///the class itself and any classes that inherit from it. The `readonly` keyword indicates that the
	///field can only be assigned a value during initialization or in a constructor, and cannot be
	///modified after that.
	/// </summary>
	protected readonly Dictionary<KeyType, byte[]> _keys = [];

	/// <inheritdoc />
	public virtual Dictionary<KeyType, byte[]> GenerateKeyPairs(int[]? sizes = null) => _keys;

	/// <inheritdoc />
	public virtual byte[] GetKey(KeyType keyType)
	{
		if (!_keys.TryGetValue(keyType, out var value))
		{
			throw new KeyNotFoundException($"Key '{keyType}' not found.");
		}

		return value;
	}

	/// <inheritdoc />
	public virtual bool HasKey(KeyType keyType) => _keys.ContainsKey(keyType);

	/// <inheritdoc />
	public virtual void ImportKeys(Dictionary<KeyType, byte[]> keys)
	{
		foreach (var key in keys)
		{
			_keys[key.Key] = key.Value;
		}
	}

	/// <inheritdoc />
	public virtual void SetKey(KeyType keyType, byte[] value) => _keys[keyType] = value;
}
