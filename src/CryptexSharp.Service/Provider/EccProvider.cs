// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using System.Security.Cryptography;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace CryptexSharp.Core.Provider;

/// <summary>
/// The `EccProvider` class is a C# class that extends the `BaseProvider` class and implements the
/// `IProvider` interface. This means that `EccProvider` inherits functionality from `BaseProvider` and
/// also provides its own implementation of the methods defined in the `IProvider` interface.
/// </summary>
public class EccProvider : BaseProvider, ICryptoProvider
{
	private readonly ECDomainParameters _domainParameters;
	private AsymmetricCipherKeyPair? _keyPair;

	/// <summary>	
	/// The `public EccProvider(string secCurveName = "secp256r1")` constructor in the `EccProvider` class
	/// is initializing an instance of the `EccProvider` class with an optional parameter `secCurveName`
	/// which defaults to `"secp256r1"`. This parameter allows the caller to specify the name of the
	/// elliptic curve to be used for generating keys. If no curve name is provided, the default curve used
	/// is `secp256r1`.
	/// </summary>
	public EccProvider(string secCurveName = "secp256r1")
	{
		var x9 = SecNamedCurves.GetByName(secCurveName);
		_domainParameters = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H);
	}

	/// <summary>
	/// The `private byte[] PrivateKey` property in the `EccProvider` class is a getter property that
	/// retrieves the private key bytes from the `_keyPair` field. It first checks if the `_keyPair` is not
	/// null, then casts the private key from the `_keyPair` as an `ECPrivateKeyParameters` object. It then
	/// returns the byte array representation of the private key `D` value using
	/// `privateKey.D.ToByteArray()`. If the `_keyPair` is null, it throws a `CryptographicException`
	/// indicating that no private key has been generated.
	/// </summary>
	private byte[] PrivateKey
	{
		get
		{
			var privateKey = (ECPrivateKeyParameters)(_keyPair?.Private ?? throw new CryptographicException("No Private key has been generated."));
			return privateKey.D.ToByteArray();
		}
	}

	/// <summary>
	/// The `private byte[] PublicKey` property in the `EccProvider` class is a getter property that
	/// retrieves the public key bytes from the `_keyPair` field. It first checks if the `_keyPair` is not
	/// null, then casts the public key from the `_keyPair` as an `ECPublicKeyParameters` object. It then
	/// returns the byte array representation of the public key `Q` value using `publicKey.Q.GetEncoded()`.
	/// If the `_keyPair` is null, it throws a `CryptographicException` indicating that no public key has
	/// been generated.
	/// </summary>
	private byte[] PublicKey
	{
		get
		{
			var publicKey = (ECPublicKeyParameters)(_keyPair?.Public ?? throw new CryptographicException("No Public key has been generated."));
			return publicKey.Q.GetEncoded();
		}
	}

	/// <inheritdoc />
	public override Dictionary<KeyType, byte[]> GenerateKeyPairs(int[]? sizes = null)
	{
		var keyGen = new ECKeyPairGenerator();
		keyGen.Init(new KeyGenerationParameters
		(
			new SecureRandom(),
			256 // 256-bit ECC
		));

		_keyPair = keyGen.GenerateKeyPair();

		return new Dictionary<KeyType, byte[]>
		{
			{ KeyType.PrivateKey, PrivateKey },
			{ KeyType.PublicKey, PublicKey }
		};
	}

	/// <inheritdoc />
	public override byte[] GetKey(KeyType keyType)
	{
		if (!_keys.TryGetValue(keyType, out var value))
		{
			throw new KeyNotFoundException($"Key '{keyType}' not found.");
		}

		return keyType == KeyType.PrivateKey ? PrivateKey : PublicKey;
	}

	/// <inheritdoc />
	public override void ImportKeys(Dictionary<KeyType, byte[]> keys)
	{
		if (!keys.ContainsKey(KeyType.PrivateKey) && !keys.ContainsKey(KeyType.PublicKey))
		{
			throw new CryptographicException("Invalid keys.");
		}

		var privateKey = new ECPrivateKeyParameters
		(
			new BigInteger(keys[KeyType.PrivateKey]),
			_domainParameters
		);

		var publicKey = new ECPublicKeyParameters
		(
			_domainParameters.Curve.DecodePoint(keys[KeyType.PublicKey]),
			_domainParameters
		);

		_keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);
	}

	/// <inheritdoc />
	public override void SetKey(KeyType keyType, byte[] value)
	{
		_keys[keyType] = value ?? throw new ArgumentNullException(nameof(value));

		if (_keys.Count == 2 && _keys.ContainsKey(KeyType.PrivateKey) && _keys.ContainsKey(KeyType.PublicKey))
		{
			ImportKeys(_keys);
		}
	}
}
