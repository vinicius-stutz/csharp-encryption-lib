// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using System.Text;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace CryptexSharp.Core.Service;

public class EccCryptoService(ICryptoProvider provider) : ICryptoService
{
	private const string CipherAlgorithm = "ECIES"; // ECIES (Elliptic Curve Integrated Encryption Scheme)
	private const string EcAlgorithm = "EC";
	private static readonly X9ECParameters _x9params = ECNamedCurveTable.GetByName("secp256k1"); // Example curve
	private static readonly ECDomainParameters _domainParams = new(_x9params.Curve, _x9params.G, _x9params.N, _x9params.H);

	public ICryptoProvider Provider => provider ?? throw new ArgumentNullException(nameof(provider));

	/// <inheritdoc/>
	public string Encrypt(string data)
	{
		var publicKeyBytes = Provider?.GetKey(KeyType.PublicKey);

		if (publicKeyBytes == null || publicKeyBytes.Length == 0)
		{
			throw new InvalidOperationException("Public key is not available.");
		}

		var publicKey = new ECPublicKeyParameters
		(
			EcAlgorithm,
			_x9params.Curve.DecodePoint(publicKeyBytes),
			_domainParams
		);

		var cipher = CipherUtilities.GetCipher(CipherAlgorithm);
		cipher.Init(true, publicKey);

		var plainBytes = Encoding.UTF8.GetBytes(data);
		var encryptedBytes = cipher.DoFinal(plainBytes);

		return Convert.ToBase64String(encryptedBytes);
	}

	/// <inheritdoc/>
	public string Decrypt(byte[] encryptedData)
	{
		var privateKeyBytes = Provider?.GetKey(KeyType.PrivateKey);

		if (privateKeyBytes == null || privateKeyBytes.Length == 0)
		{
			throw new InvalidOperationException("Private key is not available.");
		}

		var privateKey = new ECPrivateKeyParameters(new BigInteger(privateKeyBytes), _domainParams);
		var cipher = CipherUtilities.GetCipher(CipherAlgorithm);
		cipher.Init(false, privateKey);

		var decryptedBytes = cipher.DoFinal(encryptedData);
		return Encoding.UTF8.GetString(decryptedBytes);
	}

	/// <inheritdoc/>
	public string Decrypt(string encryptedData)
	{
		if (string.IsNullOrEmpty(encryptedData))
		{
			throw new ArgumentException($"'{nameof(encryptedData)}' cannot be null or empty.", nameof(encryptedData));
		}

		return Decrypt(Convert.FromBase64String(encryptedData));
	}
}