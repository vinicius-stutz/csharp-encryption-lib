// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using CryptexSharp.Core.Provider;
using CryptexSharp.Core.Service;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;

namespace CryptexSharp.Application;

public static class CryptexSharpFactory
{
	public static ICryptoAppService CreateAesService(byte[]? key = null, byte[]? iv = null)
	{
		var provider = new AesProvider(key, iv);

		if (key == null || iv == null)
		{
			provider.GenerateKeyPairs();
		}

		var service = new AesCryptoService(provider);
		return new CryptoAppService(service);
	}

	public static ICryptoAppService CreateChaCha20Service(byte[]? key = null, byte[]? nonce = null)
	{
		var provider = new ChaCha20Provider(key, nonce);

		if (key == null || nonce == null)
		{
			provider.GenerateKeyPairs();
		}

		var service = new ChaCha20CryptoService(provider);
		return new CryptoAppService(service);
	}

	public static ICryptoAppService CreateEccService(byte[]? publicKey = null, byte[]? privateKey = null)
	{
		var provider = new EccProvider();

		if (publicKey != null && privateKey != null)
		{
			provider.ImportKeys(new Dictionary<KeyType, byte[]>
			{
				{KeyType.PublicKey, publicKey},
				{KeyType.PrivateKey, privateKey}
			});
		}

		var service = new EccCryptoService(provider);
		return new CryptoAppService(service);
	}
}