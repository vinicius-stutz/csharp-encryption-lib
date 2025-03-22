// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using CryptexSharp.Domain.Contract;

namespace CryptexSharp.Core.Service;

public class HmacCryptoService : ICryptoService
{
	public ICryptoProvider? Provider => throw new NotImplementedException();

	public string Decrypt(byte[] encryptedData)
	{
		throw new NotImplementedException();
	}

	public string Decrypt(string encryptedData)
	{
		throw new NotImplementedException();
	}

	public string Encrypt(string data)
	{
		throw new NotImplementedException();
	}
}