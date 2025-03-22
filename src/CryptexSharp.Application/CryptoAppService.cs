// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using CryptexSharp.Domain.Contract;

namespace CryptexSharp.Application;

/// <inheritdoc cref="ICryptoAppService"/>
public class CryptoAppService(ICryptoService service) : ICryptoAppService
{
	private readonly ICryptoService _service = service;

	/// <inheritdoc />
	public ICryptoService? Service => _service ?? throw new ArgumentNullException(nameof(_service));

	/// <inheritdoc />
	public string Decrypt(string encryptedData) => _service.Decrypt(encryptedData);

	/// <inheritdoc />
	public string Decrypt(byte[] encryptedData) => _service.Decrypt(encryptedData);

	/// <inheritdoc />
	public string Encrypt(string data) => _service.Encrypt(data);
}
