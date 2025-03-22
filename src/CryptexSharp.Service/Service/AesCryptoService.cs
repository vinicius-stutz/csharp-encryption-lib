// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using System.Security.Cryptography;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;

namespace CryptexSharp.Core.Service;

public class AesCryptoService(ICryptoProvider provider) : ICryptoService
{
    /// <inheritdoc/>
    public ICryptoProvider Provider => provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public string Encrypt(string data)
    {
        if (string.IsNullOrEmpty(data))
        {
            throw new ArgumentException($"'{nameof(data)}' cannot be null or empty.", nameof(data));
        }

        var bytes = System.Text.Encoding.UTF8.GetBytes(data);
        using var aes = Aes.Create();
        aes.Key = Provider.GetKey(KeyType.Key);
        aes.IV = Provider.GetKey(KeyType.IV);

        using var encryptor = aes.CreateEncryptor();
        var encryptedData = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
        return Convert.ToBase64String(encryptedData);
    }

    /// <inheritdoc/>
    public string Decrypt(byte[] encryptedData)
    {
        ArgumentNullException.ThrowIfNull(encryptedData);

        using var aes = Aes.Create();
        aes.Key = Provider.GetKey(KeyType.Key);
        aes.IV = Provider.GetKey(KeyType.IV);
        using var decryptor = aes.CreateDecryptor();
        var data = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        return System.Text.Encoding.UTF8.GetString(data);
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