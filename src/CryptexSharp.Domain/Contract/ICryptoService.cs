// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

namespace CryptexSharp.Domain.Contract;

/// <summary>
/// Defines the contract for a cryptographic service that provides methods
/// for encrypting and decrypting data.
/// </summary>
public interface ICryptoService
{
    /// <summary>
    /// Gets the instance of the <see cref="ICryptoProvider"/> responsible for managing cryptographic keys.
    /// </summary>
    /// <value>
    /// An instance of <see cref="ICryptoProvider"/> or <c>null</c> if no key manager is configured.
    /// </value>
    ICryptoProvider Provider { get; }

    /// <summary>
    /// Encrypts the specified plain text data and returns the encrypted result as a string.
    /// </summary>
    /// <param name="data">The plain text data to encrypt.</param>
    /// <returns>A string representing the encrypted data.</returns>
    string Encrypt(string data);

    /// <summary>
    /// Decrypts the specified encrypted data and returns the original plain text.
    /// </summary>
    /// <param name="encryptedData">The encrypted data as a string.</param>
    /// <returns>The decrypted plain text as a string.</returns>
    string Decrypt(string encryptedData);

    /// <summary>
    /// Decrypts the specified encrypted data and returns the original plain text.
    /// </summary>
    /// <param name="encryptedData">The encrypted data as a byte array.</param>
    /// <returns>The decrypted plain text as a string.</returns>
    string Decrypt(byte[] encryptedData);
}
