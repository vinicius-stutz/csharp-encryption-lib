// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

namespace CryptexSharp.Domain.Contract;

/// <summary>
/// The `public interface ICryptexSharpAppService` is defining a contract for a service in the
/// CryptexSharp domain. It includes methods for encryption and decryption of data, as well as a
/// nullable property `KeyManager` of type `ICryptoKeyManager` that allows access to an instance of a
/// key manager implementation. The interface specifies the structure and behavior that classes
/// implementing it must adhere to, providing a blueprint for how encryption and decryption operations
/// should be handled within the CryptexSharp application.
/// </summary>
public interface ICryptoAppService
{
	/// <summary>	
	/// The line `ICryptoService? Service { get; }` in the `ICryptexSharpAppService` interface is defining
	/// a nullable property named `Service` of type `ICryptoService`. This property allows access to an
	/// instance of a service that likely provides cryptographic operations within the CryptexSharp domain.
	/// The `?` symbol after the type `ICryptoService` indicates that the property can be null, meaning it
	/// may or may not have a value assigned to it. This property provides a way to interact with a
	/// cryptographic service implementation within the context of the CryptexSharp application.
	/// </summary>
	ICryptoService Service { get; }

	/// <summary>
	/// The Encrypt function in C# takes a string as input and returns the encrypted version of the data.
	/// </summary>
	/// <param name="data">The `Encrypt` function takes a string `data` as input and returns an encrypted
	/// version of that data.</param>
	string Encrypt(string data);

	/// <summary>
	/// The function Decrypt takes encrypted data as input and returns the decrypted data as output.
	/// </summary>
	/// <param name="encryptedData">The `Decrypt` function takes a string parameter `encryptedData`, which
	/// presumably contains data that has been encrypted and needs to be decrypted. You can pass the
	/// encrypted data as a string to the `Decrypt` function to get the decrypted version of the
	/// data.</param>
	string Decrypt(string encryptedData);

	/// <summary>
	/// The function Decrypt takes in an array of encrypted data and returns the decrypted string.
	/// </summary>
	/// <param name="encryptedData">The `encryptedData` parameter is a byte array that contains the
	/// encrypted data that you want to decrypt.</param>
	string Decrypt(byte[] encryptedData);
}
