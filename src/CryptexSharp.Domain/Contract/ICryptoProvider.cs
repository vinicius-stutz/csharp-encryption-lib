// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using CryptexSharp.Domain.Enums;

namespace CryptexSharp.Domain.Contract
{
	/// <summary>
	/// Defines the contract for managing cryptographic keys, including importing and exporting private and public keys.
	/// </summary>
	public interface ICryptoProvider
	{
		/// <summary>
		/// The function GenerateKeyPairs generates a dictionary of key pairs with specified sizes. Also set generated values to use.
		/// </summary>
		/// <param name="sizes">The `sizes` parameter is an optional array of integers that specifies the
		/// sizes of the key pairs to be generated. If no sizes are provided, the function will generate key
		/// pairs with default sizes.</param>
		Dictionary<KeyType, byte[]> GenerateKeyPairs(int[]? sizes = null);

		/// <summary>
		/// The GetKey function returns a byte array representing a key based on the specified key type.
		/// </summary>
		/// <param name="KeyType">The `KeyType` parameter in the `GetKey` method is likely an enumeration or a
		/// class that specifies the type of key that you want to retrieve. It could be used to indicate
		/// whether you want to get a symmetric key, an asymmetric key, a secret key, or any other type of
		/// key</param>
		byte[] GetKey(KeyType keyType);

		/// <summary>
		/// The function HasKey checks if a specific key type is present.
		/// </summary>
		/// <param name="KeyType">KeyType is a data type that represents the type of key being checked for in
		/// the HasKey function. It could be a string, integer, or any other data type used to uniquely
		/// identify a key.</param>
		bool HasKey(KeyType keyType);

		/// <summary>
		/// The function ImportKeys takes a dictionary of keys with a specified type and corresponding byte
		/// arrays as values.
		/// </summary>
		/// <param name="keys">The `keys` parameter is a dictionary that maps keys of type `KeyType` to byte
		/// arrays.</param>
		void ImportKeys(Dictionary<KeyType, byte[]> keys);

		/// <summary>
		/// This function sets a key of a specified type with a given byte array value.
		/// </summary>
		/// <param name="KeyType">The `KeyType` parameter is a type that represents the type of key being set.
		/// It could be an enumeration or a specific type defined in your codebase to differentiate between
		/// different types of keys.</param>
		/// <param name="value">The `value` parameter is a byte array that contains the data to be associated
		/// with the specified `keyType`. This data will be stored or processed based on the key type
		/// provided.</param>
		void SetKey(KeyType keyType, byte[] value);
	}
}