// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

namespace CryptexSharp.Domain.Enums;

/// <summary>
/// The `public enum CryptoKeyType` is defining an enumeration type in C# called `CryptoKeyType`. This
/// enumeration represents different types of cryptographic keys, such as PrivateKey, PublicKey, Key, IV
/// (Initialization Vector), and Nonce. Enumerations in C# are used to define a set of named constants,
/// making the code more readable and maintainable by providing a way to represent a group of related
/// constants as a single type.
/// </summary>
public enum KeyType
{
	PrivateKey,
	PublicKey,
	Key,
	IV,
	Nonce
}
