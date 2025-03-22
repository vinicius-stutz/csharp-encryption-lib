// Copyright (c) 2025 vinici.us.com. All Rights Reserved.
// Licensed under the MIT license.

using CryptexSharp.Application;
using CryptexSharp.Domain.Contract;
using CryptexSharp.Domain.Enums;

Console.WriteLine(" === CryptexSharp Sample === ");
Console.Write("Please enter any alphanumeric value: ");
var data = Console.ReadLine() ?? "I noticed you didn't write anything...";

Console.WriteLine(" ");
RunAes(data);
Console.WriteLine(" ");
RunChaCha20(data);
Console.WriteLine(" ");
RunEcc(data);

void RunAes(string data)
{
	// Generate a random key and IV
	// 256-bit key - only 16 bytes (128 bits), 24 bytes (192 bits) or 32 bytes (256 bits)
	var key = new byte[32] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }; // 256-bit key
	var iv = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };  // 128-bit IV

	// Create an instance of...
	ICryptoAppService aes = CryptexSharpFactory.CreateAesService(key, iv);

	// Encrypt a sample string
	var encryptedData = aes.Encrypt(data);
	Console.WriteLine($"AES Encrypted Data: {encryptedData}");
	Console.WriteLine($"With key: {Convert.ToBase64String(key)}");
	Console.WriteLine($"With initialization vector: {Convert.ToBase64String(iv)}");

	// Decrypt the encrypted string
	var decryptedData = aes.Decrypt(encryptedData);
	Console.WriteLine($"AES Decrypted Data: {decryptedData}");
}

void RunChaCha20(string data)
{
	// Generate a random key and nonce
	// 256-bit key - only 16 bytes (128 bits), 24 bytes (192 bits) or 32 bytes (256 bits)
	var key = new byte[32] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }; // 256-bit key
	var nonce = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 }; // 64-bit nonce

	// Create an instance of...
	ICryptoAppService chacha20 = CryptexSharpFactory.CreateChaCha20Service(key, nonce);

	// Encrypt a sample string
	var encryptedData = chacha20.Encrypt(data);
	Console.WriteLine($"ChaCha20 Encrypted Data: {encryptedData}");
	Console.WriteLine($"With key: {Convert.ToBase64String(key)}");
	Console.WriteLine($"With nonce: {Convert.ToBase64String(nonce)}");

	// Decrypt the encrypted string
	var decryptedData = chacha20.Decrypt(encryptedData);
	Console.WriteLine($"ChaCha20 Decrypted Data: {decryptedData}");
}

void RunEcc(string data)
{
	ICryptoAppService ecc = CryptexSharpFactory.CreateEccService();

	var publicKey = ecc.Service.Provider.GetKey(KeyType.PublicKey);
	var privateKey = ecc.Service.Provider.GetKey(KeyType.PrivateKey);

	var encryptedData = ecc.Encrypt(data);
	Console.WriteLine($"ECC Encrypted Data: {encryptedData}");
	Console.WriteLine($"With public key: {Convert.ToBase64String(publicKey)}");

	var decryptedData = ecc.Decrypt(encryptedData);
	Console.WriteLine($"ECC Decrypted Data: {decryptedData}");
	Console.WriteLine($"With private key: {Convert.ToBase64String(privateKey)}");
}