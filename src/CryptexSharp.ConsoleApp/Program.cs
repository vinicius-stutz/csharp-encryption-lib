using CryptexSharp.Service;

// Generate a random key and IV
// 256-bit key - only 16 bytes (128 bits), 24 bytes (192 bits) or 32 bytes (256 bits)
var key = new byte[32] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 }; // 256-bit key

// 128-bit IV - always 16 bytes (128 bits)
var iv = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };  // 128-bit IV

// Create an instance of AesCryptoService
var cryptoService = new AesCryptoService(key, iv);

// Encrypt a sample string
Console.Write("Please enter any alphanumeric value: ");
var data = Console.ReadLine() ?? "I noticed you didn't write anything...";
var encryptedData = cryptoService.Encrypt(data);
Console.WriteLine($"Encrypted Data: {encryptedData}");

// Decrypt the encrypted string
var encryptedBytes = Convert.FromBase64String(encryptedData);
var decryptedData = cryptoService.Decrypt(encryptedBytes);
Console.WriteLine($"Decrypted Data: {decryptedData}");