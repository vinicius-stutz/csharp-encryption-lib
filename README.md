# csharp.encryption
DLL class libraries for creating and removing encryption in .Net applications

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/vinicius-stutz/csharp.encryption?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge) [![Stack Share](http://img.shields.io/badge/tech-stack-0690fa.svg?style=flat)](http://stackshare.io/vinicius-stutz/vin-cius-stutz)

## Usage
This is a very simple script to use. Create an instance of the class CryptService (making using the correct namespace) and call the method, passing the desired parameter provider (see enum CryptProvider).

### Encrypt
```
CryptService crip = new CryptService(CryptProvider.DES);
crip.Key = "MY_KEY";
return crip.Encrypt(text);
```

### Decrypt
```
CryptService crip = new CryptService(CryptProvider.DES);
crip.Key = "MY_KEY";
return crip.Decrypt(text);
```

FYI: The comments in the code are all in Portuguese. Feel free to translate ;)

## MIT License
Read the LICENSE file included with the project.

Enjoy!