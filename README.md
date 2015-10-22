# csharp.encryption
DLL class libraries for creating and removing encryption in .Net applications

[![Stack Share](http://img.shields.io/badge/tech-stack-0690fa.svg?style=flat)](http://stackshare.io/vinicius-stutz/vin-cius-stutz)

## Usage
This is a very simple script to use. Create an instance of the class CryptService (making using the correct namespace) and call the method, passing the desired parameter provider (see enum CryptProvider).

### Encrypt
```
CryptService crip = new CryptService(CryptProvider.DES);
crip.Key = "MY_KEY";
return crip.Criptografar(text);
```

### Decrypt
```
CryptService crip = new CryptService(CryptProvider.DES);
crip.Key = "MY_KEY";
return crip.Descriptografar(text);
```

FYI: Namespaces, classes and methods are in Portuguese. Feel free to refactor and translate ;)

## MIT License
Read the LICENSE file included with the project.

Enjoy!