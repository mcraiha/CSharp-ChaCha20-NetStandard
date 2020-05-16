# CSharp-ChaCha20-NetStandard

Managed .Net Standard 2.0 compatible [ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) cipher written in C#

## Build status
[![Build Status](https://travis-ci.com/mcraiha/CSharp-ChaCha20-NetStandard.svg?branch=master)](https://travis-ci.com/mcraiha/CSharp-ChaCha20-NetStandard)

## Why?

Because I needed this for my personal project

## Origin

**Scott Bennett** wrote C# implementation called [ChaCha20-csharp](https://github.com/sbennett1990/ChaCha20-csharp), which works as base for my code. That is why the license is same for both projects 

## Documentation

[Docs](https://mcraiha.github.io/CSharp-ChaCha20-NetStandard/api/index.html)

## How do I use this?

Either copy the [CSChaCha20.cs](src/CSChaCha20.cs) to your project or use [LibChaCha20](https://www.nuget.org/packages/LibChaCha20/) nuget package 

Then do code like
```csharp
using CSChaCha20;

byte[] mySimpleTextAsBytes = Encoding.ASCII.GetBytes("Plain text I want to encrypt");

// Do not use these key and nonce values in your own code!
byte[] key = new byte[32] { 142, 26, 14, 68, 43, 188, 234, 12, 73, 246, 252, 111, 8, 227, 57, 22, 168, 140, 41, 18, 91, 76, 181, 239, 95, 182, 248, 44, 165, 98, 34, 12 };
byte[] nonce = new byte[12] { 139, 164, 65, 213, 125, 108, 159, 118, 252, 180, 33, 88 };
uint counter = 1;

// Encrypt
ChaCha20 forEncrypting = new ChaCha20(key, nonce, counter);
byte[] encryptedContent = new byte[mySimpleTextAsBytes.Length];
forEncrypting.EncryptBytes(encryptedContent, mySimpleTextAsBytes);

// Decrypt
ChaCha20 forDecrypting = new ChaCha20(key, nonce, counter);
byte[] decryptedContent = new byte[encryptedContent.Length];
forDecrypting.DecryptBytes(decryptedContent, encryptedContent);

```

You can try out the code in [.NET Fiddle](https://dotnetfiddle.net/4D6E5Z)

## Test cases

You can run test cases by moving to **tests** folder and running following command
```bash
dotnet test
```

## Benchmarks

You can run benchmarks (which compare this implementation to the original version) by moving to **benchmarks** folder and running following command
```bash
dotnet run -c Release
```

there are three different input sizes (64 bytes, 1024 bytes and 1 MiB) and comparisons are done between the original version (made by Scott Bennett) and this project

## License

All the code is licensed under [ISC License](LICENSE)