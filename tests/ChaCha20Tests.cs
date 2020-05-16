using NUnit.Framework;
using CSChaCha20;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Tests
{
	public class ChaCha20Tests
	{
		/// <summary>
		/// 32 bytes equals 256 bits
		/// </summary>
		private const int validKeyLength = 32;

		/// <summary>
		/// 12 bytes equals 96 bits
		/// </summary>
		private const int validNonceLength = 12;

		[SetUp]
		public void Setup()
		{
		}

		[Test]
		public void FailedKeyInits()
		{
			// Arrange
			byte[] invalidKey1 = null;
			byte[] invalidKey2 = new byte[0];
			byte[] invalidKey3 = new byte[15];
			byte[] invalidKey4 = new byte[31];

			byte[] validNonce = new byte[12];

			uint validCounter = 1;

			// Act

			// Assert
			Assert.That(() => new ChaCha20(invalidKey1, validNonce, validCounter), Throws.ArgumentNullException);
			Assert.That(() => new ChaCha20(invalidKey2, validNonce, validCounter), Throws.ArgumentException);
			Assert.That(() => new ChaCha20(invalidKey3, validNonce, validCounter), Throws.ArgumentException);
			Assert.That(() => new ChaCha20(invalidKey4, validNonce, validCounter), Throws.ArgumentException);
		}

		[Test]
		public void FailedNonceInits()
		{
			// Arrange
			byte[] validKey = new byte[32];

			byte[] invalidNonce1 = null;
			byte[] invalidNonce2 = new byte[0];
			byte[] invalidNonce3 = new byte[11];

			uint validCounter = 1;

			// Act

			// Assert
			Assert.That(() => new ChaCha20(validKey, invalidNonce1, validCounter), Throws.ArgumentNullException);
			Assert.That(() => new ChaCha20(validKey, invalidNonce2, validCounter), Throws.ArgumentException);
			Assert.That(() => new ChaCha20(validKey, invalidNonce3, validCounter), Throws.ArgumentException);
		}

		[Test]
		public void FailedInputOrOutput()
		{
			// Arrange
			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			uint counter = 1;

			const int lengthOfData = 128;

			byte[] validOutputArray = new byte[lengthOfData];
			byte[] validInputArray = new byte[lengthOfData];
			
			byte[] invalidInput1 = null;
			byte[] invalidOutput1 = null;

			ChaCha20 nullInput = new ChaCha20(key, nonce, counter);
			ChaCha20 nullOutput = new ChaCha20(key, nonce, counter);

			// Act

			// Assert
			Assert.That(() => nullInput.EncryptBytes(validOutputArray, invalidInput1, lengthOfData), Throws.ArgumentNullException);
			Assert.That(() => nullInput.EncryptBytes(invalidOutput1, validInputArray, lengthOfData), Throws.ArgumentNullException);

			Assert.Throws<ArgumentOutOfRangeException>(() => nullInput.EncryptBytes(validOutputArray, validInputArray, -1));
			Assert.Throws<ArgumentOutOfRangeException>(() => nullInput.EncryptBytes(validOutputArray, validInputArray, lengthOfData + 1));
			Assert.Throws<ArgumentOutOfRangeException>(() => nullInput.EncryptBytes(new byte[lengthOfData/2], validInputArray, lengthOfData));

		}

		[Test]
		public void BasicByteArrayEncryptDecryptWorkflow()
		{
			// Arrange
			Random rng = new Random(Seed: 1337);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			byte[] encryptedContent = new byte[lengthOfData];
			byte[] decryptedContent = new byte[lengthOfData];

			uint counter = 1;

			ChaCha20 forEncrypting = null;
			ChaCha20 forDecrypting = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting = new ChaCha20(key, nonce, counter);
			forDecrypting = new ChaCha20(key, nonce, counter);

			forEncrypting.EncryptBytes(encryptedContent, randomContent, lengthOfData);
			forDecrypting.DecryptBytes(decryptedContent, encryptedContent, lengthOfData);

			// Assert
			Assert.AreEqual(lengthOfData, encryptedContent.Length);
			Assert.AreEqual(lengthOfData, decryptedContent.Length);

			CollectionAssert.AreEqual(randomContent, decryptedContent);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent);
		}

		[Test]
		public void BasicByteArrayEncryptDecryptWorkflowNonPowerOfTwo()
		{
			// Arrange
			Random rng = new Random(Seed: 1339);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			const int lengthOfData = 13337;
			byte[] randomContent = new byte[lengthOfData];
			byte[] encryptedContent = new byte[lengthOfData];
			byte[] decryptedContent = new byte[lengthOfData];

			uint counter = 1;

			ChaCha20 forEncrypting = null;
			ChaCha20 forDecrypting = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting = new ChaCha20(key, nonce, counter);
			forDecrypting = new ChaCha20(key, nonce, counter);

			forEncrypting.EncryptBytes(encryptedContent, randomContent, lengthOfData);
			forDecrypting.DecryptBytes(decryptedContent, encryptedContent, lengthOfData);

			// Assert
			Assert.AreEqual(lengthOfData, encryptedContent.Length);
			Assert.AreEqual(lengthOfData, decryptedContent.Length);

			CollectionAssert.AreEqual(randomContent, decryptedContent);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent);
		}

		[Test]
		public void BasicStreamEncryptDecryptWorkflow()
		{
			// Arrange
			Random rng = new Random(Seed: 1338);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			byte[] encryptedContent = new byte[lengthOfData];
			byte[] decryptedContent = new byte[lengthOfData];

			uint counter = 1;

			ChaCha20 forEncrypting = null;
			ChaCha20 forDecrypting = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting = new ChaCha20(key, nonce, counter);
			forDecrypting = new ChaCha20(key, nonce, counter);

			forEncrypting.EncryptStream(new MemoryStream(encryptedContent), new MemoryStream(randomContent));
			forDecrypting.DecryptStream(new MemoryStream(decryptedContent), new MemoryStream(encryptedContent));

			// Assert
			Assert.AreEqual(lengthOfData, encryptedContent.Length);
			Assert.AreEqual(lengthOfData, decryptedContent.Length);

			CollectionAssert.AreEqual(randomContent, decryptedContent);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent);
		}

		[Test]
		public async Task AsyncStreamEncryptDecryptWorkflow()
		{
			// Arrange
			Random rng = new Random(Seed: 1338);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			byte[] encryptedContent = new byte[lengthOfData];
			byte[] decryptedContent = new byte[lengthOfData];

			uint counter = 1;

			ChaCha20 forEncrypting = null;
			ChaCha20 forDecrypting = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting = new ChaCha20(key, nonce, counter);
			forDecrypting = new ChaCha20(key, nonce, counter);

			await forEncrypting.EncryptStreamAsync(new MemoryStream(encryptedContent), new MemoryStream(randomContent));
			await forDecrypting.DecryptStreamAsync(new MemoryStream(decryptedContent), new MemoryStream(encryptedContent));

			// Assert
			Assert.AreEqual(lengthOfData, encryptedContent.Length);
			Assert.AreEqual(lengthOfData, decryptedContent.Length);

			CollectionAssert.AreEqual(randomContent, decryptedContent);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent);
		}

		[Test]
		public void BasicStreamEncryptDecryptWorkflowNonPowerOfTwo()
		{
			// Arrange
			Random rng = new Random(Seed: 138);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			const int lengthOfData = 13339;
			byte[] randomContent = new byte[lengthOfData];
			byte[] encryptedContent = new byte[lengthOfData];
			byte[] decryptedContent = new byte[lengthOfData];

			uint counter = 1;

			ChaCha20 forEncrypting = null;
			ChaCha20 forDecrypting = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting = new ChaCha20(key, nonce, counter);
			forDecrypting = new ChaCha20(key, nonce, counter);

			forEncrypting.EncryptStream(new MemoryStream(encryptedContent), new MemoryStream(randomContent));
			forDecrypting.DecryptStream(new MemoryStream(decryptedContent), new MemoryStream(encryptedContent));

			// Assert
			Assert.AreEqual(lengthOfData, encryptedContent.Length);
			Assert.AreEqual(lengthOfData, decryptedContent.Length);

			CollectionAssert.AreEqual(randomContent, decryptedContent);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent);
		}

		[Test]
		public async Task AsyncStreamEncryptDecryptWorkflowNonPowerOfTwo()
		{
			// Arrange
			Random rng = new Random(Seed: 139);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			const int lengthOfData = 13339;
			byte[] randomContent = new byte[lengthOfData];
			byte[] encryptedContent = new byte[lengthOfData];
			byte[] decryptedContent = new byte[lengthOfData];

			uint counter = 1;

			ChaCha20 forEncrypting = null;
			ChaCha20 forDecrypting = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting = new ChaCha20(key, nonce, counter);
			forDecrypting = new ChaCha20(key, nonce, counter);

			await forEncrypting.EncryptStreamAsync(new MemoryStream(encryptedContent), new MemoryStream(randomContent));
			await forDecrypting.DecryptStreamAsync(new MemoryStream(decryptedContent), new MemoryStream(encryptedContent));

			// Assert
			Assert.AreEqual(lengthOfData, encryptedContent.Length);
			Assert.AreEqual(lengthOfData, decryptedContent.Length);

			CollectionAssert.AreEqual(randomContent, decryptedContent);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent);
		}

		[Test]
		public void TestOverloads()
		{
			// Arrange
			Random rng = new Random(Seed: 1337);

			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			uint counter = 1;

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			byte[] encryptedContent2 = null;
			byte[] decryptedContent2 = null;

			byte[] encryptedContent3 = null;
			byte[] decryptedContent3 = null;

			ChaCha20 forEncrypting1 = null;
			ChaCha20 forDecrypting1 = null;

			ChaCha20 forEncrypting2 = null;
			ChaCha20 forDecrypting2 = null;

			ChaCha20 forEncrypting3 = null;
			ChaCha20 forDecrypting3 = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);
			rng.NextBytes(randomContent);

			forEncrypting1 = new ChaCha20(key, nonce, counter);
			forDecrypting1 = new ChaCha20(key, nonce, counter);

			forEncrypting2 = new ChaCha20(key, nonce, counter);
			forDecrypting2 = new ChaCha20(key, nonce, counter);

			forEncrypting3 = new ChaCha20(key, nonce, counter);
			forDecrypting3 = new ChaCha20(key, nonce, counter);

			forEncrypting1.EncryptBytes(encryptedContent1, randomContent);
			forDecrypting1.DecryptBytes(decryptedContent1, encryptedContent1);

			encryptedContent2 = forEncrypting2.EncryptBytes(randomContent, randomContent.Length);
			decryptedContent2 = forDecrypting2.DecryptBytes(encryptedContent2, encryptedContent2.Length);

			encryptedContent3 = forEncrypting3.EncryptBytes(randomContent);
			decryptedContent3 = forDecrypting3.DecryptBytes(encryptedContent3);

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);

			CollectionAssert.AreEqual(randomContent, decryptedContent2);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent2);

			CollectionAssert.AreEqual(randomContent, decryptedContent3);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent3);
		}

		[Test]
		public void TestStringToUTF8BytesAndBack()
		{
			// Arrange
			Random rng = new Random(Seed: 1337);
			byte[] key = new byte[validKeyLength];
			byte[] nonce = new byte[validNonceLength];

			uint counter = 1;

			string testContent = "this is test content 😊";

			ChaCha20 forEncrypting1 = null;
			ChaCha20 forDecrypting1 = null;

			// Act
			rng.NextBytes(key);
			rng.NextBytes(nonce);

			forEncrypting1 = new ChaCha20(key, nonce, counter);
			forDecrypting1 = new ChaCha20(key, nonce, counter);

			byte[] encryptedContent = forEncrypting1.EncryptString(testContent);
			string decryptedString = forDecrypting1.DecryptUTF8ByteArray(encryptedContent);

			// Assert
			Assert.AreEqual(testContent, decryptedString);
		}

		[Test]
		public void ExistingTestVectors()
		{
			// Actual

			// These vectors are from https://github.com/quartzjer/chacha20/blob/master/test/chacha20.js

			byte[] key1 = new byte[validKeyLength] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			byte[] nonce1 = new byte[validNonceLength] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			uint counter1 = 0;
			const int lengthOfContent1 = 64;
			byte[] content1 = new byte[lengthOfContent1] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			byte[] expected1 = new byte[lengthOfContent1] { 
															0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 
															0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28, 
															0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 
															0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7, 
															0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 
															0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 
															0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 
															0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
															};
			byte[] output1 = new byte[lengthOfContent1];


			byte[] key2 = new byte[validKeyLength] { 
														0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
														0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
														0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
														0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f 
													};
			byte[] nonce2 = new byte[validNonceLength] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
			uint counter2 = 1;
			const int lengthOfContent2 = 114;
			byte[] content2 = new byte[lengthOfContent2] { 
														0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 
														0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
														0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 
														0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
														0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 
														0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
														0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 
														0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
														0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 
														0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
														0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 
														0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
														0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 
														0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
														0x74, 0x2e 
														};
			byte[] expected2 = new byte[lengthOfContent2] { 
															0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
															0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
															0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
															0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
															0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
															0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
															0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
															0x87, 0x4d
															};
			byte[] output2 = new byte[lengthOfContent2];


			byte[] key3 = new byte[validKeyLength] { 
														0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
														0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
														0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
														0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
													};
			byte[] nonce3 = new byte[validNonceLength] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
			uint counter3 = 42;
			const int lengthOfContent3 = 127;
			byte[] content3 = new byte[lengthOfContent3] { 
														0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72, 0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
														0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
														0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20, 0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
														0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
														0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c, 0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
														0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65,
														0x73, 0x2c, 0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
														0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75, 0x74, 0x67, 0x72, 0x61, 0x62, 0x65, 0x2e
														};
			byte[] expected3 = new byte[lengthOfContent3] { 
															0x62, 0xe6, 0x34, 0x7f, 0x95, 0xed, 0x87, 0xa4, 0x5f, 0xfa, 0xe7, 0x42, 0x6f, 0x27, 0xa1, 0xdf,
															0x5f, 0xb6, 0x91, 0x10, 0x04, 0x4c, 0x0d, 0x73, 0x11, 0x8e, 0xff, 0xa9, 0x5b, 0x01, 0xe5, 0xcf,
															0x16, 0x6d, 0x3d, 0xf2, 0xd7, 0x21, 0xca, 0xf9, 0xb2, 0x1e, 0x5f, 0xb1, 0x4c, 0x61, 0x68, 0x71,
															0xfd, 0x84, 0xc5, 0x4f, 0x9d, 0x65, 0xb2, 0x83, 0x19, 0x6c, 0x7f, 0xe4, 0xf6, 0x05, 0x53, 0xeb,
															0xf3, 0x9c, 0x64, 0x02, 0xc4, 0x22, 0x34, 0xe3, 0x2a, 0x35, 0x6b, 0x3e, 0x76, 0x43, 0x12, 0xa6,
															0x1a, 0x55, 0x32, 0x05, 0x57, 0x16, 0xea, 0xd6, 0x96, 0x25, 0x68, 0xf8, 0x7d, 0x3f, 0x3f, 0x77,
															0x04, 0xc6, 0xa8, 0xd1, 0xbc, 0xd1, 0xbf, 0x4d, 0x50, 0xd6, 0x15, 0x4b, 0x6d, 0xa7, 0x31, 0xb1,
															0x87, 0xb5, 0x8d, 0xfd, 0x72, 0x8a, 0xfa, 0x36, 0x75, 0x7a, 0x79, 0x7a, 0xc1, 0x88, 0xd1
															};
			byte[] output3 = new byte[lengthOfContent3];


			ChaCha20 forEncrypting1 = new ChaCha20(key1, nonce1, counter1);
			ChaCha20 forEncrypting2 = new ChaCha20(key2, nonce2, counter2);
			ChaCha20 forEncrypting3 = new ChaCha20(key3, nonce3, counter3);

			// Act
			forEncrypting1.EncryptBytes(output1, content1, lengthOfContent1);
			forEncrypting2.EncryptBytes(output2, content2, lengthOfContent2);
			forEncrypting3.EncryptBytes(output3, content3, lengthOfContent3);

			// Assert
			CollectionAssert.AreEqual(expected1, output1);
			CollectionAssert.AreEqual(expected2, output2);
			CollectionAssert.AreEqual(expected3, output3);
		}
	}
}