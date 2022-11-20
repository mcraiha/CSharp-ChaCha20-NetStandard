using System;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using CSChaCha20;
using ChaCha20Cipher;

namespace benchmarks
{
    [MemoryDiagnoser]
    public class OriginalVsAdjusted
    {
        private const int dataLength1 = 64;
        private const int dataLength2 = 1024;
        private const int dataLength3 = 1024*1024;

        private readonly byte[] data1;
        private readonly byte[] data2;
        private readonly byte[] data3;

        private readonly ChaCha20Cipher.ChaCha20Cipher original1 = null;
        private readonly ChaCha20Cipher.ChaCha20Cipher original2 = null;
        private readonly ChaCha20Cipher.ChaCha20Cipher original3 = null;

        private readonly CSChaCha20.ChaCha20 adjusted1 = null;
        private readonly CSChaCha20.ChaCha20 adjusted2 = null;
        private readonly CSChaCha20.ChaCha20 adjusted3 = null;

        private static readonly byte[] key = new byte[32] { 
                                                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
														0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
														0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
														0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
                                                        };
        
        private static readonly byte[] nonce = new byte[12] { 0x00, 0x09, 0x00, 0x00, 0xFF, 0x20, 0x12, 0x00, 0x00, 0x8b, 0x00, 0x02 };
        private static readonly uint counter = 13;

        private byte[] outputForOriginal1;
        private byte[] outputForOriginal2;
        private byte[] outputForOriginal3;

        private byte[] outputForAdjusted1;
        private byte[] outputForAdjusted2;
        private byte[] outputForAdjusted3;

        public OriginalVsAdjusted()
        {
            // Arrays for outputs
            this.outputForOriginal1 = new byte[dataLength1];
            this.outputForOriginal2 = new byte[dataLength2];
            this.outputForOriginal3 = new byte[dataLength3];

            this.outputForAdjusted1 = new byte[dataLength1];
            this.outputForAdjusted2 = new byte[dataLength2];
            this.outputForAdjusted3 = new byte[dataLength3];

            // Generate inputs
            Random rng = new Random(Seed: 1337);

            this.data1 = new byte[dataLength1];
            rng.NextBytes(this.data1);

            this.data2 = new byte[dataLength2];
            rng.NextBytes(this.data2);

            this.data3 = new byte[dataLength3];
            rng.NextBytes(this.data3);

            // Set encrypters
            this.original1 = new ChaCha20Cipher.ChaCha20Cipher(key, nonce, counter);
            this.original2 = new ChaCha20Cipher.ChaCha20Cipher(key, nonce, counter);
            this.original3 = new ChaCha20Cipher.ChaCha20Cipher(key, nonce, counter);

            this.adjusted1 = new CSChaCha20.ChaCha20(key, nonce, counter);
            this.adjusted2 = new CSChaCha20.ChaCha20(key, nonce, counter);
            this.adjusted3 = new CSChaCha20.ChaCha20(key, nonce, counter);
        }

    #region 64 bytes
        [Benchmark]
        public void Original64Bytes() => this.original1.EncryptBytes(this.outputForOriginal1, this.data1, dataLength1);

        [Benchmark]
        public void Adjusted64Bytes() => this.adjusted1.EncryptBytes(this.outputForAdjusted1, this.data1, dataLength1);

    #endregion // 64 bytes

    #region 1024 bytes
        [Benchmark]
        public void Original1024Bytes() => this.original2.EncryptBytes(this.outputForOriginal2, this.data2, dataLength2);

        [Benchmark]
        public void Adjusted1024Bytes() => this.adjusted2.EncryptBytes(this.outputForAdjusted2, this.data2, dataLength2);

    #endregion // 1024 bytes

    #region 1 MiB
        [Benchmark]
        public void Original1MiBBytes() => this.original3.EncryptBytes(this.outputForOriginal3, this.data3, dataLength3);

        [Benchmark]
        public void Adjusted1MibBytes() => this.adjusted3.EncryptBytes(this.outputForAdjusted3, this.data3, dataLength3);

    #endregion // 1 MiB
    }

    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<OriginalVsAdjusted>();
        }
    }
}
