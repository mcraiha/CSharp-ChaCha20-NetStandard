using System;
using System.IO;
using System.Diagnostics;
using CSChaCha20;

namespace harness
{
	class Program
	{
		static void Main(string[] args)
		{
			TextWriter errorWriter = Console.Error;

			int limit = 0;

			if(args.Length > 1 && !int.TryParse(args[1], out limit))
			{
				errorWriter.WriteLine($"{args[1]} is not a valid integer");
				return;
			}

			errorWriter.WriteLine("Starting throughput harness...");

			if (limit > 0)
			{
				errorWriter.WriteLine($"Limit is {limit} bytes");
			}
			else
			{
				errorWriter.WriteLine($"No byte limit");
			}

			byte[] key = new byte[32] { 142, 26, 14, 68, 43, 188, 234, 12, 73, 246, 252, 111, 8, 227, 57, 22, 168, 140, 41, 18, 91, 76, 181, 239, 95, 182, 248, 44, 165, 98, 34, 12 };
			byte[] nonce = new byte[12] { 139, 164, 65, 213, 125, 108, 159, 118, 252, 180, 33, 88 };
			uint counter = 1;

			int bufferSize = 1024;

			int bytesProcessed = 0;

			byte[] buffer = new byte[bufferSize];

			Stopwatch stopwatch = new Stopwatch();
			stopwatch.Start();

			using (ChaCha20 forEncrypting = new ChaCha20(key, nonce, counter))
			{
				// Read from input stream as long as there is something
				using (Stream inputStream = Console.OpenStandardInput())
				{
					// Write to output stream
					using (Stream outputStream = Console.OpenStandardOutput())
					{
						int readAmount = inputStream.Read(buffer, 0, bufferSize);
						while (readAmount > 0 && limit > -1)
						{
							outputStream.Write(forEncrypting.EncryptBytes(buffer, readAmount));

							if (limit > 0)
							{
								limit -= readAmount;
							}

							bytesProcessed += readAmount;

							readAmount = inputStream.Read(buffer, 0, bufferSize);
						}
					}
				}
			}

			stopwatch.Stop();
			errorWriter.WriteLine($"Processed {bytesProcessed} bytes in {stopwatch.Elapsed.TotalSeconds} seconds");
		}
	}
}
