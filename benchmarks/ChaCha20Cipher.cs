/*
 * Copyright (c) 2015, 2018 Scott Bennett
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

using System;
using System.Text;

namespace ChaCha20Cipher {
	public sealed class ChaCha20Cipher : IDisposable {
		/// <summary>
		/// The ChaCha20 state (aka "context")
		/// </summary>
		private uint[] state;

		/// <summary>
		/// Determines if the objects in this class have been disposed of. Set to
		/// true by the Dispose() method.
		/// </summary>
		private bool isDisposed;

		/// <summary>
		/// Set up a new ChaCha20 state. The lengths of the given parameters are
		/// checked before encryption happens.
		/// </summary>
		/// <remarks>
		/// See <a href="https://tools.ietf.org/html/rfc7539#page-10">ChaCha20 Spec Section 2.4</a>
		/// for a detailed description of the inputs.
		/// </remarks>
		/// <param name="key">
		/// A 32-byte (256-bit) key, treated as a concatenation of eight 32-bit
		/// little-endian integers
		/// </param>
		/// <param name="nonce">
		/// A 12-byte (96-bit) nonce, treated as a concatenation of three 32-bit
		/// little-endian integers
		/// </param>
		/// <param name="counter">
		/// A 4-byte (32-bit) block counter, treated as a 32-bit little-endian integer
		/// </param>
		public ChaCha20Cipher(byte[] key, byte[] nonce, uint counter) {
			this.state = new uint[16];
			this.isDisposed = false;

			KeySetup(key);
			IvSetup(nonce, counter);
		}

		/// <summary>
		/// The ChaCha20 state (aka "context"). Read-Only.
		/// </summary>
		public uint[] State {
			get {
				return this.state;
			}
		}

		/// <summary>
		/// Set up the ChaCha state with the given key. A 32-byte key is required
		/// and enforced.
		/// </summary>
		/// <param name="key">
		/// A 32-byte (256-bit) key, treated as a concatenation of eight 32-bit
		/// little-endian integers
		/// </param>
		private void KeySetup(byte[] key) {
			if (key == null) {
				throw new ArgumentNullException("Key is null");
			}
			if (key.Length != 32) {
				throw new ArgumentException(
					$"Key length must be 32. Actual: {key.Length}"
				);
			}

			// These are the same constants defined in the reference implementation.
			// http://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
			byte[] sigma = Encoding.ASCII.GetBytes("expand 32-byte k");
			byte[] tau   = Encoding.ASCII.GetBytes("expand 16-byte k");

			state[4] = Util.U8To32Little(key, 0);
			state[5] = Util.U8To32Little(key, 4);
			state[6] = Util.U8To32Little(key, 8);
			state[7] = Util.U8To32Little(key, 12);

			byte[] constants = (key.Length == 32) ? sigma : tau;
			int keyIndex = key.Length - 16;

			state[8]  = Util.U8To32Little(key, keyIndex + 0);
			state[9]  = Util.U8To32Little(key, keyIndex + 4);
			state[10] = Util.U8To32Little(key, keyIndex + 8);
			state[11] = Util.U8To32Little(key, keyIndex + 12);

			state[0] = Util.U8To32Little(constants, 0);
			state[1] = Util.U8To32Little(constants, 4);
			state[2] = Util.U8To32Little(constants, 8);
			state[3] = Util.U8To32Little(constants, 12);
		}

		/// <summary>
		/// Set up the ChaCha state with the given nonce (aka Initialization Vector
		/// or IV) and block counter. A 12-byte nonce and a 4-byte counter are
		/// required.
		/// </summary>
		/// <param name="nonce">
		/// A 12-byte (96-bit) nonce, treated as a concatenation of three 32-bit
		/// little-endian integers
		/// </param>
		/// <param name="counter">
		/// A 4-byte (32-bit) block counter, treated as a 32-bit little-endian integer
		/// </param>
		private void IvSetup(byte[] nonce, uint counter) {
			if (nonce == null) {
				// There has already been some state set up. Clear it before exiting.
				Dispose();
				throw new ArgumentNullException("Nonce is null");
			}
			if (nonce.Length != 12) {
				// There has already been some state set up. Clear it before exiting.
				Dispose();
				throw new ArgumentException(
					$"Nonce length must be 12. Actual: {nonce.Length}"
				);
			}

			state[12] = counter;
			state[13] = Util.U8To32Little(nonce, 0);
			state[14] = Util.U8To32Little(nonce, 4);
			state[15] = Util.U8To32Little(nonce, 8);
		}

		/// <summary>
		/// Encrypt an arbitrary-length plaintext message (input), writing the
		/// resulting ciphertext to the output buffer. The number of bytes to read
		/// from the input buffer is determined by numBytes.
		/// </summary>
		/// <param name="output"></param>
		/// <param name="input"></param>
		/// <param name="numBytes"></param>
		public void EncryptBytes(byte[] output, byte[] input, int numBytes) {
			if (isDisposed) {
				throw new ObjectDisposedException("state",
					"The ChaCha state has been disposed");
			}
			if (numBytes < 0 || numBytes > input.Length) {
				throw new ArgumentOutOfRangeException("numBytes",
					"The number of bytes to read must be between [0..input.Length]");
			}

			uint[] x = new uint[16];    // Working buffer
			byte[] tmp = new byte[64];  // Temporary buffer
			int outputOffset = 0;
			int inputOffset = 0;

			while (numBytes > 0) {
				for (int i = 16; i-- > 0; ) {
					x[i] = this.state[i];
				}

				for (int i = 20; i > 0; i -= 2) {
					QuarterRound(x, 0, 4,  8, 12);
					QuarterRound(x, 1, 5,  9, 13);
					QuarterRound(x, 2, 6, 10, 14);
					QuarterRound(x, 3, 7, 11, 15);

					QuarterRound(x, 0, 5, 10, 15);
					QuarterRound(x, 1, 6, 11, 12);
					QuarterRound(x, 2, 7,  8, 13);
					QuarterRound(x, 3, 4,  9, 14);
				}

				for (int i = 16; i-- > 0; ) {
					Util.ToBytes(tmp, Util.Add(x[i], this.state[i]), 4 * i);
				}

				this.state[12] = Util.AddOne(state[12]);
				if (this.state[12] <= 0) {
					/* Stopping at 2^70 bytes per nonce is the user's responsibility */
					this.state[13] = Util.AddOne(state[13]);
				}

				if (numBytes <= 64) {
					for (int i = numBytes; i-- > 0; ) {
						output[i + outputOffset] = (byte) (input[i + inputOffset] ^ tmp[i]);
					}

					return;
				}

				for (int i = 64; i-- > 0; ) {
					output[i + outputOffset] = (byte) (input[i + inputOffset] ^ tmp[i]);
				}

				numBytes -= 64;
				outputOffset += 64;
				inputOffset += 64;
			}
		}

		/// <summary>
		/// The ChaCha Quarter Round operation. It operates on four 32-bit unsigned
		/// integers within the given buffer at indices a, b, c, and d.
		/// </summary>
		/// <remarks>
		/// The ChaCha state does not have four integer numbers: it has 16.  So
		/// the quarter-round operation works on only four of them -- hence the
		/// name.  Each quarter round operates on four predetermined numbers in
		/// the ChaCha state.
		/// See <a href="https://tools.ietf.org/html/rfc7539#page-4">ChaCha20 Spec Sections 2.1 - 2.2</a>.
		/// </remarks>
		/// <param name="x">A ChaCha state (vector). Must contain 16 elements.</param>
		/// <param name="a">Index of the first number</param>
		/// <param name="b">Index of the second number</param>
		/// <param name="c">Index of the third number</param>
		/// <param name="d">Index of the fourth number</param>
		public static void QuarterRound(uint[] x, uint a, uint b, uint c, uint d) {
			if (x == null) {
				throw new ArgumentNullException("Input buffer is null");
			}
			if (x.Length != 16) {
				throw new ArgumentException();
			}

			x[a] = Util.Add(x[a], x[b]); x[d] = Util.Rotate(Util.XOr(x[d], x[a]), 16);
			x[c] = Util.Add(x[c], x[d]); x[b] = Util.Rotate(Util.XOr(x[b], x[c]), 12);
			x[a] = Util.Add(x[a], x[b]); x[d] = Util.Rotate(Util.XOr(x[d], x[a]),  8);
			x[c] = Util.Add(x[c], x[d]); x[b] = Util.Rotate(Util.XOr(x[b], x[c]),  7);
		}

		/// <summary>
		/// Currently not used.
		/// </summary>
		/// <param name="output"></param>
		/// <param name="input"></param>
		public static void ChaCha20BlockFunction(byte[] output, uint[] input) {
			if (input == null || output == null) {
				throw new ArgumentNullException();
			}
			if (input.Length != 16 || output.Length != 64) {
				throw new ArgumentException();
			}

			uint[] x = new uint[16];  // Working buffer

			for (int i = 16; i-- > 0; ) {
				x[i] = input[i];
			}

			for (int i = 20; i > 0; i -= 2) {
				QuarterRound(x, 0, 4, 8, 12);
				QuarterRound(x, 1, 5, 9, 13);
				QuarterRound(x, 2, 6, 10, 14);
				QuarterRound(x, 3, 7, 11, 15);

				QuarterRound(x, 0, 5, 10, 15);
				QuarterRound(x, 1, 6, 11, 12);
				QuarterRound(x, 2, 7, 8, 13);
				QuarterRound(x, 3, 4, 9, 14);
			}

			for (int i = 16; i-- > 0; ) {
				Util.ToBytes(output, Util.Add(x[i], input[i]), 4 * i);
			}
		}

		#region Destructor and Disposer

		/// <summary>
		/// Clear and dispose of the internal state. The finalizer is only called
		/// if Dispose() was never called on this cipher.
		/// </summary>
		~ChaCha20Cipher() {
			Dispose(false);
		}

		/// <summary>
		/// Clear and dispose of the internal state. Also request the GC not to
		/// call the finalizer, because all cleanup has been taken care of.
		/// </summary>
		public void Dispose() {
			Dispose(true);
			/*
			 * The Garbage Collector does not need to invoke the finalizer because
			 * Dispose(bool) has already done all the cleanup needed.
			 */
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// This method should only be invoked from Dispose() or the finalizer.
		/// This handles the actual cleanup of the resources.
		/// </summary>
		/// <param name="disposing">
		/// Should be true if called by Dispose(); false if called by the finalizer
		/// </param>
		private void Dispose(bool disposing) {
			if (!isDisposed) {
				if (disposing) {
					/* Cleanup managed objects by calling their Dispose() methods */
				}

				/* Cleanup any unmanaged objects here */
				if (state != null) {
					Array.Clear(state, 0, state.Length);
				}

				state = null;
			}

			isDisposed = true;
		}

		#endregion
	}
}
