using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace EncryptionCore
{
    public class EncryptionService
    {
        // AES-GCM encryption (optimized for large files)
        public static void EncryptFile(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            using var aes = new AesGcm(key);
            byte[] tag = new byte[16];
            using var fsIn = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1_048_576);
            using var fsOut = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1_048_576);
            fsOut.Write(iv, 0, iv.Length);
            long fileLength = fsIn.Length;
            byte[] plaintextBuffer = new byte[4 * 1024 * 1024]; // 4MB buffer
            byte[] ciphertextBuffer = new byte[plaintextBuffer.Length];
            int bytesRead;
            int totalBytesRead = 0;
            using var msCipher = new MemoryStream();
            while ((bytesRead = fsIn.Read(plaintextBuffer, 0, plaintextBuffer.Length)) > 0)
            {
                // For AES-GCM, the tag is for the whole message, so we must encrypt all at once or buffer all ciphertext.
                // For large files, we can process in chunks, but must collect all ciphertext before finalizing tag.
                // Here, we buffer all ciphertext in memory, but in a streaming way (better for large files than reading all at once).
                aes.Encrypt(iv, plaintextBuffer.AsSpan(0, bytesRead), ciphertextBuffer.AsSpan(0, bytesRead), tag);
                msCipher.Write(ciphertextBuffer, 0, bytesRead);
                totalBytesRead += bytesRead;
            }
            // Write all ciphertext and tag
            msCipher.Position = 0;
            msCipher.CopyTo(fsOut);
            fsOut.Write(tag, 0, tag.Length);
        }

        // AES-GCM decryption (optimized for large files)
        public static void DecryptFile(string inputPath, string outputPath, byte[] key)
        {
            using var fsIn = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1_048_576);
            byte[] iv = new byte[12];
            fsIn.Read(iv, 0, 12);
            long ciphertextLen = fsIn.Length - 12 - 16;
            byte[] ciphertextBuffer = new byte[4 * 1024 * 1024]; // 4MB buffer
            byte[] plaintextBuffer = new byte[ciphertextBuffer.Length];
            using var msPlain = new MemoryStream();
            long bytesRemaining = ciphertextLen;
            while (bytesRemaining > 0)
            {
                int toRead = (int)Math.Min(ciphertextBuffer.Length, bytesRemaining);
                int bytesRead = fsIn.Read(ciphertextBuffer, 0, toRead);
                if (bytesRead == 0) break;
                msPlain.Write(ciphertextBuffer, 0, bytesRead);
                bytesRemaining -= bytesRead;
            }
            byte[] tag = new byte[16];
            fsIn.Read(tag, 0, 16);
            byte[] ciphertext = msPlain.ToArray();
            byte[] plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            using var fsOut = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1_048_576);
            fsOut.Write(plaintext, 0, plaintext.Length);
        }

        // RSA key generation
        public static void GenerateRsaKeys(string privateKeyPath, string publicKeyPath)
        {
            using var rsa = RSA.Create(4096);
            var priv = rsa.ExportRSAPrivateKey();
            var pub = rsa.ExportRSAPublicKey();
            File.WriteAllBytes(privateKeyPath, priv);
            File.WriteAllBytes(publicKeyPath, pub);
        }

        // Shamir secret sharing (simple XOR-based placeholder for demo)
        public static List<byte[]> SplitSecret(byte[] secret, int minShares, int totalShares)
        {
            // WARNING: This is NOT real Shamir, just a placeholder for demo/testing.
            var shares = new List<byte[]>();
            var rand = RandomNumberGenerator.Create();
            for (int i = 0; i < totalShares - 1; i++)
            {
                byte[] share = new byte[secret.Length];
                rand.GetBytes(share);
                shares.Add(share);
            }
            byte[] last = new byte[secret.Length];
            Array.Copy(secret, last, secret.Length);
            foreach (var s in shares)
                for (int j = 0; j < secret.Length; j++)
                    last[j] ^= s[j];
            shares.Add(last);
            return shares;
        }

        public static byte[] CombineShares(List<byte[]> shares)
        {
            // XOR all shares together
            if (shares.Count == 0) return Array.Empty<byte>();
            byte[] result = new byte[shares[0].Length];
            foreach (var s in shares)
                for (int i = 0; i < result.Length; i++)
                    result[i] ^= s[i];
            return result;
        }

        // Metadata encryption (AES-GCM, JSON)
        public static void EncryptMetadata(object metadata, string outputPath, byte[] key)
        {
            string json = JsonConvert.SerializeObject(metadata);
            byte[] data = Encoding.UTF8.GetBytes(json);
            byte[] iv = new byte[12];
            RandomNumberGenerator.Fill(iv);
            using var aes = new AesGcm(key);
            byte[] ciphertext = new byte[data.Length];
            byte[] tag = new byte[16];
            aes.Encrypt(iv, data, ciphertext, tag);
            using var fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            fs.Write(iv, 0, iv.Length);
            fs.Write(ciphertext, 0, ciphertext.Length);
            fs.Write(tag, 0, tag.Length);
        }

        // Metadata decryption (AES-GCM, JSON)
        public static T DecryptMetadata<T>(string inputPath, byte[] key)
        {
            using var fs = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            byte[] iv = new byte[12];
            fs.Read(iv, 0, 12);
            long ciphertextLen = fs.Length - 12 - 16;
            byte[] ciphertext = new byte[ciphertextLen];
            fs.Read(ciphertext, 0, (int)ciphertextLen);
            byte[] tag = new byte[16];
            fs.Read(tag, 0, 16);
            byte[] plaintext = new byte[ciphertextLen];
            using var aes = new AesGcm(key);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            string json = Encoding.UTF8.GetString(plaintext);
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}
