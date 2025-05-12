using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace EncryptionCore
{
    public static class TpmDecryptionService
    {
        // This is a stub. Real TPM decryption would use Windows CNG/NCrypt APIs.
        // For demo, this just throws NotImplementedException.
        public static void DecryptFileWithTpm(string inputPath, string outputPath)
        {
            // TODO: Implement real TPM decryption logic here.
            throw new NotImplementedException("TPM decryption is not implemented in this demo. You must use Windows CNG/NCrypt APIs and your TPM key handle.");
        }
    }
}
