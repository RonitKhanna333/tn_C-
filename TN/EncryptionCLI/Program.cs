using System;
using System.Security.Cryptography;
using EncryptionCore;

namespace EncryptionCLI
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("\n=== Echelon X .NET CLI ===");
                Console.WriteLine("1. Encrypt folder");
                Console.WriteLine("2. Decrypt folder");
                Console.WriteLine("3. Generate RSA keys");
                Console.WriteLine("4. Exit");
                Console.Write("Select an option: ");
                var input = Console.ReadLine();
                switch (input)
                {
                    case "1":
                        Console.Write("Enter input file path: ");
                        var inFile = Console.ReadLine();
                        Console.Write("Enter output file path: ");
                        var outFile = Console.ReadLine();
                        Console.Write("Enter 32-byte key (hex, leave blank for random): ");
                        var keyHex = Console.ReadLine();
                        byte[] key;
                        if (string.IsNullOrWhiteSpace(keyHex))
                        {
                            key = new byte[32];
                            RandomNumberGenerator.Fill(key);
                            Console.WriteLine($"Generated key: {BitConverter.ToString(key).Replace("-", "")}");
                        }
                        else
                        {
                            key = Convert.FromHexString(keyHex);
                        }
                        byte[] iv = new byte[12];
                        RandomNumberGenerator.Fill(iv);
                        EncryptionService.EncryptFile(inFile, outFile, key, iv);
                        Console.WriteLine("File encrypted.");
                        break;
                    case "2":
                        Console.Write("Enter encrypted file path: ");
                        var encFile = Console.ReadLine();
                        Console.Write("Enter output file path: ");
                        var decFile = Console.ReadLine();
                        Console.Write("Enter 32-byte key (hex): ");
                        var decKeyHex = Console.ReadLine();
                        var decKey = Convert.FromHexString(decKeyHex);
                        EncryptionService.DecryptFile(encFile, decFile, decKey);
                        Console.WriteLine("File decrypted.");
                        break;
                    case "3":
                        Console.Write("Enter private key output path: ");
                        var privPath = Console.ReadLine();
                        Console.Write("Enter public key output path: ");
                        var pubPath = Console.ReadLine();
                        EncryptionService.GenerateRsaKeys(privPath, pubPath);
                        Console.WriteLine("RSA keys generated.");
                        break;
                    case "4":
                        return;
                    default:
                        Console.WriteLine("Invalid option.");
                        break;
                }
            }
        }
    }
}
