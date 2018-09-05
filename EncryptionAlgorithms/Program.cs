using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("Enter algorithm name: 'AES' or 'RSA'");
                string algorithm = Console.ReadLine();

                if (algorithm == "RSA")
                {
                    Console.WriteLine("Input file name for encription: ");
                    string fileNameSource = Console.ReadLine();

                    Console.WriteLine("Input encripted filename:");
                    string fileNameEncrypt = Console.ReadLine();

                    RSA rsa = new RSA();
                    rsa.Encrypt(fileNameSource, fileNameEncrypt, rsa.PUBLIC_KEY_FILE_NAME);

                    Console.WriteLine("File encrypted.");
                    Console.WriteLine("Input file name for decryption: ");

                    string fileNameDecrypt = Console.ReadLine();
                    rsa.Decrypt(fileNameEncrypt, fileNameDecrypt, rsa.PRIVATE_FILE_KEY_NAME);
                }
                else if (algorithm == "AES")
                {
                    Console.WriteLine("Input file name for encryption: ");
                    string fileNameSource = Console.ReadLine();

                    Console.WriteLine("Input encrypted filename:");
                    string fileNameEncypt = Console.ReadLine();

                    AES128 aes128 = new AES128();
                    aes128.GenerateRoundKeys();
                    aes128.EncipherFile(fileNameSource, fileNameEncypt);

                    Console.WriteLine("File encrypted");
                    Console.WriteLine("Input filename for decryption: ");

                    string fileNameDecrypt = Console.ReadLine();
                    aes128.DecipherFile(fileNameEncypt, fileNameDecrypt);

                    Console.WriteLine("File decrypted!");
                }
                else
                {
                    Console.WriteLine("Unknown algorithm.");
                }

                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }
        }
    }
}
