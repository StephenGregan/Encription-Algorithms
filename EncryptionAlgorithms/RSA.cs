using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionAlgorithms
{
    public class RSA
    {
        public string PUBLIC_KEY_FILE_NAME = "./public_key.txt";
        public string PRIVATE_FILE_KEY_NAME = "./private_key.txt";

        private Random random;

        private Int64[] simpleList;

        public void GenerateKeys()
        {
            random = new Random((int)DateTime.Now.Ticks % Int32.MaxValue);
            simpleList = GenerateSimpleNumbersList(1000);

            Int64 P = GenerateRandomNumberInt16();
            Int64 Q = P;

            while (P == Q)
            {
                Q = GenerateRandomNumberInt16();
            }

            Int64 N = P * Q;
            Int64 M = (P - 1) * (Q - 1);
            Int64 E = 0;

            do
            {
                E = GenerateRandomNumberInt32();
            }
            while (EuclidsAlgorithm(E, M) != 1);

            Int64 D = ExtendedEuclid(E, M);
            // How this is written is personal preference.
            // First way.
            RSAKey publicKey = new RSAKey();
            publicKey.Data = E;
            publicKey.N = N;

            // How this is written is personal preference.
            // Second way.
            RSAKey privateKey = new RSAKey();
            privateKey.Data = D;
            privateKey.N = N;

            KeyFileWriter.WriteKey(publicKey, PUBLIC_KEY_FILE_NAME);
            KeyFileWriter.WriteKey(privateKey, PRIVATE_FILE_KEY_NAME);

        }

        private Int64[] GenerateSimpleNumbersList(int arraySize)
        {
            Int64[] simpleList = new Int64[arraySize];
            Int64 i = 0;
            Int64 number = 2;
            bool IsSimpleNumber = true;

            while (i < arraySize)
            {
                IsSimpleNumber = true;

                for (Int64 j = 2; j < Math.Sqrt(number); j++)
                {
                    if (number % j == 0)
                    {
                        IsSimpleNumber = false;
                        break;
                    }
                }

                if (IsSimpleNumber)
                {
                    simpleList[i] = number;
                    i++;
                }

                number++;
            }

            return simpleList;
        }

        private Int16 GenerateRandomNumberInt16()
        {
            Int16 number = 0;
            
            do
            {
                number = (Int16) random.Next(1, Int16.MaxValue);
            }
            while (!IsSimpleNumber(number));

            return number;
        }

        private Int32 GenerateRandomNumberInt32()
        {
            Int32 number = 0;

            do
            {
                number = (Int32)random.Next(1, Int32.MaxValue);
            }
            while (!IsSimpleNumber(number));

            return number;
        }

        private bool IsSimpleNumber(Int64 number)
        {
            for (int i = 0; i < simpleList.Length; i++)
            {
                if (number % simpleList[i] == 0)
                {
                    return false;
                }
            }

            return true;
        }

        private Int64 GCD(Int64 a, Int64 b, out Int64 x, out Int64 y)
        {
            if (a == 0)
            {
                x = 0;
                y = 1;
                return b;
            }

            Int64 x1, y1;
            Int64 d = GCD(b % a, a, out x1, out y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }

        private Int64 ExtendedEuclid(Int64 a, Int64 n)
        {
            Int64 x, y;
            Int64 g = GCD(a, n, out x, out y);

            if (g != 1)
            {
                throw new ArgumentException();
            }

            return (x % n + n) % n;
        }

        public void Encrypt(string sourceFileName, string destinationFileName, string keyFileName)
        {
            RSAKey publickey = KeyFileReader.ReadKey(keyFileName);
            FileStream sourceFileStream = new FileStream(sourceFileName, FileMode.Open);
            FileStream destinationFileStream = new FileStream(destinationFileName, FileMode.Create);

            using (BinaryWriter binaryWriter = new BinaryWriter(destinationFileStream))
            {
                using (BinaryReader binaryReader = new BinaryReader(sourceFileStream))
                {
                    while (binaryReader.BaseStream.Position != binaryReader.BaseStream.Length)
                    {
                        binaryWriter.Write(PowModFast(Convert.ToInt64(binaryReader.ReadByte()), publicKey.Data, publicKey.N));
                    }
                }
            }

            sourceFileStream.Close();
            destinationFileStream.Close();
        }

        public void Decrypt(string sourceFileName, string destinationFileName, string keyFileName)
        {
            RSAKey privateKey = KeyFileReader.ReadKey(keyFileName);
            FileStream sourceFileStream = new FileStream(sourceFileName, FileMode.Open);
            FileStream destinationFileStream = new FileStream(destinationFileName, FileMode.Create);

            using (BinaryWriter binaryWriter = new BinaryWriter(destinationFileStream))
            {
                using (BinaryReader binaryReader = new BinaryReader(sourceFileStream))
                {
                    while (binaryReader.BaseStream.Position != binaryWriter.BaseStream.Length)
                    {
                        binaryWriter.Write(Convert.ToByte(PowModFast((int)binaryReader.ReadInt64(), privateKey.Data, privateKey.N)));
                    }
                }
            }

            sourceFileStream.Close();
            destinationFileStream.Close();
        }

        private Int64 EuclidsAlgorithm(Int64 firstNumber, Int64 secondNumber)
        {
            Int64 tmpFirstNumber = firstNumber;
            Int64 tmpSecondNumber = secondNumber;

            while (tmpFirstNumber != 0 && tmpSecondNumber != 0)
            {
                if (tmpFirstNumber > tmpSecondNumber)
                {
                    tmpFirstNumber = tmpFirstNumber % tmpSecondNumber;
                }
                else
                {
                    tmpSecondNumber = tmpSecondNumber & tmpFirstNumber;
                }
            }

            return tmpFirstNumber + tmpSecondNumber;
        }

        private Int64 PowModFast(int symbol, Int64 key, Int64 n)
        {
            Int64 k = key;
            Int64 r = 1;
            Int64 tmpSymbol = symbol;

            while (k > 0)
            {
                if (k % 2 == 1)
                {
                    r = (r * tmpSymbol) % n;
                }

                tmpSymbol = (tmpSymbol * tmpSymbol) % n;
                k = k / 2;
            }

            return r;
        }
    }
}
