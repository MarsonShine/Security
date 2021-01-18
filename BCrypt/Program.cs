using System;
using System.Security.Cryptography;
using static System.Console;

namespace BCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            WriteLine("按 ESC 退出...");
            while (ReadKey().Key != ConsoleKey.Escape)
            {
                CSPRNG();
            }
            WriteLine("退出...");
            BCryptUsage();
            BCryptUsage2();


            ReadLine();
        }

        static void CSPRNG()
        {
            RandomNumberGenerator randomNumberGenerator = new RNGCryptoServiceProvider();
            byte[] rawByteArry = new byte[16];
            randomNumberGenerator.GetBytes(rawByteArry);
            WriteLine(string.Join(',', rawByteArry));
        }

        static void BCryptUsage()
        {
            // 前端传的密码
            string password = "marsonshine123qwe";
            // 利用RNG生成salt
            string salt = Net.BCrypt.GenerateSalt(10, 'a');
            // 慢哈希加密
            string client_bhash = Net.BCrypt.HashPassword(password, salt);

            WriteLine(client_bhash);

        }

        //验证
        static void BCryptUsage2()
        {
            string client_bash = "$2a$10$.rAIuzCI4hBVECwjAbj3xeH6GEmYnL.xdm.gct6yj568EEIP2feKO";
            WriteLine(Net.BCrypt.Verify("marsonshine123qwe", client_bash) ? "验证成功" : "验证失败");
        }
    }
}
