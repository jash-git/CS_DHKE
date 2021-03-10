using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Security.Cryptography;

//https://zh.wikipedia.org/wiki/%E8%BF%AA%E8%8F%B2-%E8%B5%AB%E7%88%BE%E6%9B%BC%E5%AF%86%E9%91%B0%E4%BA%A4%E6%8F%9B
//https://docs.microsoft.com/zh-tw/dotnet/api/system.security.cryptography.ecdiffiehellmancng?view=net-5.0
//https://www.cscec7bjt.com/news/1213473.html

namespace CS_DHKE
{

    class Program
    {
        static void Pause()
        {
            Console.Write("Press any key to continue...");
            Console.ReadKey(true);
        }
        /// <summary>
        /// 安妮的私匙
        /// </summary>
        public static System.Security.Cryptography.CngKey anlikey = null;
        //安妮的公钥
        public static byte[] anlipulicKey = null;
        //鲍勃的私匙
        public static System.Security.Cryptography.CngKey bobkey = null;
        public static byte[] bobpulicKey = null;
        static void Main(string[] args)
        {
            CreateKey();
            AnliSendMessage("The weather today is good");//安妮开始向bob发送消息
            AnliSendMessage("La la la");//安妮开始向bob发送消息
            Pause();
        }

        public static void CreateKey()
        {
            //以ECDsaP256创建私钥
            anlikey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            //根据私钥生成公钥
            anlipulicKey = anlikey.Export(CngKeyBlobFormat.EccPublicBlob);
            //以ECDsaP256创建私钥
            bobkey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256);
            //根据公钥获得私钥
            bobpulicKey = bobkey.Export(CngKeyBlobFormat.EccPublicBlob);
        }

        public static void AnliSendMessage(string message)
        {
            byte[] rowData = Encoding.UTF8.GetBytes(message); //将发送消息转换成二进制格式
            //同annli的私匙生成一个新的随机的密钥对
            using (ECDiffieHellmanCng cng = new ECDiffieHellmanCng(anlikey))
            {
                //通过bob的公钥byte[]获得一个cngKey密钥对象
                using (CngKey bobkey = CngKey.Import(bobpulicKey, CngKeyBlobFormat.EccPublicBlob))
                {
                    //通过anli的密钥对与bob的公钥生成一个对称密钥
                    var sumKey = cng.DeriveKeyMaterial(bobkey);
                    //创建一个对称加密和解密的(AEC)高级算法实现
                    using (var aes = new AesCryptoServiceProvider())
                    {
                        aes.Key = sumKey; //设置对称加密密钥
                        aes.GenerateIV();
                        //生成对称加sh密对象
                        using (ICryptoTransform encryptor = aes.CreateEncryptor())
                        {
                            using (MemoryStream ms = new MemoryStream())
                            {
                                //定义一个加密转换流
                                var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
                                //写入加密初始化向量(IV)
                                ms.Write(aes.IV, 0, aes.IV.Length);
                                //写如传递数据
                                cs.Write(rowData, 0, rowData.Length);
                                cs.Close();//使用完后必须关闭 否则会丢失数据
                                var data = ms.ToArray();
                                //安妮向鲍勃发送加密数据消息 加密数据的二进制数据(）Console.WriteLine;
                                BobReceivesData(data);
                            }
                            aes.Clear();
                        }
                    }
                }
            }
        }

        //Bob接收信息
        public static void BobReceivesData(byte[] data)
        {
            Console.WriteLine("Bob receives it and starts decrypting...");
            byte[] rowData = null;
            //首先读取未加密的初始化向量(IV) 在data里面
            //1.通过对称加密高级算法实现AesCryptoServiceProvider 获得IV的长度
            using (var aes = new AesCryptoServiceProvider())
            {
                var ivlength = aes.BlockSize >> 3;//他的操作块二进制长度转换成byte存储的十进制长度
                byte[] ivdata = new byte[ivlength];
                Array.Copy(data, ivdata, ivlength);
                //同bob的私匙生成一个新的随机的密钥对
                using (ECDiffieHellmanCng cng = new ECDiffieHellmanCng(bobkey))
                {
                    //通过anni的公钥byte[]获得一个cngKey密钥对象
                    using (CngKey anikey = CngKey.Import(anlipulicKey, CngKeyBlobFormat.EccPublicBlob))
                    {
                        //通过anli的密钥对与bob的公钥生成一个对称密钥
                        var sumKey = cng.DeriveKeyMaterial(anikey);
                        aes.Key = sumKey; //设置对称加密密钥
                        aes.IV = ivdata;
                        using (ICryptoTransform decryptor = aes.CreateDecryptor())
                        using (MemoryStream me = new MemoryStream())
                        {
                            //定义一个加密转换流
                            var cs = new CryptoStream(me, decryptor, CryptoStreamMode.Write);
                            cs.Write(data, ivlength, data.Length - ivlength);//将加密信息进行解密
                            cs.Close();//一定要关闭 否则将丢失最后一位数据
                            rowData = me.ToArray();
                            Console.Write("The decryption is successful and the information is: ");
                            Console.WriteLine(Encoding.UTF8.GetString(rowData)+"\n");
                        }
                    }
                }
            }
        }
    }
}
