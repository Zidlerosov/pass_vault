using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SecurePasswordStorage
{
    // Convert a string key to a byte array for use with AES
    public static byte[] GetKeyFromString(string keyString)
    {
        using (var sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(keyString));
        }
    }

    public static string EncryptPassword(string password, string keyString)
    {
        byte[] key = GetKeyFromString(keyString);

        using (var aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();
            var iv = aes.IV;

            using (var encryptor = aes.CreateEncryptor(aes.Key, iv))
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (var sw = new StreamWriter(cs))
                        {
                            sw.Write(password);
                        }
                    }

                    var encryptedPassword = ms.ToArray();
                    var combinedIvAndData = new byte[iv.Length + encryptedPassword.Length];
                    Array.Copy(iv, 0, combinedIvAndData, 0, iv.Length);
                    Array.Copy(encryptedPassword, 0, combinedIvAndData, iv.Length, encryptedPassword.Length);

                    return Convert.ToBase64String(combinedIvAndData);
                }
            }
        }
    }

    public static string DecryptPassword(byte[] encryptedDataWithIv, string keyString)
    {
        //byte[] encryptedPass = Convert.FromBase64String(encryptedDataWithIv);
        byte[] key = GetKeyFromString(keyString);

        using (var aes = Aes.Create())
        {
            aes.Key = key;

            byte[] iv = new byte[aes.BlockSize / 8];
            Array.Copy(encryptedDataWithIv, 0, iv, 0, iv.Length);

            int encryptedDataLength = encryptedDataWithIv.Length - iv.Length;
            byte[] encryptedData = new byte[encryptedDataLength];
            Array.Copy(encryptedDataWithIv, iv.Length, encryptedData, 0, encryptedDataLength);

            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                using (var ms = new MemoryStream(encryptedData))
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cs))
                        {
                            try
                            {

                              return  sr.ReadToEnd();
                                    } catch { 
                                return string.Empty;
                            }
                            
                        }
                    }
                }
            }
        }
    }

    public static void WriteEncryptedPasswordToFile(string encryptedPassword, string filePath)
    {
        string[] abstract_lines = new string[1];
        abstract_lines[0] = encryptedPassword;
        File.AppendAllLines(filePath,abstract_lines);
    }

    public static string[] ReadEncryptedPasswordsFromFile(string filePath)
    {
        if (File.Exists(filePath)) {
            return File.ReadAllLines(filePath);
        }
        return null;
    }
}