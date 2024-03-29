﻿
using System.Text;

public class PasswordGenerator
{
    private const string UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
    private const string Digits = "0123456789";
    private const string SpecialCharacters = "!@#$%^&*()_-+=[{]};:<>|./?";

    private Random random = new Random();

    public string GeneratePassword(int length)
    {
        StringBuilder password = new StringBuilder();
        
            password.Append(GetRandomCharacter(LowercaseLetters)); // Ensure at least one lowercase letter
            password.Append(GetRandomCharacter(UppercaseLetters)); // Ensure at least one uppercase letter
            password.Append(GetRandomCharacter(Digits));           // Ensure at least one digit
            password.Append(GetRandomCharacter(SpecialCharacters));// Ensure at least one special character


            string allChars = UppercaseLetters + LowercaseLetters + Digits + SpecialCharacters;
        for (int i = 4; i < length; i++)
        {

            password.Append(GetRandomCharacter(allChars));
        }

        return ShuffleString(password.ToString());
    }

    private char GetRandomCharacter(string validCharacters)
    {
        int index = random.Next(validCharacters.Length);
        return validCharacters[index];
    }

    private string ShuffleString(string input)
    {
        char[] array = input.ToCharArray();
        for (int i = array.Length - 1; i > 0; i--)
        {
            int j = random.Next(i + 1);
            var temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
        return new String(array);
    }
}

class Program
{
    private static string pass;
    [STAThread]
    static void Main()
    {
        Console.WriteLine("Zida_pass_gen_vault v.1.0\n\n");
        string fileName = "saved_passwords.psw";
        string folderPath = GetFolderPath();
        string fullPath = Path.Combine(folderPath, fileName);

        // Ensure the directory exists
        Directory.CreateDirectory(folderPath);

        // Write to the file (example: write a simple text)
        Console.Write("What is the secret?  ");
        pass = ReadPassword();
        
        PasswordGenerator generator = new PasswordGenerator();
        while (true)
        {
            Console.Write(">");
            string? user_input = Console.ReadLine();
            if (user_input == null) { continue; }
            if (user_input.ToLower() == "exit" || user_input.ToLower() == "ex") { Environment.Exit(0); }
            if (user_input.ToLower().Contains("pull"))
            {
                string[] stored_passwords_raw = SecurePasswordStorage.ReadEncryptedPasswordsFromFile(fullPath);
                if (stored_passwords_raw != null)
                foreach (string passw in stored_passwords_raw) {
                    string name = passw.Split(':')[0];
                    string raw_pass = passw.Split(":")[1];
                    
                    string decrypted_pass = SecurePasswordStorage.DecryptPassword(Convert.FromBase64String(raw_pass), pass);
                    Console.WriteLine(name + ": " + decrypted_pass);
                }
            }
            if (user_input.ToLower().Contains("generate")) {
                int len = int.Parse(user_input.Split(" ")[1]);
                string password = generator.GeneratePassword(len);
                Console.WriteLine($"Generated Password: {password}");
                Console.Write("Save? y/n  ");
                ConsoleKeyInfo consoleKeyInfo = Console.ReadKey(false);
                if (consoleKeyInfo.Key == ConsoleKey.Y)
                {
                    Console.WriteLine();
                    string pass_to_save = SecurePasswordStorage.EncryptPassword(password, pass);
                    Console.Write("Name for pass:  ");
                    string? name = Console.ReadLine();
                    if (name == null) {
                        continue;
                    }
                    string line_for_save = name + ":" + pass_to_save;
                    SecurePasswordStorage.WriteEncryptedPasswordToFile(line_for_save, fullPath);
                    Console.WriteLine("\nPassword saved successfully.");
                }
                if (consoleKeyInfo.Key == ConsoleKey.N) {
                    Console.WriteLine();
                    continue;
                }
                
            }
            if (user_input.ToLower().Contains("add")) { 
                string? password = user_input.Split(' ')[1];
                if (password == null)
                {
                    continue;
                }
                string pass_to_save = SecurePasswordStorage.EncryptPassword(password, pass);
                Console.Write("Name for pass:  ");
                string? name = Console.ReadLine();
                if (name == null)
                {
                    continue;
                }
                string line_for_save = name + ":" + pass_to_save;
                SecurePasswordStorage.WriteEncryptedPasswordToFile(line_for_save, fullPath);
                Console.WriteLine("\nPassword saved successfully.");
            }
            if (user_input.ToLower() == "w" || user_input.ToLower() == "wipe") {
                Console.Clear();
                pass = null;
                Main();
            }

            
            
            

        }
    }

    private static string GetFolderPath()
    {
        string userName = Environment.UserName; // Get the current user's name
        string appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string customFolderPath = Path.Combine(appDataPath, "Zida_Soft");

        return customFolderPath;
    }


    public static string ReadPassword()
    {
        string password = "";
        while (true)
        {
            ConsoleKeyInfo info = Console.ReadKey(true); // true to suppress echoing the character
            if (info.Key == ConsoleKey.Enter)
            {
                break; // Exit loop if Enter is pressed
            }
            else if (info.Key == ConsoleKey.Backspace && password.Length > 0)
            {
                // Remove the last character if Backspace is pressed
                password = password.Substring(0, password.Length - 1);
                // To give a backspace effect on the console, move the cursor back, write a space, and then move back again
                //Console.Write("\b \b");
            }
            else if (!char.IsControl(info.KeyChar))
            {
                password += info.KeyChar; // Add character to password
                // You can optionally write a placeholder character like '*' to indicate a character was entered
                Console.Write("");
            }
        }
        Console.WriteLine();
        return password;
    }
}
