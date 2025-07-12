/*
 *  Author			: Gregory King
 *  Date			: 7/12/25
 *  Description		: This program retrieves and decrypts saved Firefox passwords using the NSS library. It searches for the Firefox installation, initializes NSS
 *					  with the profile directory, and reads the encrypted passwords from `logins.json`. The master password is prompted if needed, and the decrypted
 *					  credentials are printed to the console. Note: If you have a password protected profile, you will need to enter the ORIGINAL master password that
 *					  was used to encrypt the profile. This is not the same as the one you use to log into Firefox.
 * 
 */
using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Newtonsoft.Json.Linq;

class Program
{
	public struct SECItem
	{
		public int type;
		public IntPtr data;
		public int len;
	}

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern IntPtr PK11_GetInternalKeySlot();

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern int PK11_NeedLogin(IntPtr slot);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern int PK11_CheckUserPassword(IntPtr slot, string password);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern void PK11_FreeSlot(IntPtr slot);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern int PK11SDR_Decrypt(ref SECItem data, ref SECItem result, IntPtr cx);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern void SECITEM_FreeItem(ref SECItem item, int freeit);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern int PR_GetError();

	[DllImport("kernel32.dll", SetLastError = true)]
	static extern bool SetDllDirectory(string lpPathName);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern int NSS_InitReadWrite(string configDir);

	[DllImport("nss3.dll", CallingConvention = CallingConvention.Cdecl)]
	public static extern void NSS_Shutdown();

	private static string cachedMasterPassword = null;

	static void Main(string[] args)
	{
		
		string firefoxPath = FindFirefoxInstallPath();
		if (firefoxPath == null)
		{
			Console.WriteLine("Firefox installation not found.");
			return;
		}
		SetDllDirectory(firefoxPath);

		string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
		string profiles = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
		var dirs = Directory.GetDirectories(profiles)
			.Where(d => d.EndsWith(".default") || d.EndsWith("-release") || d.EndsWith("-esr")
			
			);

		foreach (var dir in dirs)
		{
			Console.WriteLine($"Using profile: {dir}");
			string logins = Path.Combine(dir, "logins.json");
			if (!File.Exists(logins))
			{
				Console.WriteLine("logins.json not found.");
				continue;
			}

			string cfg = "sql:" + dir;
			Console.WriteLine("Initializing NSS: " + cfg);
			if (NSS_InitReadWrite(cfg) != 0)
			{
				Console.WriteLine("NSS_InitReadWrite failed.");
				continue;
			}

			IntPtr slot = PK11_GetInternalKeySlot();
			if (slot == IntPtr.Zero)
			{
				Console.WriteLine("Failed to get internal key slot.");
				continue;
			}

			try 
			{
				int need = PK11_NeedLogin(slot);
				if (need > 0)
				{
					if (cachedMasterPassword == null)
					{
						Console.Write("Enter Firefox master password: ");
						cachedMasterPassword = ReadPassword();
					}
					int auth = PK11_CheckUserPassword(slot, cachedMasterPassword);
					if (auth != 0)
					{
						Console.WriteLine("Master password authentication failed.");
						cachedMasterPassword = null; // Reset cache on failure
						continue;
					}
				}

				string data = File.ReadAllText(logins);
				var entries = JObject.Parse(data)["logins"];
				foreach (var e in entries)
				{
					string host = e["hostname"]?.ToString() ?? string.Empty;
					string userEnc = e["encryptedUsername"]?.ToString();
					string passEnc = e["encryptedPassword"]?.ToString();
					string user = userEnc != null ? DecryptWithNSS(userEnc, cfg) : string.Empty;
					string pass = passEnc != null ? DecryptWithNSS(passEnc, cfg) : string.Empty;
					Console.WriteLine($"Host: {host}, User: {user}, Password: {pass}");
				}
			}
			finally 
			{
				PK11_FreeSlot(slot);
				NSS_Shutdown();
			}
		}
	}

	static string FindFirefoxInstallPath()
	{
		string[] candidates = new[] {
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Mozilla Firefox"),
			Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Mozilla Firefox")
		};
		foreach (string c in candidates)
		{
			if (File.Exists(Path.Combine(c, "nss3.dll")))
				return c;
		}
		try
		{
			string registryPath = @"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\firefox.exe";
			using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(registryPath))
			{
				if (key != null)
				{
					var exe = key.GetValue(string.Empty) as string;
					if (!string.IsNullOrEmpty(exe))
					{
						string dir = Path.GetDirectoryName(exe);
						if (dir != null && File.Exists(Path.Combine(dir, "nss3.dll")))
							return dir;
					}
				}
			}
		}
		catch
		{
			// ignore
		}
		return null;
	}

	static string DecryptWithNSS(string encB64, string cfg)
	{
		byte[] enc = Convert.FromBase64String(encB64);
	

		IntPtr slot = IntPtr.Zero;
		IntPtr allocatedInData = IntPtr.Zero;
		try
		{
			slot = PK11_GetInternalKeySlot();
			if (slot == IntPtr.Zero)
			{
				return "";
			}

			allocatedInData = Marshal.AllocHGlobal(enc.Length);
			Marshal.Copy(enc, 0, allocatedInData, enc.Length);
			SECItem inItem = new SECItem { type = 0, data = allocatedInData, len = enc.Length };
			
			SECItem outItem = new SECItem();
			int r = PK11SDR_Decrypt(ref inItem, ref outItem, IntPtr.Zero);
			
			if (r != 0 || outItem.len == 0)
			{
				return "";
			}

			byte[] result = new byte[outItem.len];
			Marshal.Copy(outItem.data, result, 0, outItem.len);
			
			if (outItem.data != IntPtr.Zero)
			{
				SECITEM_FreeItem(ref outItem, 0);
			}

			return Encoding.UTF8.GetString(result);
		}
		finally
		{
			if (allocatedInData != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(allocatedInData);
			}
			if (slot != IntPtr.Zero)
			{
				PK11_FreeSlot(slot);
			}
		}
	}

	static string ReadPassword()
	{
		StringBuilder sb = new StringBuilder();
		ConsoleKeyInfo key;
		while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
		{
			if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
				sb.Length--;
			else if (key.Key != ConsoleKey.Backspace)
				sb.Append(key.KeyChar);
		}
		Console.WriteLine();
		return sb.ToString();
	}
}
