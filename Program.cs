using ICSharpCode.SharpZipLib.GZip;
using ICSharpCode.SharpZipLib.Tar;
using Npgsql;
using NpgsqlTypes;
using Serilog;
using Serilog.Core;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace WindowsPostgresBackup
{
    class Program
    {
        private static Logger logger;
        private static bool consoleMode;

        static void Main(string[] args)
        {
            consoleMode = args.Contains("--console");

            if ((args.Length == 0) || args.Contains("--help"))
            {
                PrintHelp();
                ShowExit();
                return;
            }

            InitLogger(args);

            if (args.Contains("--makepwd"))
            {
                MakePassword();
                return;
            }

            logger.Information("START");
            var watch = new Stopwatch();
            watch.Start();
            try
            {
                var mode = ReadParamValue(args, "mode");
                if (mode == null)
                {
                    logger.Error("--mode parameter is required. Use --help to review parameters and options");
                    ShowExit();
                    return;
                }

                if (!Regex.Match(mode, "^(backup|restore)$", RegexOptions.IgnoreCase).Success)
                {
                    logger.Error("--mode parameter is not valid. Use --help to review parameters and options");
                    ShowExit();
                    return;
                }

                //postgresql-x64-10
                if (mode == "backup")
                {
                    if (!PerformBackup(args))
                    {
                        logger.Error("Something went wrog during backup process");
                    }
                    else
                    {
                        logger.Information("Backup process ends successfully");
                    }
                }
                else
                {
                    if (!PerformRestore(args))
                    {
                        logger.Error("Something went wrog during restore process");
                    }
                    else
                    {
                        logger.Information("Restore process ends successfully");
                    }
                }
            }
            finally
            {
                watch.Stop();
                logger.Information($"END ({watch.Elapsed.TotalSeconds.ToString("N2")}s)");
                ShowExit();
            }
        }

        private static bool PerformRestore(string[] args)
        {
            var service = ReadParamValue(args, "service");
            var host = ReadParamValue(args, "host");
            var path = ReadParamValue(args, "path");
            var wal = ReadParamValue(args, "wal");
            var rttime = ReadParamValue(args, "rttime");
            var data = ReadParamValue(args, "data");
            var sufix = ReadParamValue(args, "sufix");

            if (String.IsNullOrWhiteSpace(service) ||
                String.IsNullOrWhiteSpace(wal) ||
                String.IsNullOrWhiteSpace(path) ||
                String.IsNullOrWhiteSpace(data))
            {
                logger.Error("Parameters service, path, wal and data are required for Backup. Use --help to review parameters and options.");
                return false;
            }

            if (consoleMode)
            {
                Console.WriteLine();
                Console.Write($"Restore operation will destroy current files in '{data}' directory. Before continue you must be sure.");
                string @continue;
                do
                {
                    Console.WriteLine();
                    Console.Write($"Continue? [Y]es or [N]ot: ");
                    @continue = Console.ReadKey().KeyChar.ToString().ToLower();
                    if ((new[] { "y", "n" }).Contains(@continue))
                    {
                        break;
                    }
                } while (true);
                Console.WriteLine();

                if (@continue == "n")
                {
                    logger.Information($"Restore stopped by user.");
                    return false;
                }
            }

            logger.Information($"Stop Postgres service: {service}");
            try
            {
                ServiceController srvCtroler = new ServiceController(service, host ?? "localhost");
                if (srvCtroler.Status != ServiceControllerStatus.Stopped)
                {
                    srvCtroler.Stop();
                }
                while (srvCtroler.Status != ServiceControllerStatus.Stopped)
                {
                    if (consoleMode)
                    {
                        Console.Write(".");
                    }
                    Thread.Sleep(1000);
                    srvCtroler.Refresh();
                }
                if (consoleMode)
                {
                    Console.WriteLine();
                }
                logger.Warning($"Postgres service: {service} is stopped");
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Unhandled error during stopping Postgres service");
                return false;
            }

            logger.Information($"Clean data directory: {data}");
            try
            {
                var files = Directory.GetFiles(data, "*.*", SearchOption.AllDirectories);
                for (int f = files.Length - 1; f >= 0; f--)
                {
                    File.Delete(files[f]);
                    logger.Debug($"  - deleted: {files[f]}");
                }
                logger.Warning($"Cleaned data directory: {data}");
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Unhandled error during deleting data directory before restore");
                return false;
            }

            // Restore base
            var targzBase = Path.Combine(path, "base.tar.gz");
            if (!String.IsNullOrWhiteSpace(sufix))
            {
                targzBase = Path.Combine(path, $"base_{sufix}.tar.gz");
            }
            logger.Information($"Extract '{targzBase}' to: '{data}'");
            try
            {
                ExtractTarGz(targzBase, data);
                logger.Information($"'{targzBase}' is restored");
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"Unhandled error during extracting '{targzBase}' to '{data}' directory");
                return false;
            }

            // Restore pg_wal
            var targzWal = Path.Combine(path, "pg_wal.tar.gz");
            if (!String.IsNullOrWhiteSpace(sufix))
            {
                targzWal = Path.Combine(path, $"pg_wal_{sufix}.tar.gz");
            }
            var walPath = Path.Combine(data, "pg_wal");
            logger.Information($"Extract '{targzWal}' to: '{walPath}'");
            try
            {
                ExtractTarGz(targzWal, walPath);
                logger.Information($"{targzWal} is restored");
            }
            catch (Exception ex)
            {
                logger.Error(ex, $"Unhandled error during extracting '{targzWal}' to '{walPath}'");
                return false;
            }

            logger.Information("Create recovery.conf file");
            try
            {
                using (var recoveryFile = new StreamWriter(Path.Combine(data, "recovery.conf"), false))
                {
                    recoveryFile.WriteLine($"restore_command = 'copy \"{Path.Combine(wal, "%f").Replace("\\", "\\\\")}\" \"%p\"'");
                    if (!String.IsNullOrEmpty(rttime))
                    {
                        recoveryFile.WriteLine($"recovery_target_time = '{rttime}'");
                        recoveryFile.WriteLine($"recovery_target_inclusive = false");
                    }
                }
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Unhandled error during creating recovery.conf file");
                return false;
            }

            logger.Information($"Start Postgres service: {service}");
            try
            {
                ServiceController srvCtroler = new ServiceController(service, host ?? "localhost");
                srvCtroler.Start();
                while (srvCtroler.Status != ServiceControllerStatus.Running)
                {
                    if (consoleMode)
                    {
                        Console.Write(".");
                    }
                    Thread.Sleep(1000);
                    srvCtroler.Refresh();
                }
                if (consoleMode)
                {
                    Console.WriteLine();
                }
                logger.Warning($"Postgres service: {service} is running");
            }
            catch (Exception ex)
            {
                logger.Error(ex, "Unhandled error during starting Postgres service");
                return false;
            }

            return true;
        }

        private static bool PerformBackup(string[] args)
        {
            var host = ReadParamValue(args, "host");
            var port = ReadParamValue(args, "port");
            var user = ReadParamValue(args, "user");
            var pwd = ReadParamValue(args, "pwd");
            var path = ReadParamValue(args, "path");
            var bin = ReadParamValue(args, "bin");
            var sufix = ReadParamValue(args, "sufix");

            if (String.IsNullOrWhiteSpace(host) ||
                String.IsNullOrWhiteSpace(port) ||
                String.IsNullOrWhiteSpace(user) ||
                String.IsNullOrWhiteSpace(pwd) ||
                String.IsNullOrWhiteSpace(path) ||
                String.IsNullOrWhiteSpace(bin))
            {
                logger.Error("Parameters host, port, user, pwd, path and bin are required for Backup. Use --help to review parameters and options.");
                return false;
            }

            logger.Information("Connect to Postgres and flush current WAL");
            var pgCnxStrBuild = new NpgsqlConnectionStringBuilder();
            pgCnxStrBuild.Host = host;
            pgCnxStrBuild.Port = Convert.ToInt32(port);
            pgCnxStrBuild.Username = user;
            pgCnxStrBuild.Password = DecryptString(pwd);

            string walLSN = null;
            logger.Debug($"Start connection: {pgCnxStrBuild.Host}:{pgCnxStrBuild.Port}");
            using (var pgConnection = new NpgsqlConnection(pgCnxStrBuild.ConnectionString))
            {
                try
                {
                    pgConnection.Open();

                    // Force switch to a new write-ahead log (WAL) file
                    var commWriteWAL = new NpgsqlCommand("SELECT pg_switch_wal()", pgConnection);
                    var writeWAL = (NpgsqlLogSequenceNumber)commWriteWAL.ExecuteScalar();

                    walLSN = $"{writeWAL}";
                    logger.Information($"WAL flush lsn: {walLSN}");
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Unhandled error during flusing WAL");
                    return false;
                }
                finally
                {
                    pgConnection.Close();
                }
            }

            if (!String.IsNullOrEmpty(walLSN))
            {
                logger.Information($"Check backup target: {path}");
                try
                {
                    logger.Debug($"Check if exists: {path}");
                    if (!Directory.Exists(path))
                    {
                        logger.Debug($"  - Create: {path}");
                        Directory.CreateDirectory(path);
                    }

                    var prevFiles = Directory.GetFiles(path);
                    logger.Debug($"Previous files: {prevFiles.Length}");
                    for (int f = 0; f < prevFiles.Length; f++)
                    {
                        logger.Debug($"  delete: {prevFiles[f]}");
                        File.Delete(prevFiles[f]);
                    }
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Unhandled error cleaning backup destination");
                    return false;
                }

                var timeStamp = DateTime.Now.ToString("yyyyMMddHHmm");

                logger.Information($"Config pg_basebackup");
                var pgBackProcessConfig = new ProcessStartInfo(Path.Combine(bin, "pg_basebackup.exe"),
                    $"--gzip --format=t -D \"{path}\" --host={host} --port={port} --username={user} -w " +
                    $"--label=\"Backup {timeStamp}\"");
                pgBackProcessConfig.EnvironmentVariables["PGPASSWORD"] = DecryptString(pwd);
                pgBackProcessConfig.UseShellExecute = false;
                pgBackProcessConfig.CreateNoWindow = true;
                pgBackProcessConfig.RedirectStandardOutput = true;

                logger.Information($"Start pg_basebackup");
                try
                {
                    var pgBackProcess = Process.Start(pgBackProcessConfig);
                    logger.Debug($"Wait pg_basebackup");
                    pgBackProcess.WaitForExit();

                    logger.Debug($"Output pg_basebackup");
                    var output = pgBackProcess.StandardOutput.ReadToEnd();
                    logger.Debug($"{output}");
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Unhandled error during pg_basebackup execution");
                    return false;
                }

                if (!String.IsNullOrWhiteSpace(sufix))
                {
                    logger.Information($"Add sufix to backup files");
                    sufix = sufix.Trim();
                    if (sufix == "TS")
                    {
                        sufix = timeStamp;
                    }
                    try
                    {
                        File.Move(Path.Combine(path, "base.tar.gz"), Path.Combine(path, $"base_{sufix}.tar.gz"));
                        File.Move(Path.Combine(path, "pg_wal.tar.gz"), Path.Combine(path, $"pg_wal_{sufix}.tar.gz"));
                    }
                    catch (Exception ex)
                    {
                        logger.Error(ex, "Unhandled error during adding sufix to backup files");
                        return false;
                    }
                }

                return true;
            }
            else
            {
                logger.Warning("It was not possible to flush WAL, no backup created");
                return false;
            }
        }

        private static string ReadParamValue(string[] args, string name)
        {
            var paramArg = args.FirstOrDefault(f => f.StartsWith($"--{name}="));
            if (paramArg != null)
            {
                var parts = paramArg.Split("=");
                if (parts.Length > 1 && !String.IsNullOrWhiteSpace(parts[1]))
                {
                    return String.Join("", parts.Skip(1).ToArray());
                }
            }
            return null;
        }

        private static void ShowExit()
        {
            if (consoleMode)
            {
                Console.WriteLine();
                Console.Write("[Key] to exit.");
                Console.ReadKey();
            }
        }

        private static void MakePassword()
        {
            var plain = new StringBuilder();
            Console.Write("Password: ");
            do
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter) break;

                if (Regex.Match(key.KeyChar.ToString(),
                    "^[\\w‘\\~\\!@#\\$%\\^&\\*\\(\\)_\\-\\+=\\{\\}\\[\\]\\/<>,\\.;\\?':\\|]$",
                    RegexOptions.IgnoreCase).Success)
                {
                    plain.Append(key.KeyChar);
                    Console.Write("*");
                }
                else
                {
                    Console.Beep();
                }
            } while (true);

            var pwd = EncryptString(plain.ToString());
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Ciphered password: " + pwd);
            ShowExit();
        }

        private static (byte[] Key, byte[] IV) GetAesParams()
        {
            if (!File.Exists(".\\.aesparams"))
            {
                using (var aes = new AesManaged())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();

                    var mem = new byte[aes.Key.Length + aes.IV.Length + 2];

                    Buffer.BlockCopy(BitConverter.GetBytes((UInt16)aes.Key.Length), 0, mem, 0, 2);
                    Buffer.BlockCopy(aes.Key, 0, mem, 2, aes.Key.Length);
                    Buffer.BlockCopy(aes.IV, 0, mem, aes.Key.Length + 2, aes.IV.Length);

                    var content = Convert.ToBase64String(mem);

                    using (var stream = new StreamWriter(".\\.aesparams", false))
                    {
                        stream.Write(content);
                        stream.Flush();
                    }

                    return new(aes.Key, aes.IV);
                }
            }
            else
            {
                using (var stream = new StreamReader(".\\.aesparams"))
                {
                    var content = stream.ReadToEnd();
                    var mem = Convert.FromBase64String(content);
                    var keyLength = BitConverter.ToUInt16(mem, 0);

                    byte[] key = new byte[keyLength];
                    Buffer.BlockCopy(mem, 2, key, 0, keyLength);

                    byte[] iv = new byte[mem.Length - keyLength - 2];
                    Buffer.BlockCopy(mem, 2 + keyLength, iv, 0, iv.Length);

                    return new(key, iv);
                }
            }
        }


        public static string EncryptString(string plainText)
        {
            using (Aes aes = Aes.Create())
            {
                var aesParams = GetAesParams();
                aes.Key = aesParams.Key;
                aes.IV = aesParams.IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        return Convert.ToHexString(memoryStream.ToArray());
                    }
                }
            }
        }

        public static string DecryptString(string cipherText)
        {
            using (Aes aes = Aes.Create())
            {
                var aesParams = GetAesParams();
                aes.Key = aesParams.Key;
                aes.IV = aesParams.IV;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(Convert.FromHexString(cipherText)))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static void ExtractTarGz(String targzFileName, String path)
        {
            logger.Information($"Extract tar.gz: {targzFileName}");
            logger.Information($"  destination: {path}");
            using (Stream targzStream = File.OpenRead(targzFileName))
            {
                using (Stream gzipStream = new GZipInputStream(targzStream))
                {
                    using (TarArchive tarArchive = TarArchive.CreateInputTarArchive(gzipStream, null))
                    {
                        tarArchive.ProgressMessageEvent += (TarArchive archive, TarEntry entry, string message) =>
                        {
                            logger.Debug($"  - extract: {entry.Name}");
                        };
                        tarArchive.ExtractContents(path);
                        tarArchive.Close();
                    }
                    gzipStream.Close();
                }
                targzStream.Close();
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("> winPgBack  {params}  [options]");
            Console.WriteLine("version 2021.2.beta, (c) 2021 by jhurtadom@gmail.com");
            Console.WriteLine();
            Console.WriteLine("  params (required):");
            Console.WriteLine("    --mode=[backup|restore]");
            Console.WriteLine();
            Console.WriteLine("  params (required for backup mode):");
            Console.WriteLine("    --host=                       p.e. localhost, IP address");
            Console.WriteLine("    --port=                       p.e. 5432");
            Console.WriteLine("    --user=                       User with priviledges to run pg_switch_wal()");
            Console.WriteLine("    --pwd=                        Ciphered password, you can use --makepwd help function to generate it");
            Console.WriteLine("    --path=                       Backup directory");
            Console.WriteLine("    --bin=                        Postgres binaries (same version of backups generated)");
            Console.WriteLine();
            Console.WriteLine("  params (required for restore mode):");
            Console.WriteLine("    --service=                    Postgres service name, p.e. postgresql-x64-10");
            Console.WriteLine("    --host=                       p.e. localhost, IP address. (*default: localhost)");
            Console.WriteLine("    --path=                       Backup directory");
            Console.WriteLine("    --wal=                        WAL recovery path (WAL backup in postgres.conf::archive_command");
            Console.WriteLine("    --data=                       Data directory, including base, .conf, pg_wal, log, etc.");
            Console.WriteLine("    --rttime=                     Recovery Target Time. (*default: last moment before backup)");
            Console.WriteLine();
            Console.WriteLine("  options (optional):");
            Console.WriteLine("    --sufix=                      Backup files sufix. (TS = yyyyMMddHHmm time stamp only in backup mode)");
            Console.WriteLine("    --console                     Shows log in console, pause before close.");
            Console.WriteLine("    --logWithDebug                Debug as minimum log level, otherwise: Information");
            Console.WriteLine("    --logFormat                   Serilog log format, default: ");
            Console.WriteLine("                                    {Timestamp:HH:mm:ss.fff}\\t[{Level:u3}]\\t{Message:lj}\\t{Exception}");
            Console.WriteLine("  help functions:");
            Console.WriteLine("    --makepwd                     Creates a ciphered password to pass as parameter");
            Console.WriteLine("    --help                        Shows this help");
            Console.WriteLine();
        }

        private static void InitLogger(string[] args)
        {
            LoggerConfiguration config;

            if (args.Contains("--logWithDebug"))
            {
                config = new LoggerConfiguration().MinimumLevel.Debug();
            }
            else
            {
                config = new LoggerConfiguration().MinimumLevel.Information();
            }

            var logFormat = "{Timestamp:HH:mm:ss.fff}\t[{Level:u3}]\t{Message:lj}\t{Exception}{NewLine}";
            var logFormatArg = ReadParamValue(args, "logFormat");
            if (logFormatArg != null)
            {
                logFormat = args.First(f => f.StartsWith("--logFormat=")).Substring(12) + "{NewLine}";
            }

            config.WriteTo.Async(a => a.
                File(string.Format(string.Format(AppDomain.CurrentDomain.BaseDirectory + "\\logs\\log-.txt")),
                    outputTemplate: logFormat,
                    rollingInterval: RollingInterval.Day,
                    fileSizeLimitBytes: 50000000, // ~50MB per day
                    shared: true,
                    flushToDiskInterval: TimeSpan.FromMilliseconds(500)));

            if (consoleMode)
            {
                config.WriteTo.Console();
            }

            logger = config.CreateLogger();
        }
    }
}
