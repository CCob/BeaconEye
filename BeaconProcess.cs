using BeaconEye.Config;
using NtApiDotNet;
using NtApiDotNet.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BeaconEye {
    class BeaconProcess {

        public enum OutputTypes : int {
            CALLBACK_OUTPUT = 0,
            CALLBACK_KEYSTROKES = 1,
            CALLBACK_FILE = 2,
            CALLBACK_SCREENSHOT = 3,
            CALLBACK_CLOSE = 4,
            CALLBACK_READ = 5,
            CALLBACK_CONNECT = 6,
            CALLBACK_PING = 7,
            CALLBACK_FILE_WRITE = 8,
            CALLBACK_FILE_CLOSE = 9,
            CALLBACK_PIPE_OPEN = 10,
            CALLBACK_PIPE_CLOSE = 11,
            CALLBACK_PIPE_READ = 12,
            CALLBACK_POST_ERROR = 13,
            CALLBACK_PIPE_PING = 14,
            CALLBACK_TOKEN_STOLEN = 15,
            CALLBACK_TOKEN_GETUID = 16,
            CALLBACK_PROCESS_LIST = 17,
            CALLBACK_POST_REPLAY_ERROR = 18,
            CALLBACK_PWD = 19,
            CALLBACK_JOBS = 20,
            CALLBACK_HASHDUMP = 21,
            CALLBACK_PENDING = 22,
            CALLBACK_ACCEPT = 23,
            CALLBACK_NETVIEW = 24,
            CALLBACK_PORTSCAN = 25,
            CALLBACK_DEAD = 26,
            CALLBACK_SSH_STATUS = 27,
            CALLBACK_CHUNK_ALLOCATE = 28,
            CALLBACK_CHUNK_SEND = 29,
            CALLBACK_OUTPUT_OEM = 30,
            CALLBACK_ERROR = 31,
            CALLBACK_OUTPUT_UTF8 = 32
        }

        public NtProcess Process { get; private set; }
        public Configuration BeaconConfig { get; private set; }

        ManualResetEvent finishedEvent;
        StreamWriter logFile;
        long iv_address;
        long keys_address;
        string folderName;

        public BeaconProcess(NtProcess process, Configuration beaconConfig, long iv_address, long keys_address, ref ManualResetEvent finishedEvent) {
            Process = process;
            BeaconConfig = beaconConfig;
            this.iv_address = iv_address;
            this.keys_address = keys_address;
            this.finishedEvent = finishedEvent;
            
            folderName = $"{process.Name}_{process.ProcessId}_{process.User.Name.Replace('\\','_')}";

            Directory.CreateDirectory(folderName);
            logFile = new StreamWriter(new FileStream(Path.Combine(folderName, "activity.log"), FileMode.Create, FileAccess.ReadWrite));

            LogMessage("Configuration:");
            foreach (var config in beaconConfig.Items) {
                logFile.WriteLine($"\tValue {config.Key} {config.Value}: {config.Value}");
            }

            logFile.Flush();
        }

        byte[] EnableBreakpoint(long address) {
            var oldBPInst = Process.ReadMemory(address, 1);
            var oldProtect = Process.ProtectMemory(address, 1, MemoryAllocationProtect.ExecuteReadWrite);
            Process.WriteMemory(address, new byte[] { 0xCC });
            Process.ProtectMemory(address, 1, oldProtect);
            Process.FlushInstructionCache(address, 1);
            return oldBPInst;
        }

        void DisableBreakpoint(NtProcess process, long address, byte[] oldInst) {
            var oldProtect = process.ProtectMemory(address, 1, MemoryAllocationProtect.ExecuteReadWrite);
            process.WriteMemory(address, oldInst);
            process.ProtectMemory(address, 1, oldProtect);
            process.FlushInstructionCache(address, 1);
        }

        void LogMessage(string message) {
            logFile.WriteLine($"{DateTime.Now} - {message}");
            logFile.Flush();
        }

        void EnableSingleStep(NtThread thread, long updateRip) {

            var ctx = (ContextAmd64)thread.GetContext(ContextFlags.All);

            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags |= 0x100;
            if (updateRip != 0)
                ctx.Rip = (ulong)updateRip;

            thread.SetContext(ctx);
        }

        static void DisableSingleStep(NtThread thread) {
            var ctx = (ContextAmd64)thread.GetContext(ContextFlags.DebugRegisters);
            ctx.Dr0 = ctx.Dr6 = ctx.Dr7 = 0;
            ctx.EFlags = 0;
            thread.SetContext(ctx);
        }

        // Based on MSDN example: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rijndaelmanaged?redirectedfrom=MSDN&view=net-5.0#Y2262
        static byte[] DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV) {

            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            using (Aes aesAlg = Aes.Create()) {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText)) {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
                        using (MemoryStream msPlain = new MemoryStream()) {
                            csDecrypt.CopyTo(msPlain);
                            return msPlain.ToArray();
                        }
                    }
                }
            }
        }

        void SaveScreenshot(BinaryReader br) {
            var jpgLen = br.ReadUInt32();
            var fileName = Path.Combine(folderName, $"{DateTime.Now.ToString("yyyyMMddHHmmss")}_Screenshot.jpg");

            //older beacons contain just the JPG data, newer versions contain other stuff too
            if (jpgLen != 0xE0FFD8FF) {
                var jpgData = br.ReadBytes((int)jpgLen);
                File.WriteAllBytes(fileName, jpgData);
            } else {
                var jpgData = br.ReadBytes((int)(br.BaseStream.Length - br.BaseStream.Position));
                jpgData = new byte[4] { 0xFF, 0xD8, 0xFF, 0xE0 }.Concat(jpgData).ToArray();
                File.WriteAllBytes(fileName, jpgData);
            }
        }

        void DecryptCallback(byte[] body, byte[] key) {

            var beaconProgram = (ConfigProgramItem)BeaconConfig.Items["HTTP_Post_Program"];
            byte[] decoded = beaconProgram.Value.RecoverOutput(body);

            var dataLen = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(decoded, 0));
            var encryptedData = decoded.Skip(4).Take(dataLen).ToArray();
            var decryptedData = DecryptStringFromBytes_Aes(encryptedData, key, Encoding.ASCII.GetBytes("abcdefghijklmnop"));

            BinaryReader br = new BinaryReader(new MemoryStream(decryptedData));

            var sequenceNumber = IPAddress.NetworkToHostOrder(br.ReadInt32());
            var callbackDataLen = IPAddress.NetworkToHostOrder(br.ReadInt32());
            var callbackId = (OutputTypes)IPAddress.NetworkToHostOrder(br.ReadInt32());
            callbackDataLen -= 4;
            string output = "";

            switch (callbackId) {
                case OutputTypes.CALLBACK_OUTPUT:
                case OutputTypes.CALLBACK_OUTPUT_OEM:                
                    output = Encoding.ASCII.GetString(br.ReadBytes(callbackDataLen));
                    break;
                case OutputTypes.CALLBACK_OUTPUT_UTF8:
                case OutputTypes.CALLBACK_HASHDUMP:
                case OutputTypes.CALLBACK_KEYSTROKES:
                    output = Encoding.UTF8.GetString(br.ReadBytes(callbackDataLen));
                    break;
                case OutputTypes.CALLBACK_PENDING:
                    var pendingRequest = IPAddress.NetworkToHostOrder(br.ReadInt32());
                    output = Encoding.ASCII.GetString(br.ReadBytes(callbackDataLen-4));
                    break;
                case OutputTypes.CALLBACK_SCREENSHOT:
                    SaveScreenshot(br);
                    break;
            }

            LogMessage($"Callback {sequenceNumber} sent with type {callbackId}\n{output}");
        }

        public void MonitorTraffic() {

            NtDebug debugObject = NtDebug.Create();
            var debugging = true;
            debugObject.SetKillOnClose(false);
            debugObject.Attach(Process);
            byte[] oldBPInst = null;
            byte[] keys = null;
            long httpSendRequestAddress = 0;

            while (debugging) {

                var status = NtStatus.DBG_CONTINUE;
                DebugEvent debugEvent = debugObject.WaitForDebugEvent(100);

                if (debugEvent is UnknownDebugEvent && finishedEvent.WaitOne(400)) {
                    
                    if (httpSendRequestAddress != 0 && oldBPInst != null)
                        DisableBreakpoint(Process, httpSendRequestAddress, oldBPInst);

                    debugging = false;
                    continue;
                }

                if (debugEvent is LoadDllDebugEvent loadDllDebugEvent) {

                    if (Path.GetFileName(loadDllDebugEvent.File.FileName) == "wininet.dll") {

                        var wininetLib = SafeLoadLibraryHandle.LoadLibrary("wininet.dll");
                        httpSendRequestAddress = wininetLib.Exports
                            .Where(e => e.Name == "HttpSendRequestA")
                            .Select(e => e.Address)
                            .First();

                        oldBPInst = EnableBreakpoint(httpSendRequestAddress);
                    }
                } else if (debugEvent is ExceptionDebugEvent exceptionDebugEvent) {

                    if (exceptionDebugEvent.Code == NtStatus.STATUS_BREAKPOINT && exceptionDebugEvent.Address == httpSendRequestAddress) {

                        if (keys == null) {
                            string iv = Encoding.ASCII.GetString(Process.ReadMemory(iv_address, 16));
                            if (iv == "abcdefghijklmnop") {
                                keys = Process.ReadMemory(keys_address, 32);
                                LogMessage($"Static IV found at 0x{iv_address:x}");
                                LogMessage($"AES  Key: {StringUtils.ByteArrayToString(keys.Take(16).ToArray())}");
                                LogMessage($"HMAC Key: {StringUtils.ByteArrayToString(keys.Skip(16).Take(16).ToArray())}");
                            }
                        }

                        DisableBreakpoint(Process, httpSendRequestAddress, oldBPInst);
                        using (var requestThread = NtThread.Open(debugEvent.ThreadId, ThreadAccessRights.GetContext | ThreadAccessRights.SetContext)) {

                            var ctx = (ContextAmd64)requestThread.GetContext(ContextFlags.All);
                            string httpHeaders = Encoding.ASCII.GetString(Process.ReadMemory((long)ctx.Rdx, (int)ctx.R8));
                            byte[] body = null;
                            var body_len = BitConverter.ToUInt32(Process.ReadMemory((long)ctx.Rsp + 0x28, 4), 0);

                            if (body_len > 0 && ctx.R9 != 0) {
                                body =Process.ReadMemory((long)ctx.R9, (int)body_len);
                            }

                            //LogMessage($"HTTP Request:\n{httpHeaders}");

                            if (body != null) {
                                DecryptCallback(body, keys.Take(16).ToArray());
                            }

                            EnableSingleStep(requestThread, httpSendRequestAddress);
                        }

                    } else if (exceptionDebugEvent.Code == NtStatus.STATUS_SINGLE_STEP) {

                        using (var requestThread = NtThread.Open(debugEvent.ThreadId, ThreadAccessRights.MaximumAllowed)) {
                            DisableSingleStep(requestThread);
                        }

                        EnableBreakpoint(httpSendRequestAddress);

                    } else {
                        status = NtStatus.DBG_EXCEPTION_NOT_HANDLED;
                    }
                }

                if (!(debugEvent is UnknownDebugEvent))
                    debugObject.Continue(debugEvent.ProcessId, debugEvent.ThreadId, status);

            }

            debugObject.Detach(Process);
            LogMessage($"Disconnected from beacon process");
            logFile.Close();
        }
    }
}
