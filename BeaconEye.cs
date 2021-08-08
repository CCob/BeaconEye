using BeaconEye.Config;
using libyaraNET;
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
    class BeaconEye {

        public static string cobaltStrikeRule = "rule CobaltStrike { " +
                "strings:  " +
                    "$sdec = { " +
                        " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 " +
                        " 01 00 00 00 00 00 00 00 (00|01|02|04|08|10) 00 00 00 00 00 00 00 " +
                        " 01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 " +
                        " 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 " +
                        " 02 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 " +
                        " 01 00 00 00 00 00 00 00 ?? ?? 00 00 00 00 00 00 " +
                        "} " +
                "condition: " +
                    "any of them" +
            "}";

        static ManualResetEvent finishedEvent = new ManualResetEvent(false);
        static List<Thread> beaconMonitorThreads = new List<Thread>();
        
        static Rules CompileRules() {
            using (Compiler compiler = new Compiler()) {   
                compiler.AddRuleString(cobaltStrikeRule);
                return compiler.GetRules();
            }
        }

        public static List<int> IndexOfSequence(byte[] buffer, byte[] pattern, int startIndex) {
            List<int> positions = new List<int>();
            int i = Array.IndexOf<byte>(buffer, pattern[0], startIndex);
            while (i >= 0 && i <= buffer.Length - pattern.Length) {
                byte[] segment = new byte[pattern.Length];
                Buffer.BlockCopy(buffer, i, segment, 0, pattern.Length);
                if (segment.SequenceEqual<byte>(pattern))
                    positions.Add(i);
                i = Array.IndexOf<byte>(buffer, pattern[0], i + 1);
            }
            return positions;
        }

        static Configuration ProcessHasConfig(NtProcess process) {
           
            var memoryInfos = process.QueryAllMemoryInformation();

            foreach(var memoryInfo in memoryInfos) {
                try {

                    if(memoryInfo.Protect != MemoryAllocationProtect.ReadWrite || memoryInfo.Type != MemoryType.Private || memoryInfo.State != MemoryState.Commit) {
                        continue;
                    }

                    var memory = process.ReadMemory(memoryInfo.BaseAddress, (int)memoryInfo.RegionSize);
 
                    using(var ctx = new YaraContext()) {
                        var rules = CompileRules();

                        Scanner scanner = new Scanner();
                        var results = scanner.ScanMemory(memory, rules);

                        if (results.Count > 0) {

                            foreach (KeyValuePair<string, List<Match>> item in results[0].Matches) {
                                var configStart = memoryInfo.BaseAddress + (long)item.Value[0].Offset;
                                var configBytes = process.ReadMemory(configStart, 0x800);
                                return new Configuration(new BinaryReader(new MemoryStream(configBytes)), process);                                
                            }                           
                        }
                    }
                 
                } catch (Exception) {

                }
            }
            
            return null;
        }

        static void MonitorThread(object arg) {
            if(arg is BeaconProcess bp) {
                bp.MonitorTraffic();
            }
        }

        static bool PossibleRXBeacon(NtProcess process, MemoryInformation block) {
            
            int minBeaconTextSize = 160 * 1024;
            int maxBeaconTextSize = 180 * 1024;

            if (block.Protect == MemoryAllocationProtect.ExecuteRead
                        && block.RegionSize >= minBeaconTextSize
                        && block.RegionSize <= maxBeaconTextSize) {

                var dataMemory = process.QueryMemoryInformation(block.BaseAddress + block.RegionSize);

                if (dataMemory.AllocationBase != block.AllocationBase && 
                    (dataMemory.Protect == MemoryAllocationProtect.ReadWrite || dataMemory.Protect == MemoryAllocationProtect.ReadOnly)) {
                    return false;
                } else {
                    return true;
                }
            }

            return false;
        }

        static bool PossibleRWXBeacon(MemoryInformation block) {
            return block.Protect == MemoryAllocationProtect.ExecuteReadWrite;
        }

        static bool IsBeaconProcess(NtProcess process) {
            
            try {
                var memoryInfo = process.QueryAllMemoryInformation();
                MemoryInformation lastBlock = null;
                              
                foreach (var blockInfo in memoryInfo) {

                    if (PossibleRXBeacon(process, blockInfo) || PossibleRWXBeacon(blockInfo) ) {
      
                        var codeBlock = process.ReadMemory(blockInfo.BaseAddress, (int)blockInfo.RegionSize);
                        var offsets = IndexOfSequence(codeBlock, new byte[] { 0x0F, 0x10, 0x05 }, 0);
                        bool doneSearching = false;

                        foreach (var offset in offsets) {

                            try {
                                Configuration beaconConfig;
                                byte[] instructions = process.ReadMemory(blockInfo.BaseAddress + offset, 15);
                                SharpDisasm.Disassembler disasm = new SharpDisasm.Disassembler(instructions, SharpDisasm.ArchitectureMode.x86_64, (ulong)blockInfo.BaseAddress + (ulong)offset);

                                var movupsIns = disasm.NextInstruction();
                                var movdquIns = disasm.NextInstruction();

                                if( movdquIns.Mnemonic != SharpDisasm.Udis86.ud_mnemonic_code.UD_Imovdqu ||
                                    movdquIns.Operands[0].Base != SharpDisasm.Udis86.ud_type.UD_R_RIP ||
                                    movupsIns.Operands[0].Base != movdquIns.Operands[1].Base) {
                                    continue;                                 
                                } else {
                                    if ((beaconConfig = ProcessHasConfig(process)) == null) {
                                        doneSearching = true;
                                        break;
                                    }                                    
                                }

                                var iv_address = (long)movupsIns.PC + movupsIns.Operands[1].LvalSDWord;
                                var keys_address = (long)movdquIns.PC + movdquIns.Operands[0].LvalSDWord - 32;

                                var beaconProcess = new BeaconProcess(process, beaconConfig, iv_address, keys_address, ref finishedEvent);
                                var beaconMonitorThread = new Thread(MonitorThread);
                                beaconMonitorThreads.Add(beaconMonitorThread);
                                beaconMonitorThread.Start(beaconProcess);
                                return true;
                               
                            } catch (Exception e) {
                                Console.WriteLine(e.Message);
                            }
                        }

                        if (doneSearching) {
                            break;
                        }
                    }

                    lastBlock = blockInfo;
                }
            } catch (Exception) {

            }

            return false;
        }

        static void Main(string[] args) {
            
            Console.WriteLine($"[+] Scanning for beacon processess...");

            var processes = NtProcess.GetProcesses(ProcessAccessRights.AllAccess);
            var originalColor = Console.ForegroundColor;
            foreach (var process in processes) {
                
                if (IsBeaconProcess(process)) {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"\t{process.Name} ({process.ProcessId})");
                } else {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"\t{process.Name} ({process.ProcessId})");
                }          
            }
            Console.ForegroundColor = originalColor;
                        
            if(beaconMonitorThreads.Count > 0) {

                Console.WriteLine($"[+] Monitoring {beaconMonitorThreads.Count} beacon processes, press enter to stop monitoring");
                Console.ReadLine();
                Console.WriteLine($"[+] Exit triggered, detaching from beacon processes...");

                finishedEvent.Set();
                foreach(var bt in beaconMonitorThreads) {
                    bt.Join();
                }

            } else {
                Console.WriteLine($"[=] No beacon processes found");
            }
        }
    }
}
