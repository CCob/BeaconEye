using BeaconEye.Config;
using BeaconEye.Reader;
using Kaitai;
using libyaraNET;
using Mono.Options;
using NtApiDotNet;
using NtApiDotNet.Win32;
using SharpDisasm;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BeaconEye {
    class BeaconEye {

        enum ScanState{
            NotFound,
            Found,
            FoundNoKeys,
            HeapEnumFailed                
        }

        class FetchHeapsException : Exception {

        }

        class ScanResult {
            public ScanState State { get; set; }
            public long ConfigAddress { get; set; }
            public bool CrossArch { get; set; }
            public Configuration Configuration { get; set; }
        }
        
        public static string cobaltStrikeRule64 = "rule CobaltStrike { " +
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

        public static string cobaltStrikeRule32 = "rule CobaltStrike { " +
                "strings:  " +
                    "$sdec = { " +
                        " 00 00 00 00 00 00 00 00 " +
                        " 01 00 00 00 (00|01|02|04|08|10) 00 00 00" +
                        " 01 00 00 00 ?? ?? 00 00 " +
                        " 02 00 00 00 ?? ?? ?? ?? " +
                        " 02 00 00 00 ?? ?? ?? ?? " +
                        " 01 00 00 00 ?? ?? 00 00 " +
                        "} " +
                "condition: " +
                    "any of them" +
            "}";

        static ManualResetEvent finishedEvent = new ManualResetEvent(false);
        static List<Thread> beaconMonitorThreads = new List<Thread>();
        
        static Rules CompileRules(bool x64) {
            using (Compiler compiler = new Compiler()) {   
                compiler.AddRuleString(x64 ? cobaltStrikeRule64 : cobaltStrikeRule32);
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

        static long ReadPointer(NtProcess process, long address) {
            if (process.Is64Bit) {
                return process.ReadMemory<long>(address);
            } else {
                return process.ReadMemory<int>(address);
            }
        }

        static List<long> GetHeaps(NtProcess process) {

            try {
                int numHeaps;
                long heapArray;

                if (process.Is64Bit) {
                    numHeaps = process.ReadMemory<int>((long)process.PebAddress + 0xE8);
                    heapArray = ReadPointer(process, (long)process.PebAddress + 0xF0);
                } else {
                    numHeaps = process.ReadMemory<int>((int)process.PebAddress32 + 0x88);
                    heapArray = ReadPointer(process, (long)process.PebAddress32 + 0x90);
                }

                var heaps = new List<long>();
                for (int idx = 0; idx < numHeaps; ++idx) {
                    var heap = ReadPointer(process, heapArray + (idx * (process.Is64Bit ? 8 : 4)));
                    heaps.Add(heap);
                }

                return heaps;

            } catch (Exception) {
                throw new FetchHeapsException();
            }
        }

        static Configuration ProcessHasConfig(ProcessReader process) {

            var heaps = process.Heaps;

            using (var ctx = new YaraContext()) {
                var rules = CompileRules(process.Is64Bit);
                Scanner scanner = new Scanner();

                foreach (var heap in heaps) {
                      
                    var memoryInfo = process.QueryMemoryInfo((ulong)heap);
                    var memory = process.ReadMemory(memoryInfo.BaseAddress, (int)memoryInfo.RegionSize);
                    var results = scanner.ScanMemory(memory, rules);

                    if (results.Count > 0) {
                        foreach (KeyValuePair<string, List<Match>> item in results[0].Matches) {
                            var configStart = memoryInfo.BaseAddress + item.Value[0].Offset;
                            var configBytes = process.ReadMemory(configStart, process.Is64Bit ? 0x800 : 0x400);
                            return new Configuration((long)configStart, new BinaryReader(new MemoryStream(configBytes)), process);
                        }
                    }
                }                
            }               
                            
            return null;
        }

        static void MonitorThread(object arg) {
            if(arg is BeaconProcess bp) {
                bp.MonitorTraffic();
            }
        }

        static Tuple<long,long> GetKeyIVAddress(ProcessReader.MemoryInfo blockInfo, ProcessReader process) {

            if (process.Is64Bit) {

                var codeBlock = process.ReadMemory(blockInfo.BaseAddress, (int)blockInfo.RegionSize);
                var offsets = IndexOfSequence(codeBlock, new byte[] { 0x0F, 0x10, 0x05 }, 0);

                foreach (var offset in offsets) {

                    byte[] instructions = process.ReadMemory(blockInfo.BaseAddress + (ulong)offset, 15);
                    Disassembler disasm = new Disassembler(instructions, ArchitectureMode.x86_64, (ulong)blockInfo.BaseAddress + (ulong)offset);

                    var movupsIns = disasm.NextInstruction();
                    var movdquIns = disasm.NextInstruction();

                    if (movdquIns.Mnemonic != SharpDisasm.Udis86.ud_mnemonic_code.UD_Imovdqu ||
                        movdquIns.Operands[0].Base != SharpDisasm.Udis86.ud_type.UD_R_RIP ||
                        movupsIns.Operands[0].Base != movdquIns.Operands[1].Base) {
                        return null;
                    } else {

                        var iv_address = (long)movupsIns.PC + movupsIns.Operands[1].LvalSDWord;
                        var keys_address = (long)movdquIns.PC + movdquIns.Operands[0].LvalSDWord - 32;

                        return new Tuple<long, long>(keys_address, iv_address);
                    }
                }

            } else {

                var codeBlock = process.ReadMemory(blockInfo.BaseAddress, (int)blockInfo.RegionSize);
                var offsets = IndexOfSequence(codeBlock, new byte[] { 0xa5, 0xa5, 0xa5, 0xa5, 0xe8 }, 0);

                foreach (var offset in offsets) {

                    byte[] instructions = process.ReadMemory(blockInfo.BaseAddress + (ulong)offset - 5, 24);
                    Disassembler disasm = new Disassembler(instructions, ArchitectureMode.x86_32, (ulong)blockInfo.BaseAddress + (ulong)offset);

                    var movEDIMem = disasm.NextInstruction();

                    if(movEDIMem.Mnemonic != SharpDisasm.Udis86.ud_mnemonic_code.UD_Imov || 
                        movEDIMem.Operands[0].Base != SharpDisasm.Udis86.ud_type.UD_R_EDI ||
                        movEDIMem.Operands[1].Base != SharpDisasm.Udis86.ud_type.UD_NONE
                        ) {
                        continue;
                    }
                  
                    var iv_address = movEDIMem.Operands[1].LvalUDWord;
                    long key_address = 0;

                    for(int idx = offset; idx > offset - 50; idx--) {

                        var keysOffsets = IndexOfSequence(codeBlock, new byte[] { 0x53, 0x56, 0x57, 0xbb }, idx);

                        if(keysOffsets.Count > 0 && keysOffsets[0] < offset) {

                            instructions = codeBlock.Skip(idx+3).Take(8).ToArray();
                            disasm = new Disassembler(instructions, ArchitectureMode.x86_32, (ulong)blockInfo.BaseAddress + (ulong)idx+3);

                            var movEBX = disasm.NextInstruction();
                            key_address = movEBX.Operands[1].LvalUDWord;
                            break;
                        }
                    }

                    if (key_address != 0)
                        return new Tuple<long, long>(key_address, iv_address);
                }
            }

            return null;
        }

        static ScanResult IsBeaconProcess(ProcessReader process, bool monitor) {
            
            try {

                var beaconConfig = ProcessHasConfig(process);
                if (beaconConfig == null) {
                    return new ScanResult();
                }

                var memoryInfo = process.QueryAllMemoryInfo();

                foreach (var blockInfo in memoryInfo) {

                    if(!blockInfo.IsExecutable) {
                        continue;
                    }

                    BeaconProcess beaconProcess = null;                                   
                    Tuple<long, long> keyIV;
                    if((keyIV = GetKeyIVAddress(blockInfo, process)) == null) {
                        continue;                  
                    }

                    bool crossArch = true;

                    if (process.Is64Bit == NtProcess.Current.Is64Bit) {
                        if (monitor) {
                            beaconProcess = new BeaconProcess(process, beaconConfig, keyIV.Item2, keyIV.Item1, ref finishedEvent);
                            var beaconMonitorThread = new Thread(MonitorThread);
                            beaconMonitorThreads.Add(beaconMonitorThread);
                            beaconMonitorThread.Start(beaconProcess);
                        }                  
                        crossArch = false;
                    }

                    return new ScanResult() {
                        State = ScanState.Found,
                        ConfigAddress = beaconConfig.Address,
                        CrossArch = crossArch,
                        Configuration = beaconConfig
                    };                                                                                                                                                                                            
                }

                return new ScanResult() {
                    State = ScanState.FoundNoKeys,
                    ConfigAddress = beaconConfig.Address,
                    Configuration = beaconConfig
                };

            } catch (FetchHeapsException e) {
                return new ScanResult() {
                    State = ScanState.HeapEnumFailed
                };                
            }                
        }

        static void Main(string[] args) {

            bool monitor = false;
            string processFilter = null;
            bool showHelp = false;
            bool verbose = false;
            string dump = null;
            IProcessEnumerator procEnum;

            Console.WriteLine(
                    "BeconEye by @_EthicalChaos_\n" +
                    $"  CobaltStrike beacon hunter and command monitoring tool { (IntPtr.Size == 8 ? "x86_64" : "x86")} \n"
                   );

            OptionSet option_set = new OptionSet()
                .Add("v|verbose", "Attach to and monitor beacons found", v => verbose = true)
                .Add("m|monitor", "Attach to and monitor beacons found", v => monitor = true)
                .Add("f=|filter=", "Filter process list wih names starting with x or file extensions in Minidump mode", v => processFilter = v)
                .Add("d=|dump=", "Scan a Minidump for a Cobalt Strike beacon", v => dump = v)
                .Add("h|help", "Display this help", v => showHelp = v != null);

            try {

                option_set.Parse(args);

                if (showHelp) {
                    option_set.WriteOptionDescriptions(Console.Out);
                    return;
                }

            } catch (Exception e) {
                Console.WriteLine("[!] Failed to parse arguments: {0}", e.Message);
                option_set.WriteOptionDescriptions(Console.Out);
                return;
            }

            var timer = new Stopwatch();
            timer.Start();
            Console.WriteLine($"[+] Scanning for beacon processess...");
            if(processFilter != null) {
                Console.WriteLine($"[=] Using process filter {processFilter}*");
            }

            if (!string.IsNullOrEmpty(dump)) {
                procEnum = new MiniDumpProcessEnumerator(dump);
            } else {
                procEnum = new RunningProcessEnumerator();
            }

            var originalColor = Console.ForegroundColor;
            var beaconsFound = 0;
            var processesScanned = 0;
            
            foreach (var process in procEnum.GetProcesses()) {

                ScanResult sr;

                if ((sr = IsBeaconProcess(process, monitor)).State == ScanState.Found || sr.State == ScanState.FoundNoKeys) {
                    beaconsFound++;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"  {process.Name} ({process.ProcessId}), Keys Found:{sr.State == ScanState.Found}, Configuration Address: 0x{sr.ConfigAddress} {(sr.CrossArch ? $"(Please use the {(process.Is64Bit ? "x64" : "x86")} version of BeaconEye to monitor)" : "")}");
                    sr.Configuration.PrintConfiguration(Console.Out, 1);
                } else if(sr.State == ScanState.NotFound && verbose) {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"  {process.Name} ({process.ProcessId})");
                } else if(sr.State == ScanState.HeapEnumFailed) {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine($"  {process.Name} ({process.ProcessId}) Failed to fetch heap info");
                }

                processesScanned++;
            }

            timer.Stop();
            Console.ForegroundColor = originalColor;
            Console.WriteLine($"[+] Scanned {processesScanned} processes in {timer.Elapsed}");

            if (beaconsFound > 0) {

                Console.WriteLine($"[+] Found {beaconsFound} beacon processes");

                if (beaconMonitorThreads.Count > 0 && monitor) {
                    Console.WriteLine($"[+] Monitoring {beaconMonitorThreads.Count} beacon processes, press enter to stop monitoring");
                    Console.ReadLine();
                    Console.WriteLine($"[+] Exit triggered, detaching from beacon processes...");

                    finishedEvent.Set();
                    foreach (var bt in beaconMonitorThreads) {
                        bt.Join();
                    }
                }

            } else {
                Console.WriteLine($"[=] No beacon processes found");
            }
        }
    }
}
