using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;

namespace BeaconEye {
    public class MiniDumpReader : ProcessReader {

        public enum StreamType : uint {
            UnusedStream,
            ReservedStream0,
            ReservedStream1,
            ThreadListStream,
            ModuleListStream,
            MemoryListStream,
            ExceptionStream,
            SystemInfoStream,
            ThreadExListStream,
            Memory64ListStream,
            CommentStreamA,
            CommentStreamW,
            HandleDataStream,
            FunctionTableStream,
            UnloadedModuleListStream,
            MiscInfoStream,
            MemoryInfoListStream,
            ThreadInfoListStream,
            HandleOperationListStream,
            TokenStream,
            JavaScriptDataStream,
            SystemMemoryInfoStream,
            ProcessVmCountersStream,
            IptTraceStream,
            ThreadNamesStream,
            ceStreamNull,
            ceStreamSystemInfo,
            ceStreamException,
            ceStreamModuleList,
            ceStreamProcessList,
            ceStreamThreadList,
            ceStreamThreadContextList,
            ceStreamThreadCallStackList,
            ceStreamMemoryVirtualList,
            ceStreamMemoryPhysicalList,
            ceStreamBucketParameters,
            ceStreamProcessModuleMap,
            ceStreamDiagnosisList,
            LastReservedStream
        }

        [Flags]
        enum MinidumpType : ulong {
            MiniDumpNormal,
            MiniDumpWithDataSegs,
            MiniDumpWithFullMemory,
            MiniDumpWithHandleData,
            MiniDumpFilterMemory,
            MiniDumpScanMemory,
            MiniDumpWithUnloadedModules,
            MiniDumpWithIndirectlyReferencedMemory,
            MiniDumpFilterModulePaths,
            MiniDumpWithProcessThreadData,
            MiniDumpWithPrivateReadWriteMemory,
            MiniDumpWithoutOptionalData,
            MiniDumpWithFullMemoryInfo,
            MiniDumpWithThreadInfo,
            MiniDumpWithCodeSegs,
            MiniDumpWithoutAuxiliaryState,
            MiniDumpWithFullAuxiliaryState,
            MiniDumpWithPrivateWriteCopyMemory,
            MiniDumpIgnoreInaccessibleMemory,
            MiniDumpWithTokenInformation,
            MiniDumpWithModuleHeaders,
            MiniDumpFilterTriage,
            MiniDumpWithAvxXStateContext,
            MiniDumpWithIptTrace,
            MiniDumpScanInaccessiblePartialPages,
            MiniDumpFilterWriteCombinedMemory,
            MiniDumpValidTypeFlags
        }
        

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct Header {
            public uint Signature;
            public uint Version;
            public uint NumberOfStreams;
            public uint StreamsDirectoryRva;
            public uint Checksum;
            public uint Timestamp;
            public MinidumpType Flags;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct Directory {
            public StreamType StreamType;
            public uint Length;
            public uint Offset;

            public override string ToString() {
                return $"{StreamType}: Length={Length}, Offset={Offset}";
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct LocationDescriptor {
            public uint Length;
            public uint Offset;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct MemoryDescriptor {
            public ulong AddressMemoryRange;
            public LocationDescriptor Memory;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct MemoryDescriptorFull {
            public ulong StartOfMemoryRange;
            public ulong DataSize;
            public override string ToString() {
                return $"Start=0x{StartOfMemoryRange:x}: DataSize=0x{DataSize:x}";
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct MiniDumpThread {
            public uint ThreadId;
            public uint SuspendCount;
            public uint PriorityClass;
            public uint Priority;
            public ulong Teb;
            public MemoryDescriptor Stack;
            public LocationDescriptor ThreadContext;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct Module {
            public ulong BaseOfImage;
            public uint SizeOfImage;
            public uint CheckSum;
            public uint TimeDateStamp;
            public uint ModuleNameRva;
            public FileInfo VersionInfo;
            public LocationDescriptor CvRecord;
            public LocationDescriptor MiscRecord;
            ulong Reserved0;
            ulong Reserved1;              
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct FileInfo {
            public uint Signature;
            public uint StrucVersion;
            public uint FileVersionMS;
            public uint FileVersionLS;
            public uint ProductVersionMS;
            public uint ProductVersionLS;
            public uint FileFlagsMask;
            public uint FileFlags;
            public uint FileOS;
            public uint FileType;
            public uint FileSubtype;
            public uint FileDateMS;
            public uint FileDateLS;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct SystemInfo {
            public ushort ProcessorArchitecture;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
            public byte NumberOfProcessors;
            public byte ProductType;
            public uint MajorVersion;
            public uint MinorVersion;
            public uint BuildNumber;
            public uint PlatformId;
            public uint CDSVersionRva;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct PartialTeb64 {
            public ulong SehFrame;
            public ulong StackBase;
            public ulong StackLimit;
            public ulong SubSystemTib;
            public ulong FibreData;
            public ulong DataSlot;
            public ulong TebAddress;
            public ulong EnvironmentPointer;
            public ulong ProcessId;
            public ulong ThreadId;
            public ulong ActiveRPCHandle;
            public ulong ThreadLocalStorageAddr;
            public ulong PebAddress;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct PartialTeb32 {
            public uint SehFrame;
            public uint StackBase;
            public uint StackLimit;
            public uint SubSystemTib;
            public uint FibreData;
            public uint DataSlot;
            public uint TebAddress;
            public uint EnvironmentPointer;
            public uint ProcessId;
            public uint ThreadId;
            public uint ActiveRPCHandle;
            public uint ThreadLocalStorageAddr;
            public uint PebAddress;
        }

        Stream miniDumpStream;
        BinaryReader miniDumpReader;
        List<MiniDumpThread> threads = new List<MiniDumpThread>();
        List<Module> modules = new List<Module>();
        List<MemoryDescriptorFull> memoryInfoFull = new List<MemoryDescriptorFull>();
        SystemInfo systemInfo;
        ulong memoryFullRVA;
        ulong pebAddress;
        string processName;
        int processId;
        bool is64 = true;


        //TODO: get process name from dump
        public override string Name => processName;


        //TODO: determine 32/64 bit dumps
        public override bool Is64Bit => is64;

        public override ulong PebAddress =>  pebAddress; 
        //TODO: extract PID
        public override int ProcessId => processId;

        public MiniDumpReader(string fileName) : this(new FileStream(fileName, FileMode.Open, FileAccess.Read)) { 
        }

        public MiniDumpReader(Stream source) {

            miniDumpStream = source;

            if (!source.CanSeek) {
                throw new ArgumentException("Only seekable streams supported");
            }

            miniDumpReader = new BinaryReader(miniDumpStream);
            source.Seek(0, SeekOrigin.Begin);

            var hdr = ReadStruct<Header>();

            if(hdr.Signature != 0x504d444d) {
                throw new FormatException("Input stream doesn't appear to be a Minidump");
            }

            if( ((ulong)hdr.Flags | (ulong)MinidumpType.MiniDumpWithFullMemoryInfo) == 0) {
                throw new FormatException("Only full Minidump types supported");
            }

            var directories = new List<Directory>();
            source.Seek(hdr.StreamsDirectoryRva, SeekOrigin.Begin);

            for (int idx = 0; idx < hdr.NumberOfStreams; ++idx) {
                directories.Add(ReadStruct<Directory>());
            }

            foreach (var dir in directories) {

                source.Seek(dir.Offset, SeekOrigin.Begin);

                if (dir.StreamType == StreamType.ThreadListStream) {

                    var threadCount = miniDumpReader.ReadInt32();
                    for (int idx = 0; idx < threadCount; ++idx) {
                        threads.Add(ReadStruct<MiniDumpThread>());
                    }

                } else if (dir.StreamType == StreamType.Memory64ListStream) {

                    var memoryRangeCount = miniDumpReader.ReadUInt64();
                    memoryFullRVA = miniDumpReader.ReadUInt64();
                    for (uint idx = 0; idx < memoryRangeCount; ++idx) {
                        memoryInfoFull.Add(ReadStruct<MemoryDescriptorFull>());
                    }

                } else if (dir.StreamType == StreamType.ModuleListStream) {

                    var moduleCount = miniDumpReader.ReadInt32();
                    while (moduleCount-- > 0) {
                        modules.Add(ReadStruct<Module>());
                    }
                } else if (dir.StreamType == StreamType.SystemInfoStream) {
                    systemInfo = ReadStruct<SystemInfo>();
                }
            }

            processName = Path.GetFileName(ReadMinidumpString(modules[0].ModuleNameRva));
            is64 = systemInfo.ProcessorArchitecture == 9;

            if (is64) {
                var teb = ReadMemory<PartialTeb64>(threads[0].Teb);
                processId = (int)teb.ProcessId;
                pebAddress = teb.PebAddress;
            } else {
                var teb = ReadMemory<PartialTeb32>(threads[0].Teb);
                processId = (int)teb.ProcessId;
                pebAddress = teb.PebAddress;
            }
        }

        string ReadMinidumpString(long rva) {
            
            long oldPosition = miniDumpStream.Position;
            miniDumpStream.Seek(rva, SeekOrigin.Begin);
            var strLen = ReadStruct<int>();            
            string result = Encoding.Unicode.GetString(miniDumpReader.ReadBytes(strLen));
            miniDumpStream.Seek(oldPosition, SeekOrigin.Begin);
            return result;
        }

        T ReadStruct<T>() {

            var structData = new byte[Marshal.SizeOf(typeof(T))];
            miniDumpStream.Read(structData, 0, structData.Length);

            var handle = GCHandle.Alloc(structData, GCHandleType.Pinned);
            var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public override T ReadMemory<T>(ulong address) {

            var structData = ReadMemory(address, Marshal.SizeOf(typeof(T)));

            var handle = GCHandle.Alloc(structData, GCHandleType.Pinned);
            var theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public override byte[] ReadMemory(ulong address, int len) {

            ulong fileAddress = memoryFullRVA;

            foreach (var descriptor in memoryInfoFull) {
                if (address >= descriptor.StartOfMemoryRange && address < descriptor.StartOfMemoryRange + descriptor.DataSize) {

                    ulong offsetInRage = address - descriptor.StartOfMemoryRange;
                    miniDumpStream.Seek((long)(fileAddress + offsetInRage), SeekOrigin.Begin);
                    byte[] data = new byte[len];
                    miniDumpStream.Read(data, 0, data.Length);
                    return data;
                }
                fileAddress += descriptor.DataSize;
            }

            throw new ArgumentOutOfRangeException();
        }

        public override MemoryInfo QueryMemoryInfo(ulong address) {

            ulong fileAddress = memoryFullRVA;

            foreach (var descriptor in memoryInfoFull) {
                if (address >= descriptor.StartOfMemoryRange && address < descriptor.StartOfMemoryRange + descriptor.DataSize) {
                    return new MemoryInfo(descriptor.StartOfMemoryRange, descriptor.StartOfMemoryRange, descriptor.DataSize, false, false);                
                }
                fileAddress += descriptor.DataSize;
            }

            throw new ArgumentOutOfRangeException($"Memory address 0x{address:x} not mapped inside Minidump");
        }

        public override IEnumerable<MemoryInfo> QueryAllMemoryInfo() {
            return memoryInfoFull.Select(mi => new MemoryInfo(mi.StartOfMemoryRange, mi.StartOfMemoryRange, mi.DataSize, false, false));
        }
    }
}
