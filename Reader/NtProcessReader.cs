using NtApiDotNet;
using System.Collections.Generic;
using System.Linq;

namespace BeaconEye {
    public class NtProcessReader : ProcessReader {

        NtProcess process;

        public NtProcess Process => process;
        public override string Name => process.Name;

        public override bool Is64Bit => process.Is64Bit;

        public override ulong PebAddress => (ulong)(Is64Bit ? process.PebAddress : process.PebAddress32);

        public override int ProcessId => process.ProcessId;

        public NtProcessReader(NtProcess process) {
            this.process = process;
        }

        public override byte[] ReadMemory(ulong address, int len) {
            return process.ReadMemory((long)address, len);
        }

        public override T ReadMemory<T>(ulong address) {
            return process.ReadMemory<T>((long)address);
        }

        public override MemoryInfo QueryMemoryInfo(ulong address) {
            var info = process.QueryMemoryInformation((long)address);
            return new MemoryInfo((ulong)info.BaseAddress, (ulong)info.AllocationBase, (ulong)info.RegionSize, 
                info.Protect == MemoryAllocationProtect.ExecuteRead || info.Protect == MemoryAllocationProtect.ExecuteReadWrite);
        }

        public override IEnumerable<MemoryInfo> QueryAllMemoryInfo() {
            return process.QueryAllMemoryInformation().Select(info => new MemoryInfo((ulong)info.BaseAddress, (ulong)info.AllocationBase, (ulong)info.RegionSize,
                info.Protect == MemoryAllocationProtect.ExecuteRead || info.Protect == MemoryAllocationProtect.ExecuteReadWrite));            
        }
    }
}
