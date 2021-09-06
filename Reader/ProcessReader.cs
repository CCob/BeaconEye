using System.Collections.Generic;

namespace BeaconEye {
    public abstract class ProcessReader {

        static readonly uint SegmentHeapSignature = 0xffeeffee;

        public struct MemoryInfo {
            public ulong BaseAddress { get; }
            public ulong AllocationBase { get; }
            public ulong RegionSize { get; }
            public bool IsExecutable { get; }
            public bool NoAccess { get; }

            public MemoryInfo(ulong baseAddress, ulong allocationBase, ulong regionSize, bool isExecutable, bool noAccess) {
                BaseAddress = baseAddress;
                AllocationBase = allocationBase;
                RegionSize = regionSize;
                IsExecutable = isExecutable;
                NoAccess = noAccess;
            }
        }

        public abstract int ProcessId { get; }
        public abstract ulong PebAddress { get; }
        public abstract string Name { get; }
        public abstract bool Is64Bit { get; }       
        public abstract T ReadMemory<T>(ulong address) where T : new();
        public abstract byte[] ReadMemory(ulong address, int len);
        public abstract MemoryInfo QueryMemoryInfo(ulong address);
        public abstract IEnumerable<MemoryInfo> QueryAllMemoryInfo();

        public long ReadPointer(ulong address) {
            if (Is64Bit) {
                return ReadMemory<long>(address);
            } else {
                return ReadMemory<int>(address);
            }
        }

        bool IsSegmentHeap(long heapBase) {
            return ReadMemory<uint>((ulong)heapBase+0x10) == SegmentHeapSignature;
        }

        int PointerSize() {
            return (Is64Bit ? 8 : 4);
        }

        public List<long> Heaps { get {

                int numHeaps;
                long heapArray;

                if (Is64Bit) {
                    numHeaps = ReadMemory<int>(PebAddress + 0xE8);
                    heapArray = ReadPointer(PebAddress + 0xF0);
                } else {
                    numHeaps = ReadMemory<int>(PebAddress + 0x88);
                    heapArray = ReadPointer(PebAddress + 0x90);
                }

                var heaps = new List<long>();
                for (int idx = 0; idx < numHeaps; ++idx) {
                    var heap = ReadPointer((ulong)(heapArray + (idx * PointerSize())));
                    
                    if (IsSegmentHeap(heap)) {
                        var segmentListEntryForward = ReadPointer((ulong)heap + 0x18);
                        var segmentBase = ReadPointer((ulong)heap + 0x30);

                        while (!heaps.Contains(segmentBase)) {
                            heaps.Add(segmentBase);
                            segmentListEntryForward = ReadPointer((ulong)segmentListEntryForward + (ulong)PointerSize());
                            segmentBase = ReadPointer((ulong)segmentListEntryForward + 0x30);
                        }

                    } else {

                        //TODO: Handle Windows 10 Segment Heap 
                        heaps.Add(heap);
                    }
                }

                return heaps;
            }
        }
    }
}
