using System.Collections.Generic;
//using System.Diagnostics;

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

        public List<long> Heaps
        {
            get
            {

                int numHeaps;
                long heapArray;
                long segmentListEntry;


                //System.Console.WriteLine("Process Id: " + this.ProcessId);
                ////Ignore Large Memory Process
                //Process p = Process.GetProcessById(this.ProcessId);
                //if (p.PrivateMemorySize64 / (1024 * 1024) > 200)
                //{
                //    return new List<long>();
                //}

                //if (p.ProcessName == "explorer")
                //{
                //    return new List<long>();
                //}

                if (Is64Bit)
                {
                    numHeaps = ReadMemory<int>(PebAddress + 0xE8);
                    heapArray = ReadPointer(PebAddress + 0xF0);

                }
                else
                {
                    numHeaps = ReadMemory<int>(PebAddress + 0x88);
                    heapArray = ReadPointer(PebAddress + 0x90);
                }

                var heaps = new List<long>();
                for (int idx = 0; idx < numHeaps; ++idx)
                {
                    var heap = ReadPointer((ulong)(heapArray + (idx * (Is64Bit ? 8 : 4))));
                    long segmentEnd;
                    short xorkey;

                    //Get Heap Entry Xor Key
                    if (Is64Bit)
                    {
                        xorkey = ReadMemory<short>((ulong)heap + 0x88);
                    }
                    else
                    {
                        xorkey = ReadMemory<short>((ulong)heap + 0x50);
                    }

                    //Get SegmentListEntry
                    if (Is64Bit)
                    {
                        segmentListEntry = ReadPointer((ulong)heap + 0x18) - 0x18;
                    }
                    else
                    {
                        segmentListEntry = ReadPointer((ulong)heap + 0x10) - 0x10;
                    }
                    //Record LinkList
                    if (Is64Bit)
                    {
                        segmentEnd = ReadPointer((ulong)heap + 0x18 + 0x08) - 0x18;
                    }
                    else
                    {
                        segmentEnd = ReadPointer((ulong)heap + 0x10 + 0x04) - 0x10;
                    }

                    heaps.Add(segmentListEntry);
                    while (ReadPointer((ulong)segmentListEntry) != ReadPointer((ulong)segmentEnd))
                    {
                        if (Is64Bit)
                        {
                            segmentListEntry = ReadPointer((ulong)(segmentListEntry) + 0x18) - 0x18;
                            //Calculate Heap Entry

                            //Check Segment Signature
                            if (!IsSegmentHeap(segmentListEntry)) {
                                break;
                            }

                            //Record Fisrt And End
                            long firstHeapEntry = ReadPointer((ulong)segmentListEntry + 0x40);
                            long lastHeapEntry = ReadPointer((ulong)segmentListEntry + 0x48);

                            //If FirstHeapEntry Is Not Null
                            if (firstHeapEntry != 0)
                            {
                                short firstHeapSize;
                                try
                                {
                                    firstHeapSize = ReadMemory<short>((ulong)firstHeapEntry + 0x08);
                                }
                                catch (System.Exception e)
                                {
                                    //Can't Read Size
                                    break;
                                }

                                while (firstHeapEntry <= lastHeapEntry)
                                {
                                    //Decrypt Size
                                    int decryptSize = firstHeapSize ^ xorkey;

                                    //If Size Is Zero
                                    if (decryptSize == 0)
                                    {
                                        break;
                                    }

                                    //Get Unused Bytes
                                    byte unusedByteCount = ReadMemory<byte>((ulong)firstHeapEntry + 0x0f);

                                    //Get Next Entry
                                    firstHeapEntry = firstHeapEntry + 0x10 * decryptSize;
                                    heaps.Add(firstHeapEntry);
                                    try
                                    {
                                        firstHeapSize = ReadMemory<short>((ulong)firstHeapEntry + 0x08);
                                    }
                                    catch (System.Exception e)
                                    {
                                        //Can't Read Address
                                        break;
                                    }
                                }
                            }
                        }
                        else
                        {
                            segmentListEntry = ReadPointer((ulong)(segmentListEntry) + 0x10) - 0x10;
                        }
                        heaps.Add(segmentListEntry);
                        if (segmentListEntry == segmentEnd)
                        {
                            break;
                        }
                    }
                    heaps.Add(heap);
                }

                return heaps;
            }
        }
    }
}
