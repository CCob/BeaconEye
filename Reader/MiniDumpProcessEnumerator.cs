using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BeaconEye.Reader {
    class MiniDumpProcessEnumerator : IProcessEnumerator {

        public bool Verbose { get; private set; }

        readonly string searchPath;

        public MiniDumpProcessEnumerator(string searchPath, bool verbose) {
            this.searchPath = searchPath;
            this.Verbose = verbose;
        }

        public IEnumerable<ProcessReader> GetProcesses() {

            var minidumpReaders = new List<ProcessReader>();
            var minidumpFiles = Directory.EnumerateFiles(searchPath)
                .Where(file => file.ToLower().EndsWith("mdmp") || file.ToLower().EndsWith("dmp"));

            foreach(var minidumpFile in minidumpFiles) {
                try {
                    minidumpReaders.Add(new MiniDumpReader(minidumpFile));
                }catch(FormatException fe) {
                    if(Verbose)
                        Console.WriteLine($"[=] Failed to open minidump {Path.GetFileName(minidumpFile)} with error: {fe.Message}");
                }
            }

            return minidumpReaders;                  
        }
    }
}
