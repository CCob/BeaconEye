using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace BeaconEye.Reader {
    class MiniDumpProcessEnumerator : IProcessEnumerator {

        readonly string searchPath;

        public MiniDumpProcessEnumerator(string searchPath) {
            this.searchPath = searchPath;
        }

        public IEnumerable<ProcessReader> GetProcesses() {
            return Directory.EnumerateFiles(searchPath)
                .Where(file => file.ToLower().EndsWith("mdmp") || file.ToLower().EndsWith("dmp"))
                .Select(p => new MiniDumpReader(p));                
        }
    }
}
