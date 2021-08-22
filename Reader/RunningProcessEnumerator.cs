using NtApiDotNet;
using System.Collections.Generic;
using System.Linq;

namespace BeaconEye.Reader {
    class RunningProcessEnumerator : IProcessEnumerator {

        string filter;

        public RunningProcessEnumerator(string filter) {
            this.filter = filter;
        }

        public IEnumerable<ProcessReader> GetProcesses() {
            return NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                .Where(p => p.ExitNtStatus == NtStatus.STATUS_PENDING && (string.IsNullOrEmpty(filter) ? p.Name.Length > 0 : p.Name.ToLower().StartsWith(filter.ToLower())) )
                .Select(p => new NtProcessReader(p));
        }
    }
}
