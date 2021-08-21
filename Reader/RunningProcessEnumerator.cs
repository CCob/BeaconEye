using NtApiDotNet;
using System.Collections.Generic;
using System.Linq;

namespace BeaconEye.Reader {
    class RunningProcessEnumerator : IProcessEnumerator {
        public IEnumerable<ProcessReader> GetProcesses() {
            return NtProcess.GetProcesses(ProcessAccessRights.AllAccess)
                .Where(p => p.ExitNtStatus == NtStatus.STATUS_PENDING)
                .Select(p => new NtProcessReader(p));
        }
    }
}
