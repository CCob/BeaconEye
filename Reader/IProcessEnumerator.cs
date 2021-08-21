using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BeaconEye.Reader {
    public interface IProcessEnumerator {
        IEnumerable<ProcessReader> GetProcesses();
    }
}
