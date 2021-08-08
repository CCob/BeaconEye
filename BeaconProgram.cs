using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace BeaconEye { 

    public enum Action : int {
        NONE,
        APPEND,
        PREPEND,
        BASE64,
        PRINT,
        PARAMETER,
        HEADER,
        BUILD,
        NETBIOS,
        _PARAMETER,
        _HEADER,
        NETBIOSU,
        URI_APPEND,
        BASE64URL,
        STRREP,
        MASK,
        HOSTHEADER,
    }

    public class Statement {
        public Statement(Action action, byte[] argument) {
            Action = action;
            Argument = argument;
        }

        public Action Action { get; set; }

        public byte[] Argument { get; set; }

        public override string ToString() {
            return $"{Action}: {Encoding.ASCII.GetString(Argument)}";
        }
    }

    public class BeaconProgram {

        public List<Statement> Statements { get; set; } = new List<Statement>();

        byte[] NetBIOSDecode(byte[] source, bool upper) {

            byte baseChar = (byte)(upper ? 0x41 : 0x61);
            byte[] result = new byte[source.Length / 2];
          
            for (int idx = 0; idx < source.Length; idx += 2){
                result[idx/2] = ((byte)(((source[idx] - baseChar) << 4) | (source[idx + 1] - baseChar) & 0xf));               
            }

            return result;
        }

        byte[] MaskDecode(byte[] source) {

            var xorKey = source.Take(4).ToArray();
            var result = source.Skip(4).ToArray();

            for(int idx = 0; idx< result.Length; ++idx) {
                result[idx] ^= xorKey[idx % 4];
            }

            return result;
        }

        public byte[] RecoverOutput(byte[] source) {
            
            bool decode = false;
            byte[] decoded = source;
            bool done = false;
            var outputStatements = new List<Statement>();

            foreach (var statement in Statements) {
                switch (statement.Action) {
                    case Action.BUILD:
                        int buildType = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(statement.Argument, 0));
                        if (buildType == 1) {
                            decode = true;
                        }
                        break;
                    case Action.PRINT:
                        if (decode) {
                            done = true;
                            outputStatements.Reverse();
                        }
                        break;
                    default:
                        if (decode) {
                            outputStatements.Add(statement);
                        }
                        break;
                }

                if (done)
                    break;
            }

            foreach(var statement in outputStatements) {
                switch (statement.Action) {
                    case Action.BASE64URL:
                        decoded = Convert.FromBase64String(Uri.UnescapeDataString(Encoding.ASCII.GetString(decoded)));
                        break;
                    case Action.BASE64:
                        decoded = Convert.FromBase64String(Encoding.ASCII.GetString(decoded));
                        break;
                    case Action.PREPEND:
                        decoded = decoded.Skip(statement.Argument.Length).ToArray();
                        break;
                    case Action.APPEND:
                        decoded = decoded.Take(decoded.Length - statement.Argument.Length).ToArray();
                        break;
                    case Action.NETBIOSU:
                        decoded = NetBIOSDecode(decoded, true);
                        break;
                    case Action.NETBIOS:
                        decoded = NetBIOSDecode(decoded, false);
                        break;
                    case Action.MASK:
                        decoded = MaskDecode(decoded);
                        break;
                    default:
                        throw new NotImplementedException($"Statment with action {statement.Action} currently not supported, please open an issue on GitHub");
                }
            }

            return decoded;
        }

        internal static BeaconProgram Parse(long address, NtProcess process) {
; 
            var result = new BeaconProgram();
            bool done = false;

            while (!done) {
                var action = (Action)IPAddress.NetworkToHostOrder(process.ReadMemory<int>(address));
                address += 4;

                var actionParameter = new byte[0];
                switch (action) {
                    case Action.NONE:
                        done = true;
                        break;
                    
                    case Action.APPEND:
                    case Action.PREPEND:
                    case Action._HEADER:
                    case Action.HEADER:
                    case Action._PARAMETER:
                    case Action.PARAMETER:
                    case Action.HOSTHEADER:
                    case Action.URI_APPEND:
                    case Action.BASE64URL:
                        int actionParamLen = IPAddress.NetworkToHostOrder(process.ReadMemory<int>(address));
                        address += 4;
                        actionParameter = process.ReadMemory(address, actionParamLen);
                        address += actionParamLen;
                        break;
                    
                    case Action.BUILD:
                        actionParameter = process.ReadMemory(address, 4);
                        address += 4;
                        break;

                    case Action.BASE64:
                    case Action.PRINT:                   
                    case Action.NETBIOS:                   
                    case Action.NETBIOSU:                                                             
                    case Action.STRREP:
                    case Action.MASK:
                        break;                                        
                }

                if (action != Action.NONE) {
                    result.Statements.Add(new Statement(action, actionParameter));
                }                  
            }

            return result;
        }
    }

}
