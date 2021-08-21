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
        append,
        prepend,
        base64,
        print,
        parameter,
        header,
        BUILD,
        netbios,
        _PARAMETER,
        _HEADER,
        netbiosu,
        uri_append,
        base64url,
        strrep,
        mask,
        hostheader,
    }

    public class Statement {
        public Statement(Action action, byte[] argument) {
            Action = action;
            Argument = argument;
        }

        public Action Action { get; set; }

        public byte[] Argument { get; set; }

        public override string ToString() {

            string action = Action.ToString();
            if(Action == Action._HEADER) {
                action = "header";
            }else if(Action == Action._PARAMETER) {
                action = "parameter";
            }

            return $"{action} {Encoding.ASCII.GetString(Argument)};";
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
                    case Action.print:
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
                    case Action.base64url:
                        decoded = Convert.FromBase64String(Uri.UnescapeDataString(Encoding.ASCII.GetString(decoded)));
                        break;
                    case Action.base64:
                        decoded = Convert.FromBase64String(Encoding.ASCII.GetString(decoded));
                        break;
                    case Action.prepend:
                        decoded = decoded.Skip(statement.Argument.Length).ToArray();
                        break;
                    case Action.append:
                        decoded = decoded.Take(decoded.Length - statement.Argument.Length).ToArray();
                        break;
                    case Action.netbiosu:
                        decoded = NetBIOSDecode(decoded, true);
                        break;
                    case Action.netbios:
                        decoded = NetBIOSDecode(decoded, false);
                        break;
                    case Action.mask:
                        decoded = MaskDecode(decoded);
                        break;
                    default:
                        throw new NotImplementedException($"Statment with action {statement.Action} currently not supported, please open an issue on GitHub");
                }
            }

            return decoded;
        }

        internal static BeaconProgram Parse(long address, ProcessReader process) {
; 
            var result = new BeaconProgram();
            bool done = false;

            while (!done) {
                var action = (Action)IPAddress.NetworkToHostOrder(process.ReadMemory<int>((ulong)address));
                address += 4;

                var actionParameter = new byte[0];
                switch (action) {
                    case Action.NONE:
                        done = true;
                        break;
                    
                    case Action.append:
                    case Action.prepend:
                    case Action._HEADER:
                    case Action.header:
                    case Action._PARAMETER:
                    case Action.parameter:
                    case Action.hostheader:
                    case Action.uri_append:
                    case Action.base64url:
                        int actionParamLen = IPAddress.NetworkToHostOrder(process.ReadMemory<int>((ulong)address));
                        address += 4;
                        actionParameter = process.ReadMemory((ulong)address, actionParamLen);
                        address += actionParamLen;
                        break;
                    
                    case Action.BUILD:
                        actionParameter = process.ReadMemory((ulong)address, 4);
                        address += 4;
                        break;

                    case Action.base64:
                    case Action.print:                   
                    case Action.netbios:                   
                    case Action.netbiosu:                                                             
                    case Action.strrep:
                    case Action.mask:
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
