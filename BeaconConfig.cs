using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BeaconEye {
    using System;
    using System.Collections.Generic;
    using System.Net;


        public class BeaconConfig {
            private const int cobaltStrikeConfigSize = 0x1000;
            private const string format = "{0,-32} : {1}";
            public readonly Dictionary<int, BeaconSetting> beaconSettings = new Dictionary<int, BeaconSetting>();

            public static readonly Dictionary<int, byte> beaconVersionXorKey = new Dictionary<int, byte>
            {
            // XOR key associated with different beacon versions
            { 3, 0x69 },
            { 4, 0x2e }
            };

            // Key corresponds to byte value for each setting. Inner List contains setting name and type identifier
            public static readonly Dictionary<byte, List<string>> configFieldType = new Dictionary<byte, List<string>>
            {
            { 0x01, new List<string> { "BeaconType:", "beaconType" }},
            { 0x02, new List<string> { "Port:", "short" }},
            { 0x03, new List<string> { "Polling(ms):", "int" }},
            { 0x04, new List<string> { "MaxGetSize:", "int" }},
            { 0x05, new List<string> { "Jitter:", "short" }},
            { 0x06, new List<string> { "Maxdns:", "short" }},
            //{ 0x07, new List<string> { "PublicKey:", "bytes" }},
            { 0x08, new List<string> { "C2Server:", "string" }},
            { 0x09, new List<string> { "UserAgent:", "string" }},
            { 0x0a, new List<string> { "HTTP_Post_URI:", "string" }},
            { 0x0b, new List<string> { "HTTPGetServerOutput:", "program" }},
            { 0x0c, new List<string> { "HTTP_Get_Program:", "program" }},
            { 0x0d, new List<string> { "HTTP_Post_Program:", "program" }},
            { 0x0e, new List<string> { "Injection_Process:", "string" }},
            { 0x0f, new List<string> { "PipeName:", "string" }},
            // Options 0x10-0x12 are deprecated in 3.4
            { 0x10, new List<string> { "Year:", "int" }},
            { 0x11, new List<string> { "Month:", "int" }},
            { 0x12, new List<string> { "Day:", "int" }},
            { 0x13, new List<string> { "DNS_idle:", "int" }},
            { 0x14, new List<string> { "DNS_sleep(ms):", "int" }},
            { 0x1a, new List<string> { "HTTP_Method1:", "string" }},
            { 0x1b, new List<string> { "HTTP_ Method2:", "string" }},
            { 0x1c, new List<string> { "HttpPostChunk:", "int" }},
            { 0x1d, new List<string> { "Spawnto_x86:", "string" }},
            { 0x1e, new List<string> { "Spawnto_x64:", "string" }},
            { 0x1f, new List<string> { "CryptoScheme:", "short" }},
            { 0x20, new List<string> { "Proxy_HostName:", "string" }},
            { 0x21, new List<string> { "Proxy_UserName:", "string" }},
            { 0x22, new List<string> { "Proxy_Password:", "string" }},
            { 0x23, new List<string> { "Proxy_AccessType:", "accessType" }},
            // Deprecated { 0x24, new List<string> { "create_remote_thread:", "" }}, 
            { 0x25, new List<string> { "Watermark:", "int" }},
            { 0x26, new List<string> { "StageCleanup:", "bool" }},
            { 0x27, new List<string> { "CfgCaution:", "bool" }},
            { 0x28, new List<string> { "KillDate:", "int" }},
            // Not useful { 0x29, new List<string> { "TextSectionEnd:", "" }},
            //{ 0x2a, new List<string> { "ObfuscationSectionsInfo:", "" }},
            { 0x2b, new List<string> { "ProcInject_StartRWX:", "bool" }},
            { 0x2c, new List<string> { "ProcInject_UseRWX:", "bool" }},
            { 0x2d, new List<string> { "ProcInject_MinAllocSize:", "int" }},
            { 0x2e, new List<string> { "ProcInject_PrependAppend_x86:", "string" }},
            { 0x2f, new List<string> { "ProcInject_PrependAppend_x64:", "string" }},
            { 0x32, new List<string> { "UsesCookies:", "bool" }},
            { 0x33, new List<string> { "ProcInject_Execute:", "executeType" }},
            { 0x34, new List<string> { "ProcInject_AllocationMethod:", "allocationFunction" }},
            //{ 0x35, new List<string> { "ProcInject_Stub:", "string" }},
            { 0x36, new List<string> { "HostHeader:", "string" }},
            { 0x44, new List<string> {"RotateStrategy:", "int"}},
            { 0x45, new List<string> {"FailoverCount:", "int"}},
            { 0x46, new List<string> {"FailoverTime:", "int"}},

        };

            public BeaconConfig(byte[] processBytes, ulong c2BlockOffset, int version) {
                // C2 information starts 42 bytes after beginning of C2 block
                byte[] configBytes = new byte[cobaltStrikeConfigSize];
                Buffer.BlockCopy(processBytes, ((int)c2BlockOffset), configBytes, 0, cobaltStrikeConfigSize);

                // Check if the config section is already decoded
                byte[] decodedConfigBytes = new byte[cobaltStrikeConfigSize];
                if (version == 0) {
                    decodedConfigBytes = processBytes;
                } else {
                    // XOR decode the C2 block
                    decodedConfigBytes = DecodeConfigBytes(configBytes, version);
                }
                ParseTLV(decodedConfigBytes);
            }

            private void ParseTLV(byte[] configBytes) {
                int offset = 0;

                while (offset < configBytes.Length) {
                    // Retrieve the 6-byte config field header (TYPE) from the decoded C2 block
                    byte[] configField = new byte[6];

                    try {
                        Buffer.BlockCopy(configBytes, offset, configField, 0, 6);
                    } catch (ArgumentException) {
                        // May incorrectly parse some v4 config fields and try to copy past the length of the buffer. 
                        // If the end of configBytes has been reached, stop parsing.
                        break;
                    }

                    byte type = configField[1];
                    if(type == 0) {
                        break;
                    }

                    int dataLength = GetConfigFieldDataLength(configField);

                    // Retrieve the data for the given config field (VALUE)
                    byte[] configDataBytes = new byte[dataLength];
                    try {
                        Buffer.BlockCopy(configBytes, offset + 6, configDataBytes, 0, dataLength);
                    } catch (System.ArgumentException) {
                        // config field of 0x696969696969 or 0x2e2e2e2e2e2e should mean end of decoded data
                        break;
                    }

                    // Move to the start of the next config field header
                    offset += dataLength + 6;

                    
                    try {
                        beaconSettings.Add(type, new BeaconSetting(configFieldType[type], configDataBytes));
                    } catch (KeyNotFoundException) {
              
                    } catch (ArgumentException) {
                        // Catch failed attempts to parse some fields incorrectly 
                    }
                }
            }


            /// <summary>
            /// Determine the data size in bytes for a given CobaltStrike config field
            /// </summary>
            /// <param name="configField"></param>
            /// <returns>Int32 that contains the length of data in bytes for the given field</returns>
            private static int GetConfigFieldDataLength(byte[] configField) {
                // Swap endiannes for BitConverter
                byte[] tmp = new byte[2] { configField[3], configField[2] };
                short lengthField = BitConverter.ToInt16(tmp, 0);

                switch (lengthField) {
                    case 1:
                        return 2;
                    case 2:
                        return 4;
                    case 3:
                        short length = BitConverter.ToInt16(configField, 4);
                        length = IPAddress.HostToNetworkOrder(length);
                        return (int)length;
                    default:
                        return 4;
                        //throw new ArgumentException("Invalid length byte in config field");
                }
            }


            public static byte[] DecodeConfigBytes(byte[] configBytes, int version) {
                // Select appropriate XOR key based on detected version
                byte xorKey = BeaconConfig.beaconVersionXorKey[version];

                byte[] decoded = new byte[cobaltStrikeConfigSize];

                for (int i = 0; i < cobaltStrikeConfigSize; i++) {
                    decoded[i] = (byte)(configBytes[i] ^ xorKey);
                }

                return decoded;
            }

            /// <summary>
            /// Check a beacon's current settings for valid data 
            /// </summary>
            /// <returns>Returns true if beacon's data is valid, otherwise returns false</returns>
            public bool isValidBeacon() {
                bool isValidBeacon = true;
                // Check beacon type
                if (beaconSettings.ContainsKey(1)) {
                    BeaconSetting typeSetting = beaconSettings[1];
                    if (!BeaconSetting.beaconType.ContainsValue(typeSetting.SettingData.ToString()))
                        isValidBeacon = false;
                } else
                    isValidBeacon = false;

                // Check for valid port range
                if (beaconSettings.ContainsKey(2)) {
                    BeaconSetting portSetting = beaconSettings[2];
                    UInt16 port = 0;

                    try {
                        // UInt16 holds 0 - 65535 (port range)
                        port = Convert.ToUInt16(portSetting.SettingData);
                        if (port < 1024 || port > 49151) {
                            isValidBeacon = false;
                        }
                    } catch (OverflowException) {
                        // Port setting didn't contain valid data
                        isValidBeacon = false;
                    }
                } else
                    isValidBeacon = false;

                // Check for at least 20 settings
                if (beaconSettings.Count < 20) {
                    isValidBeacon = false;
                }

                // Check for deprecated fields that shouldn't exist in the config
                for (int i = 16; i < 19; i++) {
                    if (beaconSettings.ContainsKey(i))
                        isValidBeacon = false;
                }
                return isValidBeacon;
            }

            public void OutputToConsole() {
                foreach (KeyValuePair<int, BeaconSetting> setting in beaconSettings) {
                    // Unique formatting for HTTP headers which are lists of strings that can vary in length
                    if (setting.Value.SettingName.Contains("Header") && setting.Value.SettingData.ToString().Length > 0) {
                        List<string> headers = (List<string>)setting.Value.SettingData;

                        if (headers.Count > 0) {
                            Console.WriteLine(format, setting.Value.SettingName, headers[0]);

                            for (int i = 1; i < headers.Count; i++) {
                                Console.WriteLine(format, "", headers[i]);
                            }
                        } else {
                            Console.WriteLine(format, setting.Value.SettingName, "");
                        }
                    } else {
                        Console.WriteLine(format, setting.Value.SettingName, setting.Value.SettingData.ToString());
                    }
                }
                Console.WriteLine();
            }
        }

}
