using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace BeaconEye {
    public class BeaconSetting {
        public string SettingName;
        public int SettingLength;
        public object SettingData;

        public static readonly Dictionary<int, string> beaconType = new Dictionary<int, string>
        {
            { 0, "0 (HTTP)"},
            { 1, "1 (Hybrid HTTP and DNS)"},
            { 2, "2 (SMB)"},
            { 4, "4 (TCP)"},
            { 8, "8 (HTTPS)"},
            { 16, "16 (Bind TCP)" }
        };

        public static readonly Dictionary<int, string> accessType = new Dictionary<int, string>
        {
            { 1, "1 (use direct connection)"},
            { 2, "2 (use IE settings)"},
            { 4, "4 (use proxy server)" }
        };

        public static readonly Dictionary<int, string> executeType = new Dictionary<int, string>
        {
            { 1, "CreateThread" },
            { 2, "SetThreadContext" },
            { 3, "CreateRemoteThread" },
            { 4, "RtlCreateUserThread" },
            { 5, "NtQueueApcThread" },
            { 8, "NtQueueApcThread-s"}
        };

        public static readonly Dictionary<int, string> allocationFunction = new Dictionary<int, string>
        {
            { 0, "VirtualAllocEx" },
            { 1, "NtMapViewOfSection" }
        };

        public BeaconSetting(List<string> configField, byte[] settingData) {
            SettingName = configField[0];

            // Determine type of this variable at runtime based on which setting is being added
            switch (configField[1]) {
                case "beaconType":
                    int beaconTypeKey = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(settingData, 0));
                    SettingData = beaconType[beaconTypeKey];
                    break;
                case "executeType":
                    int executeTypeKey = BitConverter.ToInt16(settingData, 0);
                    SettingData = executeType[executeTypeKey];
                    break;
                case "accessType":
                    int accessTypeKey = BitConverter.ToInt16(settingData, 0);
                    SettingData = accessType[accessTypeKey];
                    break;
                case "allocationFunction":
                    int allocationFunctionKey = BitConverter.ToInt16(settingData, 0);
                    SettingData = allocationFunction[allocationFunctionKey];
                    break;
                case "string":
                    SettingData = Encoding.UTF8.GetString(settingData).Replace("\0", string.Empty);
                    break;
                case "int":
                    SettingData = BigEndianBytesToInt(settingData);
                    break;
                case "bool":
                    SettingData = GetBoolValue(SettingName, settingData);
                    break;
                case "header":
                    SettingData = ParseHTTPHeaders(settingData);
                    break;
                case "short":
                    SettingData = BigEndianBytesToShort(settingData);
                    break;
                case "bytes":
                    SettingData = settingData;
                    break;
                case "program":
                    //SettingData = BeaconProgram.Parse(settingData);
                    break;
            }
        }


        /// <summary>
        /// Convert a 2 or 4 byte big endian-ordered bytearray to its decimal numeric value.  
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>The numeric value of input bytearray as a string</returns>
        private static int BigEndianBytesToInt(byte[] bytes) {
            int number;

            if (bytes.Length == 2) {
                number = BitConverter.ToInt16(bytes, 0);
                number = IPAddress.HostToNetworkOrder(number);
            } else if (bytes.Length == 4) {
                number = BitConverter.ToInt32(bytes, 0);
                number = IPAddress.HostToNetworkOrder(number);
            } else {
                throw new System.ArgumentException("'bytes' param should be 2 or 4 bytes in length");
            }

            return number;
        }

        /// <summary>
        /// Get the numeric value from 2 bytes in big-endian order and output the resultant number as a short
        /// </summary>
        /// <param name="bytes">2-byte big-endian number</param>
        /// <returns>Returns a short containing the number converted from the 2-byte input value</returns>
        private static short BigEndianBytesToShort(byte[] bytes) {
            short number = BitConverter.ToInt16(bytes, 0);
            return IPAddress.HostToNetworkOrder(number);
        }

        /// <summary>
        /// Get the boolean value for Beacon config fields based on the field name.
        /// </summary>
        /// <param name="settingName">The name of the setting with a boolean value</param>
        /// <param name="bytes"></param>
        /// <returns>Returns a bool representing whether the particular setting is on/off</returns>
        private static bool GetBoolValue(string settingName, byte[] bytes) {
            int falseValue;

            switch (settingName) {
                case "ProcInject_StartRWX":
                    falseValue = 4;
                    break;
                case "ProcInject_UseRWX":
                    falseValue = 32;
                    break;
                default:
                    falseValue = 0;
                    break;
            }

            if (BigEndianBytesToInt(bytes) != falseValue) {
                return true;
            } else {
                return false;
            }
        }

        /// <summary>
        /// Parse a byte[] to retrieve a sequence of HTTP headers as strings and return the headers as a list of strings
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns>Returns a list of strings containing HTTP headers extracted from the byte[] parameter</returns>
        private static List<string> ParseHTTPHeaders(byte[] bytes) {
            List<string> headers = new List<string>();

            // Strip the leading and trailing null bytes from the headers
            byte[] stripped = new byte[bytes.Length - 1];
            Buffer.BlockCopy(bytes, 1, stripped, 0, bytes.Length - 1);


            string[] test = Encoding.UTF8.GetString(bytes).Split('\0');

            foreach (string header in test) {
                if (header.Length > 1) {
                    headers.Add(header.Substring(1));
                }
            }

            return headers;
        }
    }
}
