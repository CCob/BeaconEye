using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace BeaconEye.Config {

    public enum Type {
        Unconfigured, 
        Short,
        Integer,
        Bytes, 
        String
    }

    /*
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
            { 0x44, new List<string> { "RotateStrategy:", "int" }},
            { 0x45, new List<string> { "FailoverCount:", "int" }},
            { 0x46, new List<string> { "FailoverTime:", "int" }},
    */


    [AttributeUsage(AttributeTargets.Class)]
    public class ConfigPropertyAttribute : Attribute {
        public Type ConfigType { get; set; }
        public int Index { get; set; }

    }

    public class Configuration {

        public class ConfigAttrbute{
            public int Index { get; private set; }
            public Type ConfigType { get; private set; }
            public string Name { get; private set; }
            public System.Type Type { get; private set; }

            public ConfigAttrbute(int index, Type configType, string name, System.Type objectType) {
                Index = index;
                ConfigType = configType;
                Name = name;
                Type = objectType;
            }
        }

        static Dictionary<int, ConfigAttrbute> configTypes = new Dictionary<int, ConfigAttrbute>();
        public Dictionary<string, ConfigItem> Items { get; private set; } = new Dictionary<string, ConfigItem>();

        static Configuration() {
            configTypes.Add(1, new ConfigAttrbute(1, Type.Short, "BeaconType", typeof(ConfigShortItem)));
            configTypes.Add(2, new ConfigAttrbute(2, Type.Short, "Port", typeof(ConfigShortItem)));
            configTypes.Add(3, new ConfigAttrbute(3, Type.Integer, "Sleep", typeof(ConfigIntegerItem)));
            configTypes.Add(4, new ConfigAttrbute(4, Type.Integer, "MaxGetSize",typeof(ConfigIntegerItem)));
            configTypes.Add(5, new ConfigAttrbute(5, Type.Short, "Jitter", typeof(ConfigShortItem)));
            configTypes.Add(6, new ConfigAttrbute(6, Type.Short, "MaxDNS", typeof(ConfigShortItem)));
            configTypes.Add(8, new ConfigAttrbute(8, Type.String, "C2Server", typeof(ConfigStringItem)));
            configTypes.Add(9, new ConfigAttrbute(9, Type.String, "UserAgent", typeof(ConfigStringItem)));
            configTypes.Add(10, new ConfigAttrbute(10, Type.String, "HTTP_Post_URI", typeof(ConfigStringItem)));
            configTypes.Add(11, new ConfigAttrbute(11, Type.String, "HTTPGetServerOutput", typeof(ConfigProgramItem)));
            configTypes.Add(12, new ConfigAttrbute(12, Type.String, "HTTP_Get_Program", typeof(ConfigProgramItem)));
            configTypes.Add(13, new ConfigAttrbute(13, Type.String, "HTTP_Post_Program", typeof(ConfigProgramItem)));
        } 
        

        public  Configuration(BinaryReader configReader, NtProcess process) {

            configReader.ReadBytes(16);
            int index = 1;

            while (configReader.BaseStream.Position < configReader.BaseStream.Length) {

                var type = (Type)configReader.ReadInt64();

                if (!configTypes.ContainsKey(index) || type == Type.Unconfigured) {
                    configReader.ReadBytes(8);
                    index++;
                    continue;
                }

                var configType = configTypes[index];
                ConfigItem configItem = (ConfigItem)Activator.CreateInstance(configType.Type, new object[] { configType.Name });
                configItem.Parse(configReader, process);
                                
                if(configItem != null)
                    Items.Add(configItem.Name, configItem);

                index++;
            }
        }
    }

    public abstract class ConfigItem {
        public string Name { get; protected set; }

        public ConfigItem(string name) {
            Name = name;
        }

        public abstract void Parse(BinaryReader br, NtProcess process);
    }

    public class ConfigShortItem : ConfigItem {

        public short Value { get; private set; }

        public ConfigShortItem(string name) : base(name) {
        }

        public override string ToString() {
            return $"{Name}: {Value}";
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = br.ReadInt16();
            br.ReadBytes(6);
        }
    }

    public class ConfigIntegerItem : ConfigItem {

        public int Value { get; private set; }

        public ConfigIntegerItem(string name) : base(name) {
   
        }

        public override string ToString() {
            return $"{Name}: {Value}";
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = br.ReadInt32();
            br.ReadBytes(4);
        }
    }

    public class ConfigStringItem : ConfigItem {

        public string Value { get; private set; }

        public ConfigStringItem(string name) : base(name) {
        }

        public override string ToString() {
            return $"{Name}: {Value}";
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = ReadNullString(process, br.ReadInt64());
        }

        string ReadNullString(NtProcess process, long address) {

            MemoryStream ms = new MemoryStream();

            while (true) {
                var strChar = process.ReadMemory(address++, 1);
                if (strChar[0] == '\0') {
                    break;
                }
                ms.Write(strChar, 0, 1);
            }

            return Encoding.ASCII.GetString(ms.ToArray());
        }
    }

    public class ConfigProgramItem : ConfigItem {

        public BeaconProgram Value { get; private set; }

        public ConfigProgramItem(string name) : base(name) {
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = BeaconProgram.Parse(br.ReadInt64(), process);         
        }
    }
}
