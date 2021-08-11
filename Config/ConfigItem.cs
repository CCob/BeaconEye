using NtApiDotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
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
            public string Name { get; private set; }
            public System.Type Type { get; private set; }

            public ConfigAttrbute(int index, string name, System.Type objectType) {
                Index = index;
                Name = name;
                Type = objectType;
            }
        }

        static Dictionary<int, ConfigAttrbute> configTypes = new Dictionary<int, ConfigAttrbute>();
        public Dictionary<string, ConfigItem> Items { get; private set; } = new Dictionary<string, ConfigItem>();
        public long Address { get; private set; }

        int configEntrySize;

        static Configuration() {
            configTypes.Add(1, new ConfigAttrbute(1, "BeaconType", typeof(ConfigShortItem)));
            configTypes.Add(2, new ConfigAttrbute(2, "Port", typeof(ConfigShortItem)));
            configTypes.Add(3, new ConfigAttrbute(3, "Sleep", typeof(ConfigIntegerItem)));
            configTypes.Add(4, new ConfigAttrbute(4, "MaxGetSize",typeof(ConfigIntegerItem)));
            configTypes.Add(5, new ConfigAttrbute(5, "Jitter", typeof(ConfigShortItem)));
            configTypes.Add(6, new ConfigAttrbute(6, "MaxDNS", typeof(ConfigShortItem)));
            configTypes.Add(8, new ConfigAttrbute(8, "C2Server", typeof(ConfigStringItem)));
            configTypes.Add(9, new ConfigAttrbute(9, "UserAgent", typeof(ConfigStringItem)));
            configTypes.Add(10, new ConfigAttrbute(10, "HTTP_Post_URI", typeof(ConfigStringItem)));
            configTypes.Add(11, new ConfigAttrbute(11, "HTTPGetServerOutput", typeof(ConfigProgramItem)));
            configTypes.Add(12, new ConfigAttrbute(12, "HTTP_Get_Program", typeof(ConfigProgramItem)));
            configTypes.Add(13, new ConfigAttrbute(13, "HTTP_Post_Program", typeof(ConfigProgramItem)));
            configTypes.Add(14, new ConfigAttrbute(14, "Inject_Process", typeof(ConfigStringItem)));
            configTypes.Add(15, new ConfigAttrbute(15, "PipeName", typeof(ConfigStringItem)));
            configTypes.Add(19, new ConfigAttrbute(19, "DNS_idle", typeof(ConfigIntegerItem)));
            configTypes.Add(20, new ConfigAttrbute(20, "DNS_sleep", typeof(ConfigIntegerItem)));
            configTypes.Add(26, new ConfigAttrbute(26, "HTTP_Method1", typeof(ConfigStringItem)));
            configTypes.Add(27, new ConfigAttrbute(27, "HTTP_Method2", typeof(ConfigStringItem)));
            configTypes.Add(28, new ConfigAttrbute(28, "HttpPostChunk", typeof(ConfigIntegerItem)));
            configTypes.Add(29, new ConfigAttrbute(29, "Spawnto_x86", typeof(ConfigStringItem)));
            configTypes.Add(30, new ConfigAttrbute(30, "Spawnto_x64", typeof(ConfigStringItem)));
            configTypes.Add(32, new ConfigAttrbute(32, "Proxy_Host", typeof(ConfigStringItem)));
            configTypes.Add(33, new ConfigAttrbute(33, "Proxy_Username", typeof(ConfigStringItem)));
            configTypes.Add(34, new ConfigAttrbute(34, "Proxy_Password", typeof(ConfigStringItem)));
            configTypes.Add(37, new ConfigAttrbute(37, "Watermark", typeof(ConfigIntegerItem)));
            configTypes.Add(38, new ConfigAttrbute(38, "StageCleanup", typeof(ConfigShortItem)));
            configTypes.Add(39, new ConfigAttrbute(39, "CfgCaution", typeof(ConfigShortItem)));
            configTypes.Add(40, new ConfigAttrbute(40, "KillDate", typeof(ConfigIntegerItem)));
            configTypes.Add(54, new ConfigAttrbute(54, "Host_Header", typeof(ConfigStringItem)));
        }


        public  Configuration(long configAddress, BinaryReader configReader, NtProcess process) {

            Address = configAddress;
            configEntrySize = process.Is64Bit ? 16 : 8;
            configReader.ReadBytes(configEntrySize);
            int index = 1;

            while (configReader.BaseStream.Position < configReader.BaseStream.Length) {

                Type type;

                if (configEntrySize == 16)
                    type = (Type)configReader.ReadInt64();
                else
                    type = (Type)configReader.ReadInt32();

                if (!configTypes.ContainsKey(index) || type == Type.Unconfigured) {
                    configReader.ReadBytes(configEntrySize/2);
                    index++;
                    continue;
                }

                var configType = configTypes[index];
                ConfigItem configItem = (ConfigItem)Activator.CreateInstance(configType.Type, new object[] { configType.Name });

                if(configItem.ExpectedType != type) {
                    throw new FormatException("Serialized config format does not match configuration type");
                }

                configItem.Parse(configReader, process);

                if(configReader.BaseStream.Position % configEntrySize != 0)
                    configReader.ReadBytes(configEntrySize - (int)configReader.BaseStream.Position % configEntrySize);
                                
                if(configItem != null)
                    Items.Add(configItem.Name, configItem);

                index++;
            }
        }

        public void PrintConfiguration(TextWriter writer, int numTabs) {
            foreach (var config in Items) {
                if (!string.IsNullOrWhiteSpace(config.Value.ToString())) {
                    writer.Write(new string('\t', numTabs));
                    writer.WriteLine(config.Value);
                }
                        }
        }
    }

    public abstract class ConfigItem {
        public string Name { get; protected set; }

        public abstract Type ExpectedType { get; }

        public ConfigItem(string name) {
            Name = name;
        }

        public abstract void Parse(BinaryReader br, NtProcess process);
    }

    public class ConfigShortItem : ConfigItem {

        public short Value { get; private set; }
        public override Type ExpectedType => Type.Short;

        public ConfigShortItem(string name) : base(name) {
        }

        public override string ToString() {
            return $"{Name}: {Value}";
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = br.ReadInt16();
        }
    }

    public class ConfigIntegerItem : ConfigItem {

        public int Value { get; private set; }
        public override Type ExpectedType => Type.Integer;

        public ConfigIntegerItem(string name) : base(name) {
   
        }

        public override string ToString() {
            return $"{Name}: {Value}";
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = br.ReadInt32();
        }
    }

    public class ConfigStringItem : ConfigItem {

        public override Type ExpectedType => Type.Bytes;

        public string Value { get; private set; }

        public ConfigStringItem(string name) : base(name) {
        }

        public override string ToString() {
            return $"{Name}: {Value}";
        }

        public override void Parse(BinaryReader br, NtProcess process) {            
            Value = ReadNullString(process, process.Is64Bit ? br.ReadInt64() : br.ReadInt32());
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

        public override Type ExpectedType => Type.Bytes;

        public BeaconProgram Value { get; private set; }

        public ConfigProgramItem(string name) : base(name) {
        }

        public override void Parse(BinaryReader br, NtProcess process) {
            Value = BeaconProgram.Parse(process.Is64Bit ? br.ReadInt64() : br.ReadInt32(), process);         
        }

        public override string ToString() {
            var str = new StringBuilder();
            str.AppendLine();
            
            foreach(var statement in Value.Statements) {  
                
                if(statement.Action == Action.NONE) {
                    break;
                }else if(statement.Action == Action.BUILD) {                    
                    int type = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(statement.Argument, 0));
                    if(type == 1) {
                        str.AppendLine("\t\toutput:");
                    } else {
                        str.AppendLine("\t\tid|meta:");
                    }
                    continue;
                }
                
                str.AppendLine($"\t\t{statement}"); 
            }
            return str.ToString();
        }
    }
}
