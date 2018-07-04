using Sheriff.Common.Plugins;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Sheriff.Networking;
using Sheriff.Security;
using sheriff.plugins.aes;

namespace sheriff.plugins
{
    class fp
    {
       public IClient client;
       public string hash;
       public bool isvmware;
       public bool isvpc;
       public string providerkey;
    }

    class Limitation : IPlugin
    {
        public override string Name => "Sınırlama";
        public override string Author => "Şerif Geliştirici Takımı";
        public override string Description => "Buu eklenti sayesinde ip limit & fingerprint sınırı uygulayabilirsiniz.";
        public override Version Version => new Version("1.0.0.0");

        private List<fp> fplist = new List<fp>();
        private List<IClient> clist = new List<IClient>();

        bool fp_enabled, fp_allow_vmware, fp_allow_vpc;
        int fp_limit;

        bool ip_enabled;
        int ip_limit;

        string provider_key;

        public override void OnLoad()
        {

           
            this.GetSettings().Register<bool>("sheriffone-fp", "fp-enabled", "Sheriff™ One® fingerprint limitation.");
            this.GetSettings().Register<int>("sheriffone-fp", "fp-limit-per-machine", "Client limit per computer.");
            this.GetSettings().Register<bool>("sheriffone-fp", "fp-allow-vwware", "Allow VMWare based clients.");
            this.GetSettings().Register<bool>("sheriffone-fp", "fp-allow-vpc", "Allow virtual computer based clients.");

            this.GetSettings().Register<bool>("sheriffone-ip", "ip-enabled", "Sheriff™ One® ip limitation.");
            this.GetSettings().Register<int>("sheriffone-ip", "ip-limit-per-machine", "Client limit per ip address.");

            this.GetSettings().Register<string>("sheriffone-crypt", "crypt-key", "Sheriff™ One® network crypt key.");
            this.GetSettings().Register<string>("sheriffone-crypt", "crypt-iv", "Sheriff™ One® network crypt iv.");
            this.GetSettings().Register<string>("sheriffone-crypt", "key", "Sheriff™ One® network provider key.");

            if (this.GetSettings().Get<string>("crypt-key").Length < 32)
                this.GetSettings().Set<string>("crypt-key", "dHQ8W?Bx(d(BIv%T?((JPWdY1tq7dbX7");

            if (this.GetSettings().Get<string>("crypt-iv").Length < 16)
                this.GetSettings().Set<string>("crypt-iv", "#C(.wdy9Ku1V1d8D");

            if (this.GetSettings().Get<string>("key").Length < 32)
                this.GetSettings().Set<string>("key", "B=!?(Su4m!(d7q859RSdYAQEb.(b(((#");



            LoadSettings();
            
        }
        public override void OnUnLoad()
        {
            this.fplist = new List<fp>();
            this.clist = new List<IClient>();
        }

        public override bool OnPacketReceived(Packet packet, IClient client)
        {
            
            if(packet.Opcode ==  0x133D && !fp_enabled)
            {
                packet.Replace(new Packet(0x2002));
                return true;
            }

            if(packet.Opcode == 0x133D)
            {

                if (!fp_enabled) return false;

                try {

                    ushort version = packet.ReadUInt16();
                    packet.ReadAscii();

                    int size = packet.ReadUInt16();
                    byte[] bytes = packet.ReadBytes(size);
                    byte[] decryptedbytes = AES.Decrypt(bytes);

                    PacketReader reader = new PacketReader(decryptedbytes);

                    string fp = Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadUInt16()));
                    bool isVMWare =  reader.ReadByte() == 1;
                    bool isVPC = reader.ReadByte() == 1;
                    string key =  Encoding.UTF8.GetString(reader.ReadBytes(reader.ReadUInt16()));

                    fp user =  new fp()
                    {
                        client = client,
                        hash = fp,
                        isvmware = isVMWare,
                        isvpc = isVPC,
                        providerkey = key
                    };

                    fp find = this.fplist.Find(x => x.client == client);

                    if(user.isvmware && !fp_allow_vmware)
                    {
                        client.Disconnect();
                        GetLogger().Trace("The user will be disconnected due use VMWare.");
                        return false;
                    }

                    if (user.isvpc && !fp_allow_vpc)
                    {
                        client.Disconnect();
                        GetLogger().Trace("The user will be disconnected due use VPC.");
                        return false;
                    }

                    if (key != provider_key)
                    {
                        client.Disconnect();
                        GetLogger().Trace("The user will be disconnected due wrong provider key.");
                        return false;
                    }



                    if (find == null)
                    {
                        this.fplist.Add(user);
                        CheckSameFPs(user);
                    }
                    else
                    {
                        this.fplist.Remove(find);
                        this.fplist.Add(user);
                        CheckSameFPs(user);
                    }

                    GetLogger().Trace("FP:"+user.hash);
                }
                catch(Exception e)
                {
                    GetLogger().Warn(e);
                    GetLogger().Trace("Something went wrong. The User IP = {0}, Packet Hex Bytes = {1}",client.IPAddress,ByteArrayExtension.HexDump(packet.GetBytes()));
                }

                packet.Replace(new Packet(0x2002));
                return true;
           }

            if(packet.Opcode == 0xA102)
            {
                if (ip_enabled)
                {
                    List<IClient> ips = GetSameIPs(client);

                    if (ips.Count > ip_limit)
                    {
                        Packet resp = new Packet(packet.Opcode, packet.Encrypted, packet.Massive);
                        resp.WriteUInt8(0x02);
                        resp.WriteUInt8(0xF);
                        resp.Lock();
                        packet.Replace(resp);

                    }
                }


                if (fp_enabled)
                {
                    List<fp> fps = GetSameFps(client);

                     if(fps.Count > fp_limit || fps.Count == 0)
                    {
                        Packet resp = new Packet(packet.Opcode, packet.Encrypted, packet.Massive);
                        resp.WriteUInt8(0x02);
                        resp.WriteUInt8(0xF);
                        resp.Lock();
                        packet.Replace(resp);

                    }
                }
            }

            return true;
        }


        public override bool OnClientConnected(IClient client)
        {
            this.clist.Add(client);
            return true;
        }
        public override void OnClientDisconnected(IClient client)
        {
            this.fplist.RemoveAll(x => x.client == client);
            this.clist.Remove(client);
        }


        public override void OnSettingsChanged()
        {
            LoadSettings();
            this.fplist.ForEach(x => CheckSameFPs(x));
            this.clist.ForEach(x => CheckSameIPs(x));
        }
        void LoadSettings()
        {
            AES.IV = this.GetSettings().Get<string>("crypt-iv");
            AES.KEY = this.GetSettings().Get<string>("crypt-key");
            this.fp_enabled = this.GetSettings().Get<bool>("fp-enabled");
            this.fp_allow_vmware = this.GetSettings().Get<bool>("fp-allow-vwware");
            this.fp_allow_vpc = this.GetSettings().Get<bool>("fp-allow-vpc");
            this.fp_limit = this.GetSettings().Get<int>("fp-limit-per-machine");

            this.ip_enabled = this.GetSettings().Get<bool>("ip-enabled");

            this.ip_limit = this.GetSettings().Get<int>("ip-limit-per-machine");
            this.provider_key = this.GetSettings().Get<string>("key");


            this.Register(0x133D);
            this.Register(0xA102);

        }

        void CheckSameFPs(fp user)
        {
            List<fp> list = this.fplist.FindAll(x => x.hash == user.hash);
            if (list.Count > this.fp_limit)
            {
                list[list.Count - 1].client.Disconnect();
                this.fplist.Remove(list[list.Count - 1]);
                CheckSameFPs(user);
            }
        }
        void CheckSameIPs(IClient user)
        {
            List<IClient> list = this.clist.FindAll(x => x.IPAddress == user.IPAddress);
            if (list.Count > this.ip_limit)
            {
                clist[clist.Count - 1].Disconnect();
                this.clist.Remove(clist[clist.Count - 1]);
                CheckSameIPs(user);
            }
        }

        List<fp> GetSameFps(IClient client)
        {
            fp find = this.fplist.Find(x => x.client == client);
            return this.fplist.FindAll(x => x.hash == find.hash);
        }
        List<IClient> GetSameIPs(IClient client)
        {
            return this.clist.FindAll(x => x.IPAddress == client.IPAddress);
        }

    }
}
