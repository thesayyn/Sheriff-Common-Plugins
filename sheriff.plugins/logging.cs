using System;
using System.Dynamic;
using System.Collections.Generic;
using System.Linq;

using Sheriff.Networking;
using Sheriff.Security;
using Sheriff.Common.Plugins;

namespace sheriff.plugins
{
    class logging : IPlugin
    {
        public override string Name => "Günlük";

        public override string Author => "Şerif Geliştirici Takımı";

        public override string Description => "Eşsiz canavar çıkma olayları ve  kullanıcı sohbet olaylarını kayıt altında tutabilirsiniz.";

        public override Version Version => new Version("1.0.0.0");

        bool clog_enabled,ulog_enabled;


        List<ExpandoObject> uniquedata = new List<ExpandoObject>();
        List<ExpandoObject> chatdata = new List<ExpandoObject>();


        IClient sniffer = null;

        public override void OnLoad()
        {

            this.GetSettings().Register<bool>("c-logging", "clog-enabled", "Sohbet kaydı tutma.");
            this.GetSettings().Register<bool>("u-logging", "ulog-enabled", "Canavar kaydı tutma.");
            this.RegisterApi("unique");
            this.RegisterApi("chat");
            LoadSetttings();
        }

        public override void OnClientDisconnected(IClient client)
        {
            if (sniffer == null) sniffer = client;
        }

        public override bool OnPacketReceived(Packet packet, IClient client)
        {
            if (sniffer == null) sniffer = client;
            if (sniffer != client) return true;

            if(packet.Opcode == 0x300C) 
            {
                byte type = packet.ReadUInt8();

                if(type == 5)
                {
                    packet.ReadUInt8(); // Unkbyte

                    dynamic jit = new ExpandoObject();
                    jit.type = "spawn";
                    jit.uniqueid = packet.ReadUInt32();
                    jit.datetime = DateTime.Now;
                    uniquedata.Add(jit);

                }
                else if(type == 6)
                {
                    packet.ReadUInt8(); // Unkbyte

                    dynamic jit = new ExpandoObject();
                    jit.type = "dead";
                    jit.uniqueid = packet.ReadUInt32();
                    jit.killer = packet.ReadAscii();
                    jit.datetime = DateTime.Now;
                    uniquedata.Add(jit);
                }
            }
            else
            {
                byte chatType = packet.ReadUInt8();
                if(chatType == 6)
                {
                    string sender = packet.ReadAscii();
                    string message = packet.ReadAscii();
                    dynamic jit = new ExpandoObject();
                    jit.Name = sender;
                    jit.Message = message;
                    this.chatdata.Add(jit);
                }

            }

            return true;
        }


        public override object OnApiRequested(Request request)
        {
            int takes = 10;
            try
            {
               takes = int.Parse(request.GetParameter("take"));
            }
            catch {  }
            
            GetLogger().Info("Api Requested");
            if(request.DataSource == "unique")
            {
                uniquedata.Reverse();
                List<ExpandoObject> datas = uniquedata.Take(takes).ToList();
                uniquedata.Reverse();
                return datas;
            }
            else
            {
                chatdata.Reverse();
                List<ExpandoObject> datas = chatdata.Take(takes).ToList();
                chatdata.Reverse();
                return datas;
            }
        }

        public override void OnSettingsChanged()
        {
            LoadSetttings();
        }
        public override void OnUnLoad()
        {
            this.chatdata = new List<ExpandoObject>();
            this.uniquedata = new List<ExpandoObject>();
            this.sniffer = null;
        }




        void LoadSetttings()
        {
            this.clog_enabled = this.GetSettings().Get<bool>("clog-enabled");
            this.ulog_enabled = this.GetSettings().Get<bool>("ulog-enabled");

            if(this.clog_enabled)
            { this.Register(0x3026); }
            else
            { this.UnRegister(0x3026); }

            if (this.ulog_enabled)
            { this.Register(0x300C); }
            else
            { this.UnRegister(0x300C); }
        }
    }
}
