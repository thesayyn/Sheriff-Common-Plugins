using System;
using Sheriff.Common.Plugins;
using System.Collections.Generic;
using Sheriff.Networking;
using Sheriff.Security;

namespace sheriff.plugins
{
    public class Developmentmode : IPlugin
    {

        bool dmenabled = false;
        List<string> dmwhitelist = new List<string>();

        public override string Name => "Geliştirici Modu";
        public override string Author => "Şerif Geliştirici Takımı";
        public override string Description => "Belirli ip adreslerinden gelen kişilerin oyuna girmesini sağlayabilir.";
        public override Version Version => new Version("1.0.0.0");

        public override bool OnPacketReceived(Packet packet, IClient client)
        {
            if(packet.Opcode == 0xA101)
            {

                bool contains = this.dmwhitelist.Contains(client.IPAddress);

                Packet repl = new Packet(0xA101, packet.Encrypted, packet.Massive);
                    
                while (true)
                {
                    byte hasEnrty = packet.ReadUInt8();
                    repl.WriteUInt8(hasEnrty);
                        
                    if (hasEnrty != 1) break;
                    repl.WriteUInt8(packet.ReadUInt8());
                    repl.WriteAscii(packet.ReadAscii());
                }

                while (true)
                {
                    byte hasEnrty = packet.ReadUInt8();
                    repl.WriteUInt8(hasEnrty);

                    if (hasEnrty != 1) break;
                    repl.WriteUInt16(packet.ReadUInt16());
                    repl.WriteAscii("Developer Only"); packet.ReadAscii();
                    if (contains)
                    {
                        repl.WriteUInt16(packet.ReadUInt16());
                    }
                    else
                    {
                        repl.WriteUInt16(0);
                        packet.ReadUInt16();
                    }
                
                    repl.WriteUInt16(packet.ReadUInt16());

                    if (contains)
                    {
                        repl.WriteUInt8(1);
                        packet.ReadUInt8();
                    }
                    else
                    {
                        repl.WriteUInt8(0);
                        packet.ReadUInt8();
                    }

                    repl.WriteUInt8(packet.ReadUInt8());
                }

                repl.Lock();
                packet.Replace(repl);


                
            }
            return true;
        }

        public override void OnLoad()
        {
            LoadSettings();
            LoadMode();
        }
        public override void OnSettingsChanged()
        {
            LoadSettings();
            LoadMode();
        }
        public override void OnUnLoad()
        {
        }
     

        void LoadMode()
        {
      
            if (this.dmenabled)
            {
                this.Register(0xA101);
            }
            else
            {
                this.UnRegister(0xA101);
            }
        }
        void LoadSettings()
        {
            if(!this.GetSettings().IsRegistered<bool>("dm-enabled")) this.GetSettings().Register<bool>("developmentmode", "dm-enabled", "Geliştirici modunu açın veya kapatın.");
            if(!this.GetSettings().IsRegistered<bool>("dm-whitelist")) this.GetSettings().Register<string[]>("developmentmode", "dm-whitelist", "Sunucuya erişebilen ip adresleri.");

            this.dmenabled = this.GetSettings().Get<bool>("dm-enabled");
            this.dmwhitelist = new List<string>(this.GetSettings().Get<string[]>("dm-whitelist"));
        }

      
    }
}
