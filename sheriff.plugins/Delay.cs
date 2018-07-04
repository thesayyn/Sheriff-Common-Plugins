using Sheriff.Common.Plugins;
using System;
using Sheriff.Networking;
using Sheriff.Security;

namespace sheriff.plugins
{
    class Delay : IPlugin
    {
        public override string Name => "Gecikme";
        public override string Author => "Şerif Geliştirici Takımı";
        public override string Description => "Bu eklenti ile pazar açma yada takas gibi işlemleri belirli süre aralığında yapılmasını sağlayabilirsiniz.";
        public override Version Version => new Version("1.0.0.0");


        bool delayactive = false;
        int delaytime = 0;

        public override void OnLoad()
        {

            GetSettings().Register<bool>("delay", "stall-delay-enabled", "Stall Gecikme Aktif.");
            GetSettings().Register<int>("delay", "stall-delay-time", "Stall Gecikme Süresi.");
            
        }

        public override bool OnPacketReceived(Packet packet, IClient client)
        {

            if (packet.Opcode == 0x70B1)
            {
                if (client.GetProperty("SonStallZamani") == null)
                {
                    client.SetProperty("SonStallZamani", DateTimeOffset.Now.ToUnixTimeSeconds());
                }
                else
                {
                    Int64 fark = DateTimeOffset.Now.ToUnixTimeSeconds() - ((Int64)client.GetProperty("SonStallZamani"));
                    if (fark > this.delaytime) 
                    {
                        client.SetProperty("SonStallZamani", DateTimeOffset.Now.ToUnixTimeSeconds());
                        GetLogger().Info("Stall açabilir. " + fark);
                        return true; 
                    }
                    else 
                    {

                        Packet cannot = new Packet(0xB0B1);
                        cannot.WriteUInt8(2);
                        cannot.WriteUInt16(0x3C16);
                        client.Send(cannot);



                        Packet notice = new Packet(0x3026);
                        notice.WriteInt8(7);
                        notice.WriteAscii("Lütfen stall açmadan önce " + Math.Abs(fark - this.delaytime) + "sn. daha bekleyiniz.");
                        client.Send(notice);



                        GetLogger().Info("Stall açamaz. " + fark);

                        return false; 

                    }
                }
            }
            return true;
        }



        public override void OnSettingsChanged()
        {
            AyarlariYukle();
        }

        public override void OnUnLoad()
        {
        }


        void AyarlariYukle()
        {
            this.delayactive = this.GetSettings().Get<bool>("stall-delay-enabled");

            if (this.delayactive) /* eğer delay aktif edilmişse paketlerden haberdar ol */
            {
                this.Register(0x70B1);
                this.delaytime = this.GetSettings().Get<int>("stall-delay-time");
            }
            else /* Aktif degilse paketlerden haberdar olmayı kapat */
            {
                this.UnRegister(0x70B1);
            }
           
        }
    }

   
}
