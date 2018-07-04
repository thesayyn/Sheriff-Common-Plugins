using System;
using Sheriff.Common.Plugins;
using Sheriff.Networking;
using Sheriff.Security;

namespace sheriff.plugins
{
    class SkillDisabler : IPlugin
    {
        public override string Name => "Skill Disabler (Beta)";

        public override string Author => "Şerif Geliştirici Takımı";

        public override string Description => "Kullanılmasını istemediğiniz yetenekleri engelleyin.";

        public override Version Version => new Version("1.0.0.0");

        public override bool OnPacketReceived(Packet packet, IClient client)
        {
            if(packet.Opcode == 0x70A1)
            {

                GetLogger().Info("Skill UP = {0} " , packet.ReadInt32());
              
            }
        
            if(packet.Opcode == 0x7034)
            {
                byte type = packet.ReadUInt8(); 

                if(type == 0) 
                {
                    byte slot1 = packet.ReadUInt8();
                    byte slot2 = packet.ReadUInt8();
                    GetLogger().Info("Change Slot - Slot = {0} , Slot = {1}", slot1, slot2);

                }else if(type == 7)
                {
                    byte droppedslot = packet.ReadUInt8();
                  
                    GetLogger().Info("Item Dropped - Slot = {0}", droppedslot);
                }
                
             
            }

            if(packet.Opcode == 0xB0A2)
            {
                ushort masterId = packet.ReadUInt16(); // Yetenek Grubu
                byte seed = packet.ReadUInt8(); // Yükseltme Seviyesi 
                packet.ReadBytes(2); // Unk bytes
                byte currentLevel = packet.ReadUInt8();

                GetLogger().Info("Mastery ID = {0}, Seed = {1} , CurrentLevel = {2}", masterId, seed, currentLevel);

                GetLogger().Info("[0xB0A2]\n" + ByteArrayExtension.HexDump(packet.GetBytes()));
                return false;
            }

            GetLogger().Info(packet.Opcode.ToString("X"));
            GetLogger().Info(ByteArrayExtension.HexDump(packet.GetBytes()));
            return true;
        }

        public override void OnLoad()
        {
            this.Register(0x70A1);
            this.Register(0x7034);
            this.Register(0xB0A2);

            this.Register(0x7021);
            this.Register(0xB021);
        }

        public override void OnSettingsChanged()
        {
            
        }

        public override void OnUnLoad()
        {
          
        }
    }
}
