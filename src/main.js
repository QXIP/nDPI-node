/* nDPI Node.js Binding PoC */
/* (c) 2015 QXIP BV */

var VERSION = "0.1";

/* REQs */ 
var ref = require("ref");
var ffi = require('ffi');
var Struct = require('ref-struct');

/* VARS */

var ndpi = ffi.Library('./libndpilua.so', {
  "init": [ "void", [] ],
  "finish": [ "void", [] ],
  "processPacket": [ "void", [ "pointer", "string" ] ],
  "addProtocolHandler": [ "void", [ "pointer" ] ]
});

var myobj = ref.types.void;

var pcap_pkthdr = Struct({
  'ts_sec': 'long', 
  'ts_usec': 'long',
  'incl_len': 'int',
  'orig_len': 'int'
});

var L7PROTO = [
"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
]

function onProto(id, packet) {
	console.log("Proto: "+id);
}

/* APP */

console.log("nDPI Node v"+VERSION);
console.log("Test DNS :", L7PROTO[5] );

// ndpi.addProtocolHandler(onProto);

ndpi.init();
ndpi.finish();

console.log("exit");
