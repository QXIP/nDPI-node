/*  nDPI Node.js Binding PoC 	*/
/*  (c) 2015 QXIP BV 		*/
/*  http://qxip.net 		*/

var VERSION = "0.1.1";

/* NODE REQs */ 

var ref = require("ref");
var ffi = require('ffi');
var Struct = require('ref-struct');
var ArrayType = require('ref-array');

var pcap = require("pcap"),
    pcap_session = pcap.createSession("", "tcp");


/* NDPI CALLBACK */

// On Windows UTF-16 (2-bytes), Unix UTF-32 (4-bytes)
var wchar_size = process.platform == 'win32' ? 2 : 4

var wchar_t = Object.create(ref.types.CString);
wchar_t.get = function get (buf, offset) {
  var _buf = buf.readPointer(offset)
  if (_buf.isNull()) {
    return null
  }
  var stringBuf = _buf.reinterpretUntilZeros(wchar_size)
  return stringBuf.toString('win32' ? 'utf16le' : 'utf32li') // TODO: decode UTF-32 on Unix
};

wchar_t.set = function set (buf, offset, val) {
  // TODO: better UTF-16 and UTF-32 encoding
  var _buf = new Buffer((val.length + 1) * wchar_size)
  _buf.fill(0)
  var l = 0
  for (var i = wchar_size - 1; i < _buf.length; i += wchar_size) {
    _buf[i] = val.charCodeAt(l++)
  }
  return buf.writePointer(_buf, offset)
};

var callback_Ptr = ArrayType(wchar_t);


/* APP VARS */

var ndpi = ffi.Library('./libndpilua.so', {
  "init": [ "void", [] ],
  "finish": [ "void", [] ],
  "processPacket": [ "void", [ "pointer", "string" ] ],
  "addProtocolHandler": [ "void", [ callback_Ptr ] ]
});

// PCAP Header
var pcap_pkthdr = Struct({
  'ts_sec': 'long', 
  'ts_usec': 'long',
  'incl_len': 'int',
  'orig_len': 'int'
});
var hdrPtr = ref.refType(pcap_pkthdr);

var L7PROTO = [
"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
]

function onProto(id, packet) {
	console.log("Proto: "+id);
}


/* APP */

console.log("nDPI Node v"+VERSION);
console.log("Test DNS :", L7PROTO[5] );

ndpi.addProtocolHandler(onProto);

ndpi.init();

/* PCAP LOOP */

console.log("Listening on " + pcap_session.device_name);
var header = new pcap_pkthdr();

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);

    if (packet) {
	header = packet.pcap_header;
        console.log(header);

	// ndpi.processPacket('', '');

    }
});




// ndpi.finish();




var exit = false;

process.on('SIGINT', function() {
    console.log();
    if (exit) {
    	console.log("Exiting...");
	ndpi.finish();
        process.exit();
    } else {
    	console.log("Press CTRL-C within 2 seconds to Exit...");
        exit = true;
	setTimeout(function () {
    	  // console.log("Continuing...");
	  exit = false;
	}, 2000)
    }
});
