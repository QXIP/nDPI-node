/*  nDPI Node.js Binding PoC 	*/
/*  (c) 2015 QXIP BV 		*/
/*  http://qxip.net 		*/

var VERSION = "0.1.2";

/* NODE REQs */ 

var ffi = require('ffi');
var ref = require("ref");
var Struct = require('ref-struct');
var ArrayType = require('ref-array');

/* PCAP Filter */

if (process.argv.length > 4) {
    console.error("usage: tcp_metrics interface filter");
    console.error("Examples: ");
    console.error("  tcp_metrics \"tcp port 80\"");
    console.error("  tcp_metrics eth1 \"\"");
    console.error("  tcp_metrics lo0 \"ip proto \\tcp and tcp port 80\"");
    process.exit(1);
}
var pcapp = require('pcap-parser');
var pcap_parser = pcapp.parse('./pcap/lamernews.pcap');

/* NDPI CALLBACK */

var voidPtr = ref.refType(ref.types.void);
var u_char = exports.u_char = Struct({
  __u_char: ref.types.uchar,
});
var u_charPtr = exports.u_charPtr = ref.refType(u_char);

var pcap_t = exports.pcap_t = voidPtr;
var pcap_tPtr = exports.pcap_tPtr = ref.refType(pcap_t);
var pcap_handler = exports.pcap_handler = ffi.Function(ref.types.void, [
  ref.refType(ref.types.uchar),
  voidPtr,
  ref.refType(ref.types.uchar),
]);
var pcap_handlerPtr = exports.pcap_handlerPtr = ref.refType(pcap_handler);

var uint8_t = exports.uint8_t = voidPtr;
var uint8_tPtr = exports.uint8_tPtr = ref.refType(uint8_t);
var callback = exports.callback = ffi.Function(ref.types.void, [
  ref.types.int32,
  ref.refType(ref.types.uchar),
]);
var callbackPtr = exports.callbackPtr = ref.refType(callback);

var ndpi = new ffi.Library('./libndpilua.so', {

  init: [ref.types.void, [
  ]],
  setDatalinkType: [ref.types.void, [
      pcap_tPtr,
  ]],
  processPacket: [ref.types.void, [
    voidPtr,
    uint8_t,
  ]],
  finish: [ref.types.void, [
  ]],
  addProtocolHandler: [ref.types.void, [
    callback,
  ]],
});

// PCAP Header
var pcap_pkthdr = Struct({
  'ts_sec': 'uint64', 
  'ts_usec': 'uint64',
  'incl_len': 'uint32',
  'orig_len': 'uint32'
});

var pcap_pkthdr_ptr = ref.refType(pcap_pkthdr);

/*
var ndpi = ffi.Library('./libndpilua.so', {
  "init": [ "void", [] ],
  "finish": [ "void", [] ],
//  "processPacket": [ "void", [ pcap_pkthdr_ptr, ucharPtr ] ],
  "processPacket": [ "void", [ ref.refType(pcap_pkthdr), ref.refType(ref.types.uchar) ] ],
  "addProtocolHandler": [ "void", [ callback_Ptr ] ],
  "setDatalinkType": [ "void", [ "pointer"] ]
});

*/

/* APP VARS */

var L7PROTO = [
"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP","NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL","MySQL","TDS","Direct_Download_Link","POPS","AppleJuice","DirectConnect","Socrates","WinMX","VMware","SMTPS","Filetopia","iMESH","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI","Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","Move","RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer","HTTP_APPLICATION_VEOHTV","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencryped_Jabber","MSN","Oscar","Yahoo","BattleField","Quake","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec","GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC","PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini","SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars","HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL","PPTP","Warcraft3","WorldOfKungFu","Meebo","Facebook","Twitter","DropBox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow","HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","GrooveShark","SkyFile_PrePaid","SkyFile_Rudics","SkyFile_PostPaid","Citrix_Online","Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti","LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN","NOE","CiscoVPN","TeamSpeak","TOR","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE","Whois-DAS","Collectd","SOCKS5","SOCKS4","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay","CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","FacebookChat","Pandora","Vevo"
]

function onProto(id, packet) {
	console.log("Proto: "+L7PROTO[id]+" ("+id+")");
}

/* APP */

console.log("nDPI Node v"+VERSION);
	//console.log("Test L7 Proto-2-Name :", L7PROTO[5] );

/* NDPI LOOP */

ndpi.init();

/* PCAP LOOP */

pcap_parser.on('globalHeader', function (globalHeader) {
	console.log('START!');
	ndpi.init();
	// ndpi.addProtocolHandler(onProto);
	var ltype = new Buffer(globalHeader.linkLayerType);
	ltype.type = ref.refType(pcap_t);
	ndpi.setDatalinkType(ltype.ref())
});

pcap_parser.on('packet', function (raw_packet) {

	var header = raw_packet.header;
	// Build PCAP Hdr Struct
	var newHdr = new pcap_pkthdr();
		newHdr.ts_sec=header.timestampSeconds;
		newHdr.ts_usec=header.timestampMicroseconds;
		newHdr.incl_len=header.capturedLength;
		newHdr.orig_len=header.originalLength;

	var newHeader = new Buffer(newHdr);
    	ndpi.processPacket(newHdr.ref(), raw_packet.data );


});

pcap_parser.on('end', function () {
	console.log('EOF!');
	ndpi.finish();
});

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
