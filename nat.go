package main

import (
	"fmt"
)

type natEntry struct {
	globalIpAddr uint32
	localIpAddr  uint32
	globalPort   uint16 //icmpのidentifierとしても使う
	localPort    uint16
}

type natPacketHeader struct {
	packet []byte
}

//UDPとTCPのNATテーブルセット

type natEntryList struct {
	tcp  []*natEntry
	udp  []*natEntry
	icmp []*natEntry
}
type natProtocolType uint8
type natDirectionType uint8

const (
	NAT_GLOBAL_PORT_MIN  = 20000
	NAT_GLOBAL_PORT_MAX  = 59999
	NAT_GLOBAL_PORT_SIZE = (NAT_GLOBAL_PORT_MAX - NAT_GLOBAL_PORT_MIN + 1)
	NAT_ICMP_ID_SIZE     = 0xffff
)
const (
	outgoing natDirectionType = iota
	incoming
)
const (
	tcp natProtocolType = iota
	udp
	icmp
)

// ip_deviceが持つNATデバイス
type natDevice struct {
	outsideIpAddr uint32
	natEntry      *natEntryList
}

func configureIPNat(inside string, outside uint32) {

	for _, dev := range netDeviceList {
		if inside == dev.name {
			dev.ipdev.natdev = natDevice{
				outsideIpAddr: outside,
				natEntry: &natEntryList{
					tcp:  make([]*natEntry, NAT_GLOBAL_PORT_SIZE),
					udp:  make([]*natEntry, NAT_GLOBAL_PORT_SIZE),
					icmp: make([]*natEntry, NAT_ICMP_ID_SIZE),
				},
			}
			fmt.Printf("Set nat to %s, outside ip addr is %s\n", inside, printIPAddr(outside))
		}
	}
}

// 空いているポートを探してNATエントリを作る
func (entry *natEntryList) createNatEntry(protoType natProtocolType) *natEntry {
	switch protoType {
	case udp:
		//udpの場合、空いているエントリを見つけてグローバルポートを設定しエントリを返す
		for i, v := range entry.udp {
			if v == nil {
				entry.udp[i] = &natEntry{
					globalPort: uint16(NAT_GLOBAL_PORT_MIN + i),
				}
				return entry.udp[i]
			}
		}
	case tcp:
		//tcpも同様、空いているエントリを見つけてグローバルポートを設定しエントリを返す
		for i, v := range entry.tcp {
			if v == nil {
				entry.tcp[i] = &natEntry{
					globalPort: uint16(NAT_GLOBAL_PORT_MIN + i),
				}
				return entry.tcp[i]
			}
		}
	case icmp:
		//icmpも同様であるが、空いているエントリを見つけてグローバルポートにidentifierを設定しエントリを返す
		for i, v := range entry.icmp {
			if v == nil {
				entry.icmp[i] = &natEntry{
					globalPort: uint16(i), //identifier
				}
				return entry.icmp[i]
			}
		}
	}
	return nil
}

func (entry *natEntryList) getNatEntryByGlobal(prototype natProtocolType, ipaddr uint32, port uint16) *natEntry {
	switch prototype {
	case udp:
		for _, v := range entry.udp {
			if v != nil && ipaddr == v.globalIpAddr && port == v.globalPort {
				return v
			}
		}
	case tcp:
		for _, v := range entry.tcp {
			if v != nil && ipaddr == v.globalIpAddr && port == v.globalPort {
				return v
			}
		}
	case icmp:
		for _, v := range entry.icmp {
			if v != nil && ipaddr == v.globalIpAddr && port == v.globalPort {
				return v
			}
		}
	}
	return nil
}

func (entry *natEntryList) getNatEntryByLocal(prototype natProtocolType, ipaddr uint32, port uint16) *natEntry {
	switch prototype {
	case udp:
		for _, v := range entry.udp {
			if v != nil && ipaddr == v.localIpAddr && port == v.localPort {
				return v
			}
		}
	case tcp:
		for _, v := range entry.tcp {
			if v != nil && ipaddr == v.localIpAddr && port == v.localPort {
				return v
			}
		}
	case icmp:
		for _, v := range entry.icmp {
			if v != nil && ipaddr == v.localIpAddr && port == v.localPort {
				return v
			}
		}

	}
	return nil
}

func natExec(ipHeader *ipHeader, natPacket natPacketHeader, natdevice natDevice, proto natProtocolType, direction natDirectionType) ([]byte, error) {
	var udph udpHeader
	var tcph tcpHeader
	var icmpm icmpMessage
	var srcPort, destPort uint16
	var packet []byte

	//プロトコルごとのパース (RFC 3022 Section 4.1)
	switch proto {
	case udp:
		udph = udph.ParsePacket(natPacket.packet)
		srcPort = udph.srcPort
		destPort = udph.destPort
	case tcp:
		tcph = tcph.ParsePacket(natPacket.packet)
		srcPort = tcph.srcPort
		destPort = tcph.destPort
	case icmp:
		icmpm = icmpm.ParsePacket(natPacket.packet)
		// RFC 5508: NAT対象は Echo Request / Echo Reply のみ
		if icmpm.icmpHeader.icmpType != ICMP_TYPE_ECHO_REPLY && icmpm.icmpHeader.icmpType != ICMP_TYPE_ECHO_REQUEST {
			return nil, fmt.Errorf("NAT icmpMEssage.icmpHeader.icmpType is not allowed type : %d\n", icmpm.icmpHeader.icmpType)
		}
		// RFC 5508: ICMP Identifier フィールドをポート番号の代替として使用
		srcPort = icmpm.icmpEcho.identity
		destPort = icmpm.icmpEcho.identity
	}

	var entry *natEntry
	//テーブル検索とヘッダ書き換え (RFC 3022)
	//NATテーブル検索 & アドレス・ポート書き換え
	if direction == incoming {
		//外から中 (DNAT 宛先IP/PORTをローカルに変換)
		entry = natdevice.natEntry.getNatEntryByGlobal(proto, ipHeader.destAddr, destPort)
		if entry == nil {
			return nil, fmt.Errorf("No nat entry")
		}
		fmt.Printf("incoming nat from %s:%d to %s:%d\n", printIPAddr(entry.globalIpAddr), entry.globalPort, printIPAddr(entry.localIpAddr), entry.localPort)
		fmt.Printf("incoming ip header src is %s, dest is %s\n", printIPAddr(ipHeader.srcAddr), printIPAddr(ipHeader.destAddr))
		//IPヘッダの送信元アドレスを内側のアドレスにする
		ipHeader.destAddr = entry.localIpAddr
		switch proto {
		case udp:
			udph.destPort = entry.localPort
		case tcp:
			tcph.destPort = entry.localPort
		case icmp:
			icmpm.icmpEcho.identity = entry.localPort
		}
	} else {
		//中から外 (SNAT 宛先IP/PORTをグローバルに変換)
		entry = natdevice.natEntry.getNatEntryByLocal(proto, ipHeader.srcAddr, srcPort)
		if entry == nil {
			entry = natdevice.natEntry.createNatEntry(proto)
			if entry == nil {
				return nil, fmt.Errorf("NAT table is full")
			}
			entry.globalIpAddr = natdevice.outsideIpAddr
			entry.localIpAddr = ipHeader.srcAddr
			entry.localPort = srcPort
		}
		//IPヘッダの送信元アドレスを外側のアドレスにする
		ipHeader.srcAddr = entry.globalIpAddr
		switch proto {
		case udp:
			udph.srcPort = entry.globalPort
		case tcp:
			tcph.srcPort = entry.globalPort
		case icmp:
			icmpm.icmpEcho.identity = entry.globalPort
		}
	}
	//L4パケットのシリアライズ & チェックサム再計算 (RFC 793, RFC 768, RFC 5508)
	// RFC 793: チェックサムフィールドを 0x0000 に初期化して擬似ヘッダ付きで計算
	// RFC 768: 元が 0x0000（チェックサム無効）の場合は再計算せず 0x0000 を維持
	// RFC 768: 計算結果が 0x0000 になった場合は 0xFFFF を格納する（必須要件）
	// RFC 792 / RFC 5508: ICMPは擬似ヘッダを含めない（L3情報は検査対象外）
	var l4Payload []byte
	packet = natPacket.packet
	switch proto {
	case udp:
		if len(natPacket.packet) < 8 {
			return nil, fmt.Errorf("udp packet too short")
		}

		l4Payload = natPacket.packet[8:]
		//RFC 768 元が0なら送信側が計算していないので0のまま
		if udph.checkSum != 0 {
			//ゼロクリア
			udph.checkSum = 0
			packet = append(udph.toPacket(), l4Payload...)
			//疑似ヘッダとパケット全体で計算する
			//疑似ヘッダは送信元・宛先アドレスとtcp・udp 6か17 L4パケット全体
			sum := pseudoHeaderSum(ipHeader.srcAddr, ipHeader.destAddr, IP_PROTOCOL_NUM_UDP, len(packet))
			sum += sumByteArr(packet)
			cksum := foldChecksum(sum)
			if cksum == 0 {
				cksum = 0xffff
			}
			udph.checkSum = cksum
		}
		packet = append(udph.toPacket(), l4Payload...)
	case tcp:
		tcph.checkSum = 0
		packet = tcph.toPacket()

		sum := pseudoHeaderSum(ipHeader.srcAddr, ipHeader.destAddr, IP_PROTOCOL_NUM_TCP, len(packet))
		sum += sumByteArr(packet)
		tcph.checkSum = foldChecksum(sum)
		packet = tcph.toPacket()
	case icmp:
		packet = natPacket.packet
		//identityは4-5バイト目
		copy(packet[4:6], uint16ToByte(icmpm.icmpEcho.identity))
		//チェックサムは2-3バイト目、ゼロクリアして計算
		packet[2], packet[3] = 0, 0
		//icmpなら疑似ヘッダは足さない
		copy(packet[2:4], uint16ToByte(foldChecksum(sumByteArr(packet))))
	}
	return packet, nil
}
