package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

const IP_ADDRESS_LEN = 4
const IP_ADDRESS_LIMITED_BROADCAST uint32 = 0xffffffff
const IP_PROTOCOL_NUM_ICMP uint8 = 0x01
const IP_PROTOCOL_NUM_TCP uint8 = 0x06
const IP_PROTOCOL_NUM_UDP uint8 = 0x11

type ipRouteType uint8

const (
	connected ipRouteType = iota
	network
)

type ipRouteEntry struct {
	iptype  ipRouteType
	netdev  *netDevice
	nexthop uint32
}

type ipDevice struct {
	address   uint32    // デバイスのIPアドレス
	netmask   uint32    //サブネットマスク
	broadcast uint32    //ブロードキャストアドレス
	natdev    natDevice //グローバルIPを持つデバイス
}

type ipHeader struct {
	version        uint8  //バージョン（IPv4なら4)
	headerLen      uint8  //ヘッダ長　オプションがない場合は20byteで2bit右シフトして5が入る
	tos            uint8  // Type of Service
	totalLen       uint16 //Totalのパケット長
	identity       uint16 //識別番号
	flagOffset     uint16 //フラグ
	ttl            uint8  //Time To Live
	protocol       uint8  // 上位のプロトコル番号
	headerChecksum uint16 //ヘッダのチェックサム
	srcAddr        uint32 //送信元IPアドレス
	destAddr       uint32 //送信先IPアドレス
}

func (ipheader *ipHeader) ToPacket(calc bool) (ipHeaderByte []byte) {
	var b bytes.Buffer

	b.Write([]byte{ipheader.version<<4 + ipheader.headerLen})
	b.Write([]byte{ipheader.tos})
	b.Write(uint16ToByte(ipheader.totalLen))
	b.Write(uint16ToByte(ipheader.identity))
	b.Write(uint16ToByte(ipheader.flagOffset))
	b.Write([]byte{ipheader.ttl})
	b.Write([]byte{ipheader.protocol})
	b.Write(uint16ToByte(ipheader.headerChecksum))
	b.Write(uint32ToByte(ipheader.srcAddr))
	b.Write(uint32ToByte(ipheader.destAddr))

	//checksumを計算する
	if calc {
		ipHeaderByte = b.Bytes()
		ipHeaderByte[10], ipHeaderByte[11] = 0, 0
		cksum := foldChecksum(sumByteArr(ipHeaderByte))
		//checksumをセット
		copy(ipHeaderByte[10:12], uint16ToByte(cksum))
		ipheader.headerChecksum = cksum
	} else {
		ipHeaderByte = b.Bytes()
	}
	return ipHeaderByte
}

// IPパケットの受信処理
func ipInput(inputdev *netDevice, packet []byte) {

	//IPアドレスのついていないインターフェイスからの受信は無視
	if inputdev.ipdev.address == 0 {
		return
	}
	//IPヘッダ長より短かったらドロップ
	if len(packet) < 20 {
		fmt.Printf("Received IP packet too short from %s\n", inputdev.name)
		return
	}
	//受信したIPパケットをipHeader構造体にセットする
	ipheader := ipHeader{
		version:        packet[0] & 0xf0 >> 4,
		headerLen:      packet[0] & 0x0f,
		tos:            packet[1],
		totalLen:       byteToUint16(packet[2:4]),
		identity:       byteToUint16(packet[4:6]),
		flagOffset:     byteToUint16(packet[6:8]),
		ttl:            packet[8],
		protocol:       packet[9],
		headerChecksum: byteToUint16(packet[10:12]),
		srcAddr:        byteToUint32(packet[12:16]),
		destAddr:       byteToUint32(packet[16:20]),
	}

	//ヘッダ長とトータルの長さからペイロードのオフセットを計算する
	headerLen := int(ipheader.headerLen) * 4
	if ipheader.headerLen < 5 || len(packet) < headerLen {
		fmt.Printf("headerLen is wrong: %s\n", packet)
		return
	}
	totalLen := int(ipheader.totalLen)
	if totalLen < headerLen || totalLen > len(packet) {
		fmt.Printf("totalLen is wrong: %s\n", packet)
		return
	}
	payload := packet[headerLen:totalLen]
	// 受信したMACアドレスがARPテーブルになければ追加しておく
	macaddr, _ := searchArpTableEntry(ipheader.srcAddr)
	if macaddr == [6]uint8{} {
		addArpTableEntry(inputdev, ipheader.srcAddr, inputdev.etheHeader.srcAddr)
	}

	// 宛先アドレスがブロードキャストアドレスか受信したNICインターフェイスのIPアドレスの場合
	if ipheader.destAddr == IP_ADDRESS_LIMITED_BROADCAST || inputdev.ipdev.address == ipheader.destAddr {
		//自分宛の通信として処理
		ipInputToOurs(inputdev, &ipheader, payload)
		return
	}

	//宛先IPアドレスをルーターが持っているか調べる
	//つまり宛先アドレスがルーターが持つNWインターフェイスにセットされているIPアドレスだったら自分宛のものとして処理する
	for _, dev := range netDeviceList {
		//宛先IPアドレスがルーターを持っているIPアドレス or ディレクディット・ブロードキャストアドレス時の処理
		if dev.ipdev.address == ipheader.destAddr || dev.ipdev.broadcast == ipheader.destAddr {
			//自分宛の通信として処理
			ipInputToOurs(inputdev, &ipheader, payload)
			return
		}
	}

	// NAT変換
	var natPacket []byte
	//NATの内側から外
	if inputdev.ipdev.natdev != (natDevice{}) {
		var err error
		switch ipheader.protocol {
		case IP_PROTOCOL_NUM_UDP:
			natPacket, err = natExec(&ipheader, natPacketHeader{packet: payload}, inputdev.ipdev.natdev, udp, outgoing)
			if err != nil {
				fmt.Printf("nat udp packet err is %s\n", err)
				return
			}
		case IP_PROTOCOL_NUM_TCP:
			natPacket, err = natExec(&ipheader, natPacketHeader{packet: payload}, inputdev.ipdev.natdev, tcp, outgoing)
			if err != nil {
				fmt.Printf("nat tcp packet err is %s\n", err)
				return
			}
		case IP_PROTOCOL_NUM_ICMP:
			natPacket, err = natExec(&ipheader, natPacketHeader{packet: payload}, inputdev.ipdev.natdev, icmp, outgoing)
			if err != nil {
				fmt.Printf("nat icmp packet err is %s\n", err)
				return
			}
		}

	}

	route := iproute.radixTreeSearch(ipheader.destAddr) //ルーティングテーブルを見る
	if route == (ipRouteEntry{}) {
		fmt.Printf("IPへの経路がありません:%s\n", printIPAddr(ipheader.destAddr))
		return
	}

	if ipheader.ttl <= 1 {
		//todo send_icmp_time_exceeed
		return
	}
	//TTLを減らす
	ipheader.ttl -= 1
	//bufferにコピー
	forwardPacket := ipheader.ToPacket(true)
	if inputdev.ipdev.natdev != (natDevice{}) {
		forwardPacket = append(forwardPacket, natPacket...)
	} else {
		forwardPacket = append(forwardPacket, payload...)
	}
	// 直接接続のネットワーク経路の場合
	if route.iptype == connected {
		//ホストに送る
		ipPacketOutputToHost(route.netdev, ipheader.destAddr, forwardPacket)
	} else {
		fmt.Printf("next hop is %s\n", printIPAddr(route.nexthop))
		fmt.Printf("forwad packet is %x : \n", forwardPacket[0:20])
		ipPacketOutputToNexthop(route.nexthop, forwardPacket)
	}
}

func ipPacketOutputToNexthop(nextHop uint32, packet []byte) {
	//ARPテーブルの検索
	destMacAddr, dev := searchArpTableEntry(nextHop)
	if destMacAddr == [6]uint8{0, 0, 0, 0, 0, 0} {
		fmt.Printf("Typing ip output to next hop, but no arp record to %s\n", printIPAddr(nextHop))
		//ルーティングテーブルのルックアップ
		routeToNextHop := iproute.radixTreeSearch(nextHop)
		if routeToNextHop == (ipRouteEntry{}) || routeToNextHop.iptype != connected {
			//next hopへの到達性がない場合
			fmt.Printf("Next hop %s is not reachable\n", printIPAddr(nextHop))
		} else {
			sendARPRequest(routeToNextHop.netdev, nextHop)
		}
	} else {
		//ARPエントリがある場合、イーサネットでカプセル化して送る
		ethernetOutput(dev, destMacAddr, packet, ETHER_TYPE_IP)
	}
}

func ipPacketOutputToHost(dev *netDevice, destAddr uint32, packet []byte) {
	//ARPテーブルの検索
	destMacAddr, _ := searchArpTableEntry(destAddr)
	if destMacAddr == [6]uint8{0, 0, 0, 0, 0, 0} {
		//ARPエントリが無かったら
		fmt.Printf("Trying ip output to host, but no arp record to %s\n", printIPAddr(destAddr))
		// ARPリクエストを送信
		sendARPRequest(dev, destAddr)
	} else {
		//ARPエントリがある場合、MACアドレスを得たのちにイーサネットでカプセル化して送信
		ethernetOutput(dev, destMacAddr, packet, ETHER_TYPE_IP)
	}
}

func ipInputToOurs(inputdev *netDevice, ipheader *ipHeader, packet []byte) {
	for _, dev := range netDeviceList {
		if dev.ipdev != (ipDevice{}) && dev.ipdev.natdev != (natDevice{}) && dev.ipdev.natdev.outsideIpAddr == ipheader.destAddr {
			//送信先のIPがNATの外側のIPなら以下処理を実行する
			//NATの戻りパケットをDNATする
			natExecused := false
			var destPacket []byte
			var err error
			switch ipheader.protocol {
			case IP_PROTOCOL_NUM_UDP:
				destPacket, err = natExec(ipheader, natPacketHeader{packet: packet}, dev.ipdev.natdev, udp, incoming)
				if err != nil {
					return
				}
				natExecused = true
			case IP_PROTOCOL_NUM_TCP:
				destPacket, err = natExec(ipheader, natPacketHeader{packet: packet}, dev.ipdev.natdev, tcp, incoming)
				if err != nil {
					return
				}
				natExecused = true
			case IP_PROTOCOL_NUM_ICMP:
				destPacket, err = natExec(ipheader, natPacketHeader{packet: packet}, dev.ipdev.natdev, icmp, incoming)
				if err != nil {
					return
				}
				natExecused = true
			}
			if natExecused {
				if ipheader.ttl <= 1 {
					//todo send_icmp_time_exceeded
					return
				}
				ipheader.ttl -= 1
				ipPacket := ipheader.ToPacket(true)
				ipPacket = append(ipPacket, destPacket...)
				fmt.Printf("To dest is %s, checksum is %x, packet is %x\n", printIPAddr(ipheader.destAddr),
					ipheader.headerChecksum, ipPacket)
				ipPacketOutput(dev, iproute, ipheader.destAddr, ipPacket)
				return
			}

		}
	}

	//上位プロトコルの処理に移行
	switch ipheader.protocol {
	case IP_PROTOCOL_NUM_ICMP:
		fmt.Println("ICMP received!")
		icmpInput(inputdev, ipheader.srcAddr, ipheader.destAddr, packet)
	case IP_PROTOCOL_NUM_UDP:
		fmt.Printf("udp received : %x\n", packet)
		return
	case IP_PROTOCOL_NUM_TCP:
		fmt.Printf("tcp received : %x\n", packet)
		return
	default:
		fmt.Printf("Unhandled ip protocol number : %d\n", ipheader.protocol)
		return
	}
}

func ipPacketEncapsulateOutput(destAddr, srcAddr uint32, payload []byte, protocolType uint8) {
	var ipPacket []byte
	//IPヘッダで必要なIPパケットの全長を算出する
	//IPヘッダの20byte + パケットの長さ
	totalLengh := 20 + len(payload)

	//IPヘッダの各項目を設定
	ipHeader := ipHeader{
		version:        4,
		headerLen:      20 / 4,
		tos:            0,
		totalLen:       uint16(totalLengh),
		identity:       0xf80c,
		flagOffset:     2 << 13,
		ttl:            0x40,
		protocol:       protocolType,
		headerChecksum: 0, // checksum計算をする前は0をセット
		srcAddr:        srcAddr,
		destAddr:       destAddr,
	}
	// IPヘッダをbyteにする
	ipPacket = append(ipPacket, ipHeader.ToPacket(true)...)
	//IPヘッダにペイロードをつなげる
	ipPacket = append(ipPacket, payload...)
	//ルートテーブルを参照して送信先MACアドレスを特定する
	//なければARPリクエストを送信してMACアドレスを特定してから、ethernetOutputでパケットを送信する
	route := iproute.radixTreeSearch(destAddr)
	if route == (ipRouteEntry{}) {
		fmt.Printf("No route to %s\n", printIPAddr(destAddr))
		return
	}
	if route.iptype == connected {
		ipPacketOutputToHost(route.netdev, destAddr, ipPacket)
	} else {
		ipPacketOutputToNexthop(route.nexthop, ipPacket)
	}
}

/*
IPパケットを送信
*/
func ipPacketOutput(outputdev *netDevice, routeTree radixTreeNode, destAddr uint32, packet []byte) {
	// 宛先IPアドレスへの経路を検索
	route := routeTree.radixTreeSearch(destAddr)
	if route == (ipRouteEntry{}) {
		// 経路が見つからなかったら
		fmt.Printf("No route to %s\n", printIPAddr(destAddr))
		return
	}
	if route.iptype == connected {
		// 直接接続されたネットワークなら
		ipPacketOutputToHost(outputdev, destAddr, packet)
	} else if route.iptype == network {
		// 直接つながっていないネットワークなら
		ipPacketOutputToNexthop(route.nexthop, packet)
	}
}

func getIPdevice(addrs []net.Addr) (ipdev ipDevice) {
	for _, addr := range addrs {
		// ipv6ではなくipv4アドレスをリターン
		ipaddrstr := addr.String()
		if !strings.Contains(ipaddrstr, ":") && strings.Contains(ipaddrstr, ".") {
			ip, ipnet, _ := net.ParseCIDR(ipaddrstr)
			ipdev.address = byteToUint32(ip.To4())
			ipdev.netmask = byteToUint32(ipnet.Mask)
			// ブロードキャストアドレスの計算はIPアドレスとサブネットマスクのbit反転の2進数「OR（論理和）」演算
			ipdev.broadcast = ipdev.address | (^ipdev.netmask)
		}
	}
	return ipdev
}
