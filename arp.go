package main

import (
	"bytes"
	"fmt"
)

const ARP_OPERATION_CODE_REQUEST = 1
const ARP_OPERATION_CODE_REPLY = 2
const ARP_HTYPE_ETHERNET uint16 = 0001

// ARPテーブル用の配列
var ArpTableEntryList []arpTableEntry

type arpTableEntry struct {
	macAddr [6]uint8
	ipAddr  uint32
	netdev  *netDevice
}

// ARPテーブルのエントリ追加と更新
func addArpTableEntry(netdev *netDevice, ipaddr uint32, macaddr [6]uint8) {
	//同じIPのエントリがあればMACとデバイスを上書きする
	for i := range ArpTableEntryList {
		if ArpTableEntryList[i].ipAddr == ipaddr {
			ArpTableEntryList[i].macAddr = macaddr
			ArpTableEntryList[i].netdev = netdev
			return
		}
	}
	//無ければ追加する
	ArpTableEntryList = append(ArpTableEntryList, arpTableEntry{
		macAddr: macaddr,
		ipAddr:  ipaddr,
		netdev:  netdev,
	})
}

type arpIPToEthernet struct {
	hardwareType       uint16   //ハードウェアタイプ
	protocolType       uint16   //プロトコルタイプ
	hardwareLen        uint8    //ハードウェアアドレス長
	protocolLen        uint8    //プロトコルアドレス長
	opcode             uint16   //オペレーション　ARPreqなら0x0001 ARPrepなら0x0002
	senderHardwareAddr [6]uint8 //送信元MACアドレス
	senderIPAddr       uint32   //送信元IPアドレス
	targetHardwareAddr [6]uint8 //ターゲットのMACアドレス　ARPreqなら00-00-00-00-00-00
	targetIPAddr       uint32   //ターゲットのIPアドレス ARPreqならMACアドレスを取得したいIPアドレスが入る
}

func (arpmsg arpIPToEthernet) ToPacket() []byte {
	var b bytes.Buffer

	b.Write(uint16ToByte(arpmsg.hardwareType))
	b.Write(uint16ToByte(arpmsg.protocolType))
	b.Write([]byte{arpmsg.hardwareLen})
	b.Write([]byte{arpmsg.protocolLen})
	b.Write(uint16ToByte(arpmsg.opcode))
	b.Write(macToByte(arpmsg.senderHardwareAddr))
	b.Write(uint32ToByte(arpmsg.senderIPAddr))
	b.Write(macToByte(arpmsg.targetHardwareAddr))
	b.Write(uint32ToByte(arpmsg.targetIPAddr))
	return b.Bytes()
}

// ARPリクエストの作成 MACアドレスを取得したいIPアドレスをセットしたらパケットデータにしてブロードキャストアドレス(FF-FF-FF-FF-FF-FF)でイーサネットに送信
func sendARPRequest(netdev *netDevice, targetip uint32) {
	fmt.Printf("Sending arp request via %s for %x\n", netdev.name, targetip)
	//ARPリクエストのパケットを作成
	arpPacket := arpIPToEthernet{
		hardwareType:       ARP_HTYPE_ETHERNET,
		protocolType:       ETHER_TYPE_IP,
		hardwareLen:        ETHERNET_ADDRES_LEN,
		protocolLen:        IP_ADDRESS_LEN,
		opcode:             ARP_OPERATION_CODE_REQUEST,
		senderHardwareAddr: netdev.macaddr,
		senderIPAddr:       netdev.ipdev.address,
		targetHardwareAddr: ETHERNET_ADDRESS_BROADCAST,
		targetIPAddr:       targetip,
	}.ToPacket()
	//ethernetでカプセル化して送信
	ethernetOutput(netdev, ETHERNET_ADDRESS_BROADCAST, arpPacket, ETHER_TYPE_ARP)
}

// ARPテーブルの検索
func searchArpTableEntry(ipaddr uint32) ([6]uint8, *netDevice) {
	if len(ArpTableEntryList) != 0 {
		for _, arpTable := range ArpTableEntryList {
			if arpTable.ipAddr == ipaddr {
				return arpTable.macAddr, arpTable.netdev
			}
		}
	}
	return [6]uint8{}, nil
}

func arpInput(netdev *netDevice, packet []byte) {
	//ARPパケットが規定より短かったら
	if len(packet) < 28 {
		println("received ARP Packet is too short")
	}
	//構造体にセット
	arpMsg := arpIPToEthernet{
		hardwareType:       byteToUint16(packet[0:2]),
		protocolType:       byteToUint16(packet[2:4]),
		hardwareLen:        packet[4],
		protocolLen:        packet[5],
		opcode:             byteToUint16(packet[6:8]),
		senderHardwareAddr: setMacAddr(packet[8:14]),
		senderIPAddr:       byteToUint32(packet[14:18]),
		targetHardwareAddr: setMacAddr(packet[18:24]),
		targetIPAddr:       byteToUint32(packet[24:28]),
	}
	switch arpMsg.protocolType {
	case ETHER_TYPE_IP:
		if arpMsg.hardwareLen != ETHERNET_ADDRES_LEN {
			fmt.Printf("Illegal hardware address length")

		}
		if arpMsg.protocolLen != IP_ADDRESS_LEN {
			fmt.Println("Illegal protocol address length")
		}
		//オペレーションコードによって分岐
		if arpMsg.opcode == ARP_OPERATION_CODE_REQUEST {
			//ARPリクエストの受信
			fmt.Printf("ARP Request Packet is %+v\n", arpMsg)
			arpRequestArrives(netdev, arpMsg)
		} else {
			//ARPリプライの受信
			fmt.Printf("ARP Reply Packet is %+v\n", arpMsg)
			arpReplyArrives(netdev, arpMsg)
		}
	}
}

func arpReplyArrives(netdev *netDevice, arp arpIPToEthernet) {
	//IPアドレスが設定されているデバイスからの受信だったら
	if netdev.ipdev.address != 00000000 {
		fmt.Printf("Added arp table entry by arp reply (%s => %s)\n", printIPAddr(arp.senderIPAddr), printMacAddr(arp.senderHardwareAddr))
		//ARPテーブルエントリの追加
		addArpTableEntry(netdev, arp.senderIPAddr, arp.senderHardwareAddr)
	}
}

func arpRequestArrives(netdev *netDevice, arp arpIPToEthernet) {
	//IPアドレスが設定されているデバイスからの受信勝要求されているアドレスが自分のものだったら
	if netdev.ipdev.address != 00000000 && netdev.ipdev.address == arp.targetIPAddr {
		addArpTableEntry(netdev, arp.senderIPAddr, arp.senderHardwareAddr)
		fmt.Printf("Sending arp reply via %s\n", printIPAddr(arp.targetIPAddr))
		//ARPリプライのパケットを作成
		arpPacket := arpIPToEthernet{
			hardwareType:       ARP_HTYPE_ETHERNET,
			protocolType:       ETHER_TYPE_IP,
			hardwareLen:        ETHERNET_ADDRES_LEN,
			protocolLen:        IP_ADDRESS_LEN,
			opcode:             ARP_OPERATION_CODE_REPLY,
			senderHardwareAddr: netdev.macaddr,
			senderIPAddr:       netdev.ipdev.address,
			targetHardwareAddr: arp.senderHardwareAddr,
			targetIPAddr:       arp.targetIPAddr,
		}.ToPacket()
		//Ethernetでカプセル化して送信
		ethernetOutput(netdev, arp.senderHardwareAddr, arpPacket, ETHER_TYPE_ARP)
	}
}
