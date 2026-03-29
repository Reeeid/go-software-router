package main

import (
	"bytes"
	"fmt"
)

const (
	ICMP_TYPE_ECHO_REPLY              uint8 = 0
	ICMP_TYPE_DESTINATION_UNREACHABLE uint8 = 3
	ICMP_TYPE_ECHO_REQUEST            uint8 = 8
	ICMP_TYPE_TIME_EXCEEDED           uint8 = 11
)

type icmpHeader struct {
	icmpType uint8  // タイプ
	icmpCode uint8  // コード
	checksum uint16 // チェックサム
}

type icmpEcho struct {
	identity  uint16  // 識別番号
	sequence  uint16  // シーケンス番号
	timestamp []uint8 // タイムスタンプ
	data      []uint8 // データ
}

type icmpDestnationUnreachable struct {
	unused uint32  // 未使用
	data   []uint8 // データ
}

type icmpTimeExceeded struct {
	unused uint32  // 未使用
	data   []uint8 // データ
}

type icmpMessage struct {
	icmpHeader                icmpHeader
	icmpEcho                  icmpEcho
	icmpDestnationUnreachable icmpDestnationUnreachable
	icmpTimeExceeded          icmpTimeExceeded
}

func (icmpMsg icmpMessage) ReplyPacket() (icmpPacket []byte) {
	var b bytes.Buffer
	//ICMPヘッダをバイト列に変換して書き込む
	b.Write([]byte{ICMP_TYPE_ECHO_REPLY})
	b.Write([]byte{0x00})       //icmpCodeは0
	b.Write([]byte{0x00, 0x00}) //チェックサムは0で初期化する
	//ICMPエコーメッセージ
	b.Write(uint16ToByte(icmpMsg.icmpEcho.identity))
	b.Write(uint16ToByte(icmpMsg.icmpEcho.sequence))
	b.Write(icmpMsg.icmpEcho.timestamp)
	b.Write(icmpMsg.icmpEcho.data)

	icmpPacket = b.Bytes()
	//ICMPヘッダのチェックサムを計算して書き込む
	checksum := calcChecksum(icmpPacket)
	//計算したチェックサムをセットする
	icmpPacket[2] = checksum[0]
	icmpPacket[3] = checksum[1]
	return icmpPacket
}

func icmpInput(inputdev *netDevice, sourceAddr, destAddr uint32, icmpPacket []byte) {
	//ICMPメッセージ長より短かったら
	if len(icmpPacket) < 4 {
		fmt.Println("Received ICMP packet is too short")
	}
	//ICMPのパケットとして解釈する
	icmpmsg := icmpMessage{
		icmpHeader: icmpHeader{
			icmpType: icmpPacket[0],
			icmpCode: icmpPacket[1],
			checksum: byteToUint16(icmpPacket[2:4]),
		},
		icmpEcho: icmpEcho{
			identity:  byteToUint16(icmpPacket[4:6]),
			sequence:  byteToUint16(icmpPacket[6:8]),
			timestamp: icmpPacket[8:16],
			data:      icmpPacket[16:],
		},
	}
	// fmt.Printf("ICMP Packet is %+v\n", icmpmsg)
	switch icmpmsg.icmpHeader.icmpType {
	case ICMP_TYPE_ECHO_REPLY:
		//ICMPエコーリクエストの返信は特に処理しない
		fmt.Println("ICMP ECHO REPLY is received")
	case ICMP_TYPE_ECHO_REQUEST:
		//ICMPエコーリクエストの返信を作成して送信する
		fmt.Println("ICMP ECHO REQUEST is received, Create ECHO REPLY Packet")
		ipPacketEncapsulateOutput(inputdev, sourceAddr, destAddr, icmpmsg.ReplyPacket(), IP_PROTOCOL_NUM_ICMP)
	}
}
func (icmpmsg *icmpMessage) ParsePacket(icmppacket []byte) icmpMessage {
	return icmpMessage{
		icmpHeader: icmpHeader{
			icmpType: icmppacket[0],
			icmpCode: icmppacket[1],
			checksum: byteToUint16(icmppacket[2:4]),
		},
		icmpEcho: icmpEcho{
			identity:  byteToUint16(icmppacket[4:6]),
			sequence:  byteToUint16(icmppacket[6:8]),
			timestamp: icmppacket[8:16],
			data:      icmppacket[16:],
		},
	}
}
