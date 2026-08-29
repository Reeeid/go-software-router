package main

import (
	"bytes"
	"fmt"
)

// UDPヘッダ（8byte固定、オプション無し）
//
//	0-1  srcPort
//	2-3  destPort
//	4-5  segmentLen
//	6-7  checkSum
type udpHeader struct {
	srcPort    uint16
	destPort   uint16
	segmentLen uint16 //UDPヘッダ8byte + データの長さ
	checkSum   uint16 //疑似ヘッダを含めて計算する 0は「計算していない」の意味なので結果が0なら0xffffを送る
}

// TCPヘッダ（20〜60byte、末尾のoptionsが可変長）
//
//	0-1    srcPort
//	2-3    destPort
//	4-7    sequenceNum
//	8-11   responseCheckNum
//	12     dataOffset(4bit) + reserve(4bit)
//	13     flag(8bit)
//	14-15  windowSize
//	16-17  checkSum
//	18-19  urgPointer
//	20-    options（dataOffset*4 の位置まで）
type tcpHeader struct {
	srcPort          uint16
	destPort         uint16
	sequenceNum      uint32
	responseCheckNum uint32 //ACK番号 ACKフラグが立っている時のみ有効
	dataOffset       uint8  //4bit TCPヘッダ長を32ビット語単位で表す 最小5(20byte) 最大15(60byte)
	reserve          uint8  //4bit 常に0 受信側は無視する
	flag             uint8  //8bit 上位から CWR ECE URG ACK PSH RST SYN FIN
	windowSize       uint16 //受信側があと何byte受け取れるかの通知 フロー制御用 実効値はWindow Scaleオプション次第
	checkSum         uint16 //疑似ヘッダ + ヘッダ + ペイロードで計算する TCPでは省略不可
	urgPointer       uint16 //URGフラグが立っている時のみ有効 RFC 6093で新規実装での使用は非推奨
	options          []byte //0〜40byte TLV形式 MSS/Window Scale/SACK/Timestampsなど
	tcpdata          []byte
}

// TCPのコントロールフラグ（flagフィールドのビット位置）
const (
	TCP_FLAG_FIN uint8 = 1 << iota //送信終了 方向ごとに独立して閉じる
	TCP_FLAG_SYN                   //接続開始 シーケンス番号の初期値を同期する
	TCP_FLAG_RST                   //強制切断 閉じたポートへの接続試行などで返る
	TCP_FLAG_PSH                   //バッファに溜めず即座にアプリへ渡す
	TCP_FLAG_ACK                   //responseCheckNumが有効 接続確立後はほぼ常に1
	TCP_FLAG_URG                   //urgPointerが有効
	TCP_FLAG_ECE                   //経路上で輻輳の印を付けられたことを相手に伝える(データが多くてパンク)
	TCP_FLAG_CWR                   //輻輳通知を受けて送信量を減らしたと応答する
)

func (tcp tcpHeader) toPacket() []byte {
	var b bytes.Buffer
	b.Write(uint16ToByte(tcp.srcPort)) //0byte 1byte目
	b.Write(uint16ToByte(tcp.destPort))
	b.Write(uint32ToByte(tcp.sequenceNum))
	b.Write(uint32ToByte(tcp.responseCheckNum))
	b.Write([]byte{
		tcp.dataOffset<<4 | tcp.reserve&0x0f, // 12byte目
		tcp.flag,                             //13byte目
	})
	b.Write(uint16ToByte(tcp.windowSize))
	b.Write(uint16ToByte(tcp.checkSum))
	b.Write(uint16ToByte(tcp.urgPointer))
	if len(tcp.options) != 0 {
		b.Write(tcp.options)
	} //ここまで20-60byteのTCPヘッダになる
	if len(tcp.tcpdata) != 0 {
		b.Write(tcp.tcpdata)
	}
	return b.Bytes()
}
func (udp udpHeader) toPacket() []byte {
	var b bytes.Buffer
	b.Write(uint16ToByte(udp.srcPort))
	b.Write(uint16ToByte(udp.destPort))
	b.Write(uint16ToByte(udp.segmentLen))
	b.Write(uint16ToByte(udp.checkSum))

	return b.Bytes()
}

func (tcp tcpHeader) ParsePacket(packet []byte) tcpHeader {
	if len(packet) < 20 {
		fmt.Printf("tcp header error %x\n", packet)
		return tcpHeader{}
	}

	header := tcpHeader{
		srcPort:          byteToUint16(packet[0:2]),
		destPort:         byteToUint16(packet[2:4]),
		sequenceNum:      byteToUint32(packet[4:8]),
		responseCheckNum: byteToUint32(packet[8:12]),
		dataOffset:       packet[12] >> 4,
		reserve:          packet[12] & 0x0f,
		flag:             packet[13],
		windowSize:       byteToUint16(packet[14:16]),
		checkSum:         byteToUint16(packet[16:18]),
		urgPointer:       byteToUint16(packet[18:20]),
	}

	headerLen := header.dataOffset * 4

	if header.dataOffset < 5 || int(headerLen) > len(packet) {
		fmt.Printf("tcp header dataOffset error %x\n", packet)
		return tcpHeader{}
	}
	//オプションがあれば(60byteまで)
	if 20 < headerLen {
		header.options = packet[20:headerLen]
	}
	if int(headerLen) < len(packet) {
		header.tcpdata = packet[headerLen:]
	}
	return header
}

func (udp udpHeader) ParsePacket(packet []byte) udpHeader {
	if len(packet) < 8 {
		fmt.Printf("udp header error %x\n", packet)
		return udpHeader{}
	}
	return udpHeader{
		srcPort:    byteToUint16(packet[0:2]),
		destPort:   byteToUint16(packet[2:4]),
		segmentLen: byteToUint16(packet[4:6]),
		checkSum:   byteToUint16(packet[6:8]),
	}
}
