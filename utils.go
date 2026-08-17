package main

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func byteToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func byteToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func uint16ToByte(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func uint32ToByte(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

func calcChecksum(packet []byte) []byte {
	sum := sumByteArr(packet)
	sum = (sum & 0xffff) + sum>>16
	return uint16ToByte(uint16(sum ^ 0xffff))
}

func sumByteArr(packet []byte) (sum uint) {
	for i, _ := range packet {
		if i%2 == 0 {
			sum += uint(byteToUint16(packet[i:]))
		}
	}
	return sum
}

func printMacAddr(macaddr [6]uint8) string {
	var str string
	for _, v := range macaddr {
		str += fmt.Sprintf("%x:", v)
	}
	return strings.TrimRight(str, ":")
}

func printIPAddr(ip uint32) string {
	ipbyte := uint32ToByte(ip)
	return fmt.Sprintf("%d.%d.%d.%d", ipbyte[0], ipbyte[1], ipbyte[2], ipbyte[3])
}
