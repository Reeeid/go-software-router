package main

import (
	"fmt"
	"syscall"
)

var IGNORE_INTERFACES = []string{"lo", "bond0", "dummy0"}

type netDevice struct {
	name       string                    // インターフェース名(例: eth0)　どのLANカードを使うか指定するために必要
	macaddr    [6]uint8                  // 送信元MACアドレス　自分のMACアドレスをテンプレートとして持つ
	socket     int                       //syscall.Readやsyscall.Writeでパケットの入出力を行うためのソケット
	sockaddr   syscall.SockaddrLinklayer // syscall.bindでソケットをLANカードの番号と紐づける
	etheHeader ethernetHeader            // Ethernetヘッダ　宛先とか自分のMACアドレスをテンプレートとして持つ
	ipdev      ipDevice                  //IPプロトコル用
}

// ネットデバイスの送信処理
func (netdev netDevice) netDeviceTransmit(data []byte) error {
	err := syscall.Sendto(netdev.socket, data, 0, &netdev.sockaddr)
	if err != nil {
		return err
	}
	return nil
}

func isIgnoreInterfaces(name string) bool {
	for _, ignore := range IGNORE_INTERFACES {
		if name == ignore {
			return true
		}
	}
	return false
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// ネットデバイスの受信処理
func (netdev *netDevice) netDevicePoll(mode string) error {
	recvbuffer := make([]byte, 1500)
	n, _, err := syscall.Recvfrom(netdev.socket, recvbuffer, 0)
	if err != nil {
		if n == -1 {
			return nil // 受信エラーは無視する
		} else {
			return fmt.Errorf("recv err, n is %d, device is %s, err is %s", n, netdev.name, err)
		}
	}
	//Chapter1では受診したパケットをprintするだけ
	if mode == "ch1" {
		fmt.Printf("Received %d bytes from %s: %x\n", n, netdev.name, recvbuffer[:n])
	} else {
		ethernetInput(netdev, recvbuffer[:n])
	}
	return nil
}

// インターフェイス名からデバイスを探す
func getnetDeviceByName(name string) *netDevice {
	for _, dev := range netDeviceList {
		if name == dev.name {
			return dev
		}
	}
	return &netDevice{}
}
