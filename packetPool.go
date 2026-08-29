package main

import (
	"encoding/binary"
	"errors"
	"sync"
)

const (
	MaxPacketSize   = 2048
	DefaultHeadroom = 128 // L2(14B) + L3(20B-60B) + L4(20B-60B) を十分収める余白
)

// PacketBuffer はパケットをゼロコピーで操作するための構造体
type PacketBuffer struct {
	buf  [MaxPacketSize]byte
	head int // 有効データの先頭インデックス
	tail int // 有効データの末尾インデックス

	// レイヤごとの開始オフセット
	L3Offset int
	L4Offset int
}

var pktPool = sync.Pool{
	New: func() any {
		return &PacketBuffer{}
	},
}

// AllocPacket はプールからバッファを取得し、Headroomを初期化
func AllocPacket() *PacketBuffer {
	pkt := pktPool.Get().(*PacketBuffer)
	pkt.Reset()
	return pkt
}

// Release はバッファをプールへ返却（GC負荷をゼロ化）
func (p *PacketBuffer) Release() {
	pktPool.Put(p)
}

// Reset はバッファの位置ポインタを初期状態に戻す
func (p *PacketBuffer) Reset() {
	p.head = DefaultHeadroom
	p.tail = DefaultHeadroom
	p.L3Offset = 0
	p.L4Offset = 0
}

// Data は現在有効なパケット全体のバイトスライスを返す
func (p *PacketBuffer) Data() []byte {
	return p.buf[p.head:p.tail]
}

// Len は有効データ長を返す
func (p *PacketBuffer) Len() int {
	return p.tail - p.head
}

// Prepend はヘッダ付与時にデータを前方に拡張する（コピーなし）
func (p *PacketBuffer) Prepend(n int) ([]byte, error) {
	if p.head < n {
		return nil, errors.New("headroom overflow")
	}
	p.head -= n
	return p.buf[p.head : p.head+n], nil
}

// Append は末尾にデータを拡張する
func (p *PacketBuffer) Append(n int) ([]byte, error) {
	if p.tail+n > MaxPacketSize {
		return nil, errors.New("tailroom overflow")
	}
	oldTail := p.tail
	p.tail += n
	return p.buf[oldTail:p.tail], nil
}

// 段階チェックサム計算（擬似ヘッダ結合用のメモリ確保を排除）

// ChecksumPartial は16ビットごとの加算を行い、未反転の合計値を返す
func ChecksumPartial(data []byte, initialSum uint32) uint32 {
	sum := initialSum
	n := len(data)

	for i := 0; i < n-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	return sum
}

// FinalizeChecksum はキャリーを折り返し、1の補数（ビット反転）を取る
func FinalizeChecksum(sum uint32) uint16 {
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ComputeL4ChecksumZeroCopy は擬似ヘッダを append せずにL4チェックサムを計算
func ComputeL4ChecksumZeroCopy(srcIP, dstIP uint32, proto uint8, l4Data []byte) uint16 {
	// スタック上に12バイトの擬似ヘッダを用意
	var pseudo [12]byte
	binary.BigEndian.PutUint32(pseudo[0:4], srcIP)
	binary.BigEndian.PutUint32(pseudo[4:8], dstIP)
	pseudo[8] = 0x00
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4Data)))

	// 擬似ヘッダとL4データを別々に積算
	sum := ChecksumPartial(pseudo[:], 0)
	sum = ChecksumPartial(l4Data, sum)

	return FinalizeChecksum(sum)
}
