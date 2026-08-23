package main

type natEntry struct {
	globalIpAddr uint32
	localIpAddr  uint32
	globalPort   uint16 //icmpのidentifierとしても使う
	localPort    uint16
}

//UDPとTCPのNATテーブルセット

type natEntryList struct {
	tcp  [NAT_GLOBAL_PORT_SIZE]*natEntry
	udp  [NAT_GLOBAL_PORT_SIZE]*natEntry
	icmp [NAT_GLOBAL_PORT_MAX]*natEntry
}
type natProtocolType uint8

const NAT_GLOBAL_PORT_MIN = 1024
const NAT_GLOBAL_PORT_MAX = 65535
const NAT_GLOBAL_PORT_SIZE = NAT_GLOBAL_PORT_MAX - NAT_GLOBAL_PORT_MIN + 1

const (
	tcp natProtocolType = iota
	udp
	icmp
)

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
			}
		}
	case tcp:
		//tcpも同様、空いているエントリを見つけてグローバルポートを設定しエントリを返す
		for i, v := range entry.tcp {
			if v == nil {
				entry.tcp[i] = &natEntry{
					globalPort: uint16(NAT_GLOBAL_PORT_MIN + i),
				}
			}
		}
	case icmp:
		//icmpも同様であるが、空いているエントリを見つけてグローバルポートにidentifierを設定しエントリを返す
		for i, v := range entry.icmp {
			if v == nil {
				entry.icmp[i] = &natEntry{
					globalPort: uint16(NAT_GLOBAL_PORT_MIN + i), //identifier
				}
			}
		}
	}
	return &natEntry{}
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
	return &natEntry{}
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
	return &natEntry{}
}

func natExec(ipHeader *ipHeader)
