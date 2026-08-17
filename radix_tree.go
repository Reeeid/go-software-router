package main

type radixTreeNode struct {
	depth  int
	parent *radixTreeNode
	node0  *radixTreeNode
	node1  *radixTreeNode
	data   ipRouteEntry
	value  int
}

type ipRouteType int

const (
	connected ipRouteType = iota
	network
)

type ipRouteEntry struct {
	iptype  ipRouteType
	netdev  *netDevice
	nexthop uint32
}

func (node *radixTreeNode) radixTreeAdd(prefixIpAddr, prefixLen uint32, entryData ipRouteEntry) {
	//ルートノードから辿る
	current := node
	//枝を辿る
	for i := 1; i <= int(prefixLen); i++ {
		if prefixIpAddr>>(32-i)&0x01 == 1 {
			//上からiビット目が１なら
			if current.node1 == nil {
				current.node1 = &radixTreeNode{
					parent: current,
					depth:  i,
					value:  0,
				}
			}
			current = current.node1
		} else { //上からiビット目が0なら
			//たどる先の枝が無かったら作る
			if current.node0 == nil {
				current.node0 = &radixTreeNode{
					parent: current,
					depth:  i,
					value:  0,
				}
			}
			current = current.node0
		}
	}
	// 最後にデータをセット
	current.data = entryData
}

func subnetToPrefixLen(subnet uint32) uint32 {
	var length uint32
	for i := 0; i < 32; i++ {
		if subnet>>(31-i)&0x01 == 0 {
			break
		}
		length++
	}
	return length
}

func (node *radixTreeNode) radixTreeSearch(prefixIpAddr uint32) ipRouteEntry {
	current := node
	var result ipRouteEntry
	// 検索するIPアドレスを比較して1ビットずつ辿っていく
	for i := 1; i <= 32; i++ {
		if current.data != (ipRouteEntry{}) {
			result = current.data
		}
		if prefixIpAddr>>(32-i)&0x01 == 1 {
			if current.node1 == nil {
				return result
			}
			current = current.node1
		} else {
			if current.node0 == nil {
				return result
			}
			current = current.node0
		}
	}
	if current.data != (ipRouteEntry{}) {
		result = current.data
	}
	return result
}
