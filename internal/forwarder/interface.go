package forwarder

import "github.com/vishvananda/netlink"

type infControler struct {
	inflink *netlink.Link
	vlink   *netlink.Link
}

// func launchInterface() (*infControler, error) {

// }
