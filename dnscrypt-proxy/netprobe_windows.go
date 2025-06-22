package main

import (
	"errors"
	"net"
	"time"

	"github.com/jedisct1/dlog"
)

func NetProbe(proxy *Proxy, address string, timeout int) error {
	if timeout == 0 {
		return nil
	}
	addrlen := len(address)
	if addrlen <= 8 {
		addrerr := ""
		if addrlen > 0 {
			addrerr = "Netprobe address not configured correctly. Example: 1.1.1.1:53"
		} else {
			addrerr = "Netprobe address not configured."
		}
		return errors.New(addrerr)
	}
	if captivePortalHandler, err := ColdStart(proxy); err == nil {
		if captivePortalHandler != nil {
			defer captivePortalHandler.Stop()
		}
	} else {
		dlog.Critical(err)
	}
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	retried := false
	if timeout <= 0 {
		timeout = MaxTimeout
	} else {
		timeout = Min(MaxTimeout, timeout)
	}
	for tries := 60; tries > 0; tries-- {
		pc, err := net.DialUDP("udp", nil, remoteUDPAddr)
		if err == nil {
			// Write at least 1 byte. This ensures that sockets are ready to use for writing.
			// Windows specific: during the system startup, sockets can be created but the underlying buffers may not be
			// setup yet. If this is the case Write fails with WSAENOBUFS: "An operation on a socket could not be
			// performed because the system lacked sufficient buffer space or because a queue was full"
			dlog.Notice("Sending an empty packet query to netprobe address")
			_, err = pc.Write([]byte{0})
		}
		if err != nil {
			pc.Close()
			if !retried {
				retried = true
				dlog.Notice("Network not available yet -- waiting...")
			}
			dlog.Debug(err)
			time.Sleep(1 * time.Second)
			// Needed to exit NetProbe since the packet can be blocked by a firewall but a connection to the query addr may be established
			if Bypass_NetProbe == 3 { // Add timeout check to return more on point info
				dlog.Notice("Connection to NetProbe address failed")
				return nil
			}
			continue
		}
		pc.Close()
		if Bypass_NetProbe != 3 {
			Bypass_NetProbe = 3
			dlog.Notice("Network connectivity detected")
		}
		return nil
	}
	dlog.Error("Timeout while waiting for network connectivity")
	return nil
}
