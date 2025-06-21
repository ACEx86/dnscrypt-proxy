//go:build !windows

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
		if err != nil {
			pc.Close()
			if !retried {
				retried = true
				dlog.Notice("Network not available yet -- waiting...")
			}
			dlog.Debug(err)
			time.Sleep(1 * time.Second)
			// Needed to exit NetProbe since the packet can be blocked by a firewall but a connection to the query addr may be established
			if Bypass_NetProbe == 3 {
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
