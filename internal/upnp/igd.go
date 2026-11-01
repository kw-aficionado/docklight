// Package upnp discovers and controls IPv4 UPnP Internet Gateway Devices.
package upnp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrNoGateway = errors.New("no compatible UPnP Internet Gateway was discovered")

type Mapping struct {
	RemoteHost     string
	ExternalPort   uint16
	Protocol       string
	InternalPort   uint16
	InternalClient string
	Enabled        bool
	Description    string
	LeaseDuration  uint32
}

type Gateway interface {
	LocalIP() net.IP
	ExternalIP(context.Context) (net.IP, error)
	GetMapping(context.Context, string, uint16) (Mapping, bool, error)
	AddMapping(context.Context, Mapping) error
	DeleteMapping(context.Context, string, uint16) error
}

type service struct {
	serviceType string
	controlURL  *url.URL
}

type gateway struct {
	localIP    net.IP
	services   []service
	httpClient *http.Client
	mu         sync.Mutex
	selected   int
}

type deviceDescription struct {
	Services []struct {
		Type       string `xml:"serviceType"`
		ControlURL string `xml:"controlURL"`
	} `xml:"serviceList>service"`
	Devices []deviceDescription `xml:"deviceList>device"`
}

// Discover searches the local IPv4 segment for an IGD and selects the first
// WANIPConnection or WANPPPConnection service that reports a WAN address.
func Discover(ctx context.Context) (Gateway, error) {
	localIP, err := routeLocalIPv4()
	if err != nil {
		return nil, fmt.Errorf("find the host LAN address for UPnP discovery: %w", err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open a local UPnP discovery socket: %w", err)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stopClose()
		_ = conn.Close()
	}()

	ssdp := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	for _, target := range []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"upnp:rootdevice",
	} {
		request := "M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n" +
			"ST: " + target + "\r\n\r\n"
		if _, err = conn.WriteToUDP([]byte(request), ssdp); err != nil {
			return nil, fmt.Errorf("send UPnP discovery request: %w", err)
		}
	}

	deadline := time.Now().Add(2500 * time.Millisecond)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	locations := map[string]*url.URL{}
	buffer := make([]byte, 16*1024)
	for time.Now().Before(deadline) {
		readUntil := time.Now().Add(200 * time.Millisecond)
		if deadline.Before(readUntil) {
			readUntil = deadline
		}
		_ = conn.SetReadDeadline(readUntil)
		n, source, readErr := conn.ReadFromUDP(buffer)
		if readErr != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return nil, fmt.Errorf("read UPnP discovery response: %w", readErr)
		}
		location, parseErr := ssdpLocation(buffer[:n], source.IP)
		if parseErr == nil {
			locations[location.String()] = location
		}
	}
	if len(locations) == 0 {
		return nil, ErrNoGateway
	}

	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("UPnP device redirects are not followed")
		},
	}
	for _, location := range locations {
		services, fetchErr := fetchServices(ctx, client, location)
		if fetchErr != nil || len(services) == 0 {
			continue
		}
		candidate := &gateway{localIP: append(net.IP(nil), localIP...), services: services, selected: -1}
		if _, statusErr := candidate.ExternalIP(ctx); statusErr == nil {
			return candidate, nil
		}
	}
	return nil, ErrNoGateway
}

func routeLocalIPv4() (net.IP, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil || addr.IP.IsUnspecified() || addr.IP.IsLoopback() || addr.IP.IsMulticast() {
		return nil, errors.New("no usable IPv4 route to the local network")
	}
	return addr.IP.To4(), nil
}

func ssdpLocation(packet []byte, responseIP net.IP) (*url.URL, error) {
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(packet)), &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("unexpected SSDP response status")
	}
	location, err := url.Parse(strings.TrimSpace(response.Header.Get("Location")))
	if err != nil || location == nil || location.Scheme != "http" || location.User != nil || location.RawQuery != "" || location.Fragment != "" {
		return nil, errors.New("invalid UPnP device location")
	}
	ip := net.ParseIP(location.Hostname())
	if ip == nil || ip.To4() == nil || (!ip.IsPrivate() && !ip.IsLinkLocalUnicast()) {
		return nil, errors.New("UPnP location must use a private IPv4 address")
	}
	if responseIP == nil || !ip.Equal(responseIP) {
		return nil, errors.New("UPnP location must match the device that sent the SSDP response")
	}
	if location.Port() != "" {
		port, portErr := strconv.Atoi(location.Port())
		if portErr != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid UPnP device port")
		}
	}
	return location, nil
}

func fetchServices(ctx context.Context, client *http.Client, location *url.URL) ([]service, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("UPnP device description returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("UPnP device description is too large")
	}
	var root struct {
		Device deviceDescription `xml:"device"`
	}
	if err = xml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("parse UPnP device description: %w", err)
	}
	services := make([]service, 0, 2)
	var collect func(deviceDescription)
	collect = func(device deviceDescription) {
		for _, candidate := range device.Services {
			if !supportedService(candidate.Type) {
				continue
			}
			if strings.TrimSpace(candidate.ControlURL) == "" {
				continue
			}
			controlURL, parseErr := url.Parse(candidate.ControlURL)
			if parseErr != nil || controlURL.IsAbs() && !sameAuthority(location, controlURL) {
				continue
			}
			resolved := location.ResolveReference(controlURL)
			if resolved.Scheme != "http" || !sameAuthority(location, resolved) || resolved.User != nil {
				continue
			}
			services = append(services, service{serviceType: candidate.Type, controlURL: resolved})
		}
		for _, child := range device.Devices {
			collect(child)
		}
	}
	collect(root.Device)
	return services, nil
}

func supportedService(serviceType string) bool {
	return serviceType == "urn:schemas-upnp-org:service:WANIPConnection:1" ||
		serviceType == "urn:schemas-upnp-org:service:WANIPConnection:2" ||
		serviceType == "urn:schemas-upnp-org:service:WANPPPConnection:1"
}

func sameAuthority(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return "80"
}

func (g *gateway) LocalIP() net.IP { return append(net.IP(nil), g.localIP...) }

func (g *gateway) ExternalIP(ctx context.Context) (net.IP, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.selected >= 0 && g.selected < len(g.services) {
		values, err := g.call(ctx, g.services[g.selected], "GetExternalIPAddress", nil)
		if err == nil {
			ip := net.ParseIP(strings.TrimSpace(values["NewExternalIPAddress"]))
			if ip != nil && !ip.IsUnspecified() {
				return ip, nil
			}
			return nil, errors.New("router returned an invalid WAN IP address")
		}
	}
	var lastErr error
	for index, candidate := range g.services {
		values, err := g.call(ctx, candidate, "GetExternalIPAddress", nil)
		if err != nil {
			lastErr = err
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(values["NewExternalIPAddress"]))
		if ip == nil || ip.IsUnspecified() {
			lastErr = errors.New("router returned an invalid WAN IP address")
			continue
		}
		g.selected = index
		return ip, nil
	}
	if lastErr == nil {
		lastErr = ErrNoGateway
	}
	return nil, lastErr
}

func (g *gateway) selectedService(ctx context.Context) (service, error) {
	if _, err := g.ExternalIP(ctx); err != nil {
		return service{}, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.selected < 0 || g.selected >= len(g.services) {
		return service{}, ErrNoGateway
	}
	return g.services[g.selected], nil
}

func (g *gateway) GetMapping(ctx context.Context, protocol string, externalPort uint16) (Mapping, bool, error) {
	candidate, err := g.selectedService(ctx)
	if err != nil {
		return Mapping{}, false, err
	}
	values, err := g.call(ctx, candidate, "GetSpecificPortMappingEntry", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(externalPort))},
		{"NewProtocol", strings.ToUpper(protocol)},
	})
	if err != nil {
		var soapErr *soapError
		if errors.As(err, &soapErr) && soapErr.code == 714 {
			return Mapping{}, false, nil
		}
		return Mapping{}, false, err
	}
	internalPort, err := strconv.ParseUint(values["NewInternalPort"], 10, 16)
	if err != nil || internalPort == 0 {
		return Mapping{}, false, errors.New("router returned an invalid internal port mapping")
	}
	lease, _ := strconv.ParseUint(values["NewLeaseDuration"], 10, 32)
	return Mapping{
		RemoteHost: values["NewRemoteHost"], ExternalPort: externalPort,
		Protocol: strings.ToUpper(values["NewProtocol"]), InternalPort: uint16(internalPort),
		InternalClient: values["NewInternalClient"], Enabled: strings.EqualFold(values["NewEnabled"], "1") || strings.EqualFold(values["NewEnabled"], "true"),
		Description: values["NewPortMappingDescription"], LeaseDuration: uint32(lease),
	}, true, nil
}

func (g *gateway) AddMapping(ctx context.Context, mapping Mapping) error {
	candidate, err := g.selectedService(ctx)
	if err != nil {
		return err
	}
	_, err = g.call(ctx, candidate, "AddPortMapping", [][2]string{
		{"NewRemoteHost", mapping.RemoteHost},
		{"NewExternalPort", strconv.Itoa(int(mapping.ExternalPort))},
		{"NewProtocol", strings.ToUpper(mapping.Protocol)},
		{"NewInternalPort", strconv.Itoa(int(mapping.InternalPort))},
		{"NewInternalClient", mapping.InternalClient},
		{"NewEnabled", map[bool]string{true: "1", false: "0"}[mapping.Enabled]},
		{"NewPortMappingDescription", mapping.Description},
		{"NewLeaseDuration", strconv.FormatUint(uint64(mapping.LeaseDuration), 10)},
	})
	return err
}

func (g *gateway) DeleteMapping(ctx context.Context, protocol string, externalPort uint16) error {
	candidate, err := g.selectedService(ctx)
	if err != nil {
		return err
	}
	_, err = g.call(ctx, candidate, "DeletePortMapping", [][2]string{
		{"NewRemoteHost", ""},
		{"NewExternalPort", strconv.Itoa(int(externalPort))},
		{"NewProtocol", strings.ToUpper(protocol)},
	})
	var soapErr *soapError
	if errors.As(err, &soapErr) && soapErr.code == 714 {
		return nil
	}
	return err
}

type soapError struct {
	code int
	text string
}

func (e *soapError) Error() string {
	if e.text == "" {
		return fmt.Sprintf("UPnP router rejected the action (error %d)", e.code)
	}
	return fmt.Sprintf("UPnP router rejected the action (error %d): %s", e.code, e.text)
}

func (g *gateway) call(ctx context.Context, target service, action string, params [][2]string) (map[string]string, error) {
	var envelope strings.Builder
	envelope.WriteString(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:`)
	envelope.WriteString(action)
	envelope.WriteString(` xmlns:u="`)
	envelope.WriteString(target.serviceType)
	envelope.WriteString(`">`)
	for _, param := range params {
		envelope.WriteString(`<`)
		envelope.WriteString(param[0])
		envelope.WriteString(`>`)
		_ = xml.EscapeText(&envelope, []byte(param[1]))
		envelope.WriteString(`</`)
		envelope.WriteString(param[0])
		envelope.WriteString(`>`)
	}
	envelope.WriteString(`</u:`)
	envelope.WriteString(action)
	envelope.WriteString(`></s:Body></s:Envelope>`)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.controlURL.String(), strings.NewReader(envelope.String()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	request.Header.Set("SOAPAction", `"`+target.serviceType+`#`+action+`"`)
	client := g.httpClient
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("UPnP control redirects are not followed")
		}}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("UPnP control response is too large")
	}
	values, parseErr := soapValues(body)
	if parseErr != nil {
		return nil, parseErr
	}
	if code, parseErr := strconv.Atoi(values["errorCode"]); parseErr == nil {
		return nil, &soapError{code: code, text: values["errorDescription"]}
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("UPnP control returned HTTP %d", response.StatusCode)
	}
	return values, nil
}

func soapValues(body []byte) (map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	values := map[string]string{}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse UPnP control response: %w", err)
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		name := start.Name.Local
		if name == "NewExternalIPAddress" || name == "NewRemoteHost" || name == "NewExternalPort" || name == "NewProtocol" || name == "NewInternalPort" || name == "NewInternalClient" || name == "NewEnabled" || name == "NewPortMappingDescription" || name == "NewLeaseDuration" || name == "errorCode" || name == "errorDescription" {
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return nil, err
			}
			values[name] = value
		}
	}
	return values, nil
}
