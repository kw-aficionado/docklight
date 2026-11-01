package upnp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type upnpRoundTripper func(*http.Request) (*http.Response, error)

func (fn upnpRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestSSDPResponseRequiresAPrivateLocationMatchingItsSender(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:1900/root.xml\r\n\r\n")
	if _, err := ssdpLocation(response, net.ParseIP("192.168.1.1")); err != nil {
		t.Fatalf("expected a matching private router location: %v", err)
	}
	for _, sender := range []net.IP{net.ParseIP("192.168.1.2"), net.ParseIP("203.0.113.1")} {
		if _, err := ssdpLocation(response, sender); err == nil {
			t.Fatalf("accepted UPnP location from mismatched sender %s", sender)
		}
	}
	for _, location := range []string{"http://router.local/root.xml", "http://203.0.113.1/root.xml", "https://192.168.1.1/root.xml"} {
		packet := []byte("HTTP/1.1 200 OK\r\nLOCATION: " + location + "\r\n\r\n")
		if _, err := ssdpLocation(packet, net.ParseIP("192.168.1.1")); err == nil {
			t.Fatalf("accepted unsafe UPnP location %q", location)
		}
	}
}

func TestFetchServicesRestrictsControlURLToTheDiscoveredGateway(t *testing.T) {
	location, err := ssdpLocation([]byte("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1/root.xml\r\n\r\n"), net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	body := `<root><device><serviceList>` +
		`<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/upnp/control</controlURL></service>` +
		`<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>http://192.168.1.2:80/other</controlURL></service>` +
		`</serviceList></device></root>`
	client := &http.Client{Transport: upnpRoundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != location.String() {
			t.Fatalf("description request escaped the discovered location: %s", request.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: request}, nil
	})}
	services, err := fetchServices(context.Background(), client, location)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0].controlURL.String() != "http://192.168.1.1/upnp/control" {
		t.Fatalf("unexpected accepted gateway services: %#v", services)
	}
}

func TestSOAPCallEscapesParametersAndSendsTheExpectedAction(t *testing.T) {
	transport := upnpRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.Header.Get("SOAPAction") != `"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"` {
			t.Errorf("unexpected SOAP request: method=%s action=%q", r.Method, r.Header.Get("SOAPAction"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "Docklight &amp; &lt;router&gt;") {
			t.Errorf("SOAP parameter was not XML escaped: %s", body)
		}
		responseBody := `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(responseBody)), Header: make(http.Header), Request: r}, nil
	})
	client := &gateway{
		services:   []service{{serviceType: "urn:schemas-upnp-org:service:WANIPConnection:1", controlURL: mustParseURL(t, "http://192.168.1.1/upnp/control")}},
		httpClient: &http.Client{Transport: transport}, selected: 0,
	}
	if _, err := client.call(context.Background(), client.services[0], "AddPortMapping", [][2]string{{"NewPortMappingDescription", "Docklight & <router>"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSOAPValuesExtractsNoEntryFault(t *testing.T) {
	values, err := soapValues([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError><errorCode>714</errorCode><errorDescription>NoSuchEntryInArray</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`))
	if err != nil || values["errorCode"] != "714" || values["errorDescription"] != "NoSuchEntryInArray" {
		t.Fatalf("SOAP fault values were not extracted: values=%#v err=%v", values, err)
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	u, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
