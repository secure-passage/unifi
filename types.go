// nolint: revive
package unifi

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
)

func init() {
	gofakeit.AddFuncLookup("port", gofakeit.Info{
		Category:    "custom",
		Description: "Random Unifi Port integer value",
		Example:     "8443",
		Output:      "int",
		Generate: func(r *rand.Rand, m *gofakeit.MapParams, info *gofakeit.Info) (interface{}, error) {
			return r.Int31n(65535), nil
		},
	})

	gofakeit.AddFuncLookup("timestamp", gofakeit.Info{
		Category:    "custom",
		Description: "Recent timestamp value",
		Example:     "123456",
		Output:      "int64",
		Generate: func(r *rand.Rand, m *gofakeit.MapParams, info *gofakeit.Info) (interface{}, error) {
			return gofakeit.DateRange(time.Now().Add(-time.Second*59), time.Now().Add(-time.Second)).Unix(), nil
		},
	})

	gofakeit.AddFuncLookup("recent_time", gofakeit.Info{
		Category:    "custom",
		Description: "Recent time.Time value",
		Example:     "time.Now().Add(-time.Second)",
		Output:      "time.Time",
		Generate: func(r *rand.Rand, m *gofakeit.MapParams, info *gofakeit.Info) (interface{}, error) {
			return gofakeit.DateRange(time.Now().Add(-time.Second*59), time.Now().Add(-time.Second)), nil
		},
	})

	gofakeit.AddFuncLookup("timestamps", gofakeit.Info{
		Category:    "custom",
		Description: "Recent timestamp values",
		Example:     "123456",
		Output:      "[]int64",
		Params: []gofakeit.Param{
			{
				Field:       "length",
				Display:     "number of items to generate",
				Type:        "uint",
				Optional:    false,
				Default:     "2",
				Description: "The number of ints to generate",
			},
		},
		Generate: func(r *rand.Rand, m *gofakeit.MapParams, info *gofakeit.Info) (interface{}, error) {
			l, err := info.GetUint(m, "length")
			if err != nil {
				return nil, err
			}

			result := make([]int64, 0)
			for i := 0; i < int(l); i++ {
				result = append(result, gofakeit.DateRange(time.Now().Add(time.Hour-2), time.Now()).Unix())
			}

			return result, nil
		},
	})

	gofakeit.AddFuncLookup("constFlexBool", gofakeit.Info{
		Category:    "custom",
		Description: "Configured FlexBool",
		Example:     "FlexBool{Val: false, Txt: \"false\"}",
		Output:      "FlexBool",
		Params: []gofakeit.Param{
			{
				Field:       "value",
				Display:     "value",
				Type:        "bool",
				Optional:    true,
				Default:     "false",
				Description: "The default value",
			},
		},
		Generate: func(r *rand.Rand, m *gofakeit.MapParams, info *gofakeit.Info) (interface{}, error) {
			l, err := info.GetBool(m, "value")
			if err != nil {
				return nil, err
			}

			return *NewFlexBool(l), nil
		},
	})

	gofakeit.AddFuncLookup("tempStatusByName", gofakeit.Info{
		Category:    "custom",
		Description: "Configured TempStatusByName",
		Example:     "TempStatusByName{...}",
		Output:      "TempStatusByName",
		Generate: func(r *rand.Rand, m *gofakeit.MapParams, info *gofakeit.Info) (interface{}, error) {
			return TempStatusByName{
				"cpu":     NewFlexTemp(float64(r.Int31n(100))),
				"sys":     NewFlexTemp(float64(r.Int31n(100))),
				"probe":   NewFlexTemp(float64(r.Int31n(100))),
				"memory":  NewFlexTemp(float64(r.Int31n(100))),
				"network": NewFlexTemp(float64(r.Int31n(100))),
			}, nil
		},
	})
}

var (
	ErrCannotUnmarshalFlexInt    = fmt.Errorf("cannot unmarshal to FlexInt")
	ErrCannotUnmarshalFlexString = fmt.Errorf("cannot unmarshal to FlexString")
)

// This is a list of unifi API paths.
// The %s in each string must be replaced with a Site.Name.
const (
	// APIRogueAP shows your neighbors' wifis.
	APIRogueAP string = "/api/s/%s/stat/rogueap"
	// APIStatusPath shows Controller version.
	APIStatusPath string = "/status"
	// APIEventPath contains UniFi Event data.
	APIEventPath string = "/api/s/%s/stat/event"
	// APISiteList is the path to the api site list.
	APISiteList string = "/api/stat/sites"
	// APISiteDPI is site DPI data.
	APISiteDPI string = "/api/s/%s/stat/sitedpi"
	// APISiteDPI is site DPI data.
	APIClientDPI string = "/api/s/%s/stat/stadpi"
	// APIClientPath is Unifi Clients API Path.
	APIClientPath string = "/api/s/%s/stat/sta"
	// APIAllUserPath is Unifi Insight all previous Clients API Path.
	APIAllUserPath string = "/api/s/%s/stat/alluser"
	// APINetworkPath is where we get data about Unifi networks.
	APINetworkPath string = "/api/s/%s/rest/networkconf"
	// APIDevicePath is where we get data about Unifi devices.
	APIDevicePath string = "/api/s/%s/stat/device"
	// APILoginPath is Unifi Controller Login API Path.
	APILoginPath string = "/api/login"
	// APILoginPathNew is how we log into UDM 5.12.55+.
	APILoginPathNew string = "/api/auth/login"
	// APILogoutPath is how we logout from UDM.
	APILogoutPath string = "/api/logout"
	// APIEventPathIDS returns Intrusion Detection/Prevention Systems Events.
	APIEventPathIDS string = "/api/s/%s/stat/ips/event"
	// APIEventPathAlarms contains the site alarms.
	APIEventPathAlarms string = "/api/s/%s/list/alarm"
	// APIPrefixNew is the prefix added to the new API paths; except login. duh.
	APIPrefixNew string = "/proxy/protect"
	// APIAnomaliesPath returns site anomalies.
	APIAnomaliesPath string = "/api/s/%s/stat/anomalies"
	APICommandPath   string = "/api/s/%s/cmd"
	APIDevMgrPath    string = APICommandPath + "/devmgr"
)

// path returns the correct api path based on the new variable.
// new is based on the unifi-controller output. is it new or old output?
func (u *Unifi) path(path string) string {
	if u.new {
		if path == APILoginPath {
			return APILoginPathNew
		}

		if !strings.HasPrefix(path, APIPrefixNew) && path != APILoginPathNew {
			return APIPrefixNew + path
		}
	}

	return path
}

// Logger is a base type to deal with changing log outputs. Create a logger
// that matches this interface to capture debug and error logs.
type Logger func(msg string, fmt ...interface{})

// discardLogs is the default debug logger.
func discardLogs(_ string, _ ...interface{}) {
	// do nothing.
}

// Devices contains a list of all the unifi devices from a controller.
// Contains Access points, security gateways and switches.
type Devices struct {
	UAPs []*UAP `fakesize:"5"`
	USGs []*USG `fakesize:"5"`
	USWs []*USW `fakesize:"5"`
	UDMs []*UDM `fakesize:"5"`
	UXGs []*UXG `fakesize:"5"`
	PDUs []*PDU `fakesize:"5"`
}

// Config is the data passed into our library. This configures things and allows
// us to connect to a controller and write log messages. Optional SSLCert is used
// for ssl cert pinning; provide the content of a PEM to validate the server's cert.
type Config struct {
	User      string
	Pass      string
	URL       string
	SSLCert   [][]byte
	ErrorLog  Logger
	DebugLog  Logger
	Timeout   time.Duration // how long to wait for replies, default: forever.
	VerifySSL bool
}

type UnifiClient interface { //nolint: revive
	// GetAlarms returns Alarms for a list of Sites.
	GetAlarms(sites []*Site) ([]*Alarm, error)
	// GetAlarmsSite retreives the Alarms for a single Site.
	GetAlarmsSite(site *Site) ([]*Alarm, error)
	// GetAnomalies returns Anomalies for a list of Sites.
	GetAnomalies(sites []*Site, timeRange ...time.Time) ([]*Anomaly, error)
	// GetAnomaliesSite retreives the Anomalies for a single Site.
	GetAnomaliesSite(site *Site, timeRange ...time.Time) ([]*Anomaly, error)
	// GetClients returns a response full of clients' data from the UniFi Controller.
	GetClients(sites []*Site) ([]*Client, error)
	// GetClientsDPI garners dpi data for clients.
	GetClientsDPI(sites []*Site) ([]*DPITable, error)
	// GetDevices returns a response full of devices' data from the UniFi Controller.
	GetDevices(sites []*Site) (*Devices, error)
	// GetUSWs returns all switches, an error, or nil if there are no switches.
	GetUSWs(site *Site) ([]*USW, error)
	// GetUAPs returns all access points, an error, or nil if there are no APs.
	GetUAPs(site *Site) ([]*UAP, error)
	// GetUDMs returns all dream machines, an error, or nil if there are no UDMs.
	GetUDMs(site *Site) ([]*UDM, error)
	// GetUXGs returns all 10Gb gateways, an error, or nil if there are no UXGs.
	GetUXGs(site *Site) ([]*UXG, error)
	// GetUSGs returns all 1Gb gateways, an error, or nil if there are no USGs.
	GetUSGs(site *Site) ([]*USG, error)
	// GetEvents returns a response full of UniFi Events for the last 1 hour from multiple sites.
	GetEvents(sites []*Site, hours time.Duration) ([]*Event, error)
	// GetSiteEvents retrieves the last 1 hour's worth of events from a single site.
	GetSiteEvents(site *Site, hours time.Duration) ([]*Event, error)
	// GetIDS returns Intrusion Detection Systems events for a list of Sites.
	// timeRange may have a length of 0, 1 or 2. The first time is Start, the second is End.
	// Events between start and end are returned. End defaults to time.Now().
	GetIDS(sites []*Site, timeRange ...time.Time) ([]*IDS, error)
	// GetIDSSite retrieves the Intrusion Detection System Data for a single Site.
	// timeRange may have a length of 0, 1 or 2. The first time is Start, the second is End.
	// Events between start and end are returned. End defaults to time.Now().
	GetIDSSite(site *Site, timeRange ...time.Time) ([]*IDS, error)
	// GetNetworks returns a response full of network data from the UniFi Controller.
	GetNetworks(sites []*Site) ([]Network, error)
	// GetSites returns a list of configured sites on the UniFi controller.
	GetSites() ([]*Site, error)
	// GetSiteDPI garners dpi data for sites.
	GetSiteDPI(sites []*Site) ([]*DPITable, error)
	// GetRogueAPs returns RogueAPs for a list of Sites.
	// Use GetRogueAPsSite if you want more control.
	GetRogueAPs(sites []*Site) ([]*RogueAP, error)
	// GetRogueAPsSite returns RogueAPs for a single Site.
	GetRogueAPsSite(site *Site) ([]*RogueAP, error)
	// Login is a helper method. It can be called to grab a new authentication cookie.
	Login() error
	// Logout closes the current session.
	Logout() error
	// GetServerData sets the controller's version and UUID. Only call this if you
	// previously called Login and suspect the controller version has changed.
	GetServerData() (*ServerStatus, error)
	// GetUsers returns a response full of clients that connected to the UDM within the provided amount of time
	// using the insight historical connection data set.
	GetUsers(sites []*Site, hours int) ([]*User, error)
}

// Unifi is what you get in return for providing a password! Unifi represents
// a controller that you can make authenticated requests to. Use this to make
// additional requests for devices, clients or other custom data. Do not set
// the loggers to nil. Set them to DiscardLogs if you want no logs.
type Unifi struct {
	*http.Client
	*Config
	*ServerStatus
	csrf         string
	fingerprints fingerprints
	new          bool
}

// ensure Unifi implements UnifiClient fully, will fail to compile otherwise
var _ UnifiClient = &Unifi{}

type fingerprints []string

// Contains returns true if the fingerprint is in the list.
func (f fingerprints) Contains(s string) bool {
	for i := range f {
		if s == f[i] {
			return true
		}
	}

	return false
}

// ServerStatus is the /status endpoint from the Unifi controller.
type ServerStatus struct {
	Up            FlexBool `json:"up"`
	ServerVersion string   `fake:"{appversion}" json:"server_version"`
	UUID          string   `fake:"{uuid}"       json:"uuid"`
}

type FlexString struct {
	Val         string
	Arr         []string
	hintIsArray bool
}

func NewFlexString(v string) *FlexString {
	return &FlexString{
		Val:         v,
		Arr:         []string{v},
		hintIsArray: false,
	}
}

func NewFlexStringArray(v []string) *FlexString {
	return &FlexString{
		Val:         strings.Join(v, ", "),
		Arr:         v,
		hintIsArray: true,
	}
}

// UnmarshalJSON converts a string or number to an integer.
// Generally, do not call this directly, it's used in the json interface.
func (f *FlexString) UnmarshalJSON(b []byte) error {
	var ust interface{}

	if err := json.Unmarshal(b, &ust); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	switch i := ust.(type) {
	case []interface{}:
		f.hintIsArray = true
		// try to cast to string
		for _, v := range i {
			if s, ok := v.(string); ok {
				f.Arr = append(f.Arr, s)
			}
		}

		f.Val = strings.Join(f.Arr, ", ")
	case []string:
		f.hintIsArray = true
		f.Val = strings.Join(i, ", ")
		f.Arr = i
	case string:
		f.Val = i
		f.Arr = []string{i}
	case nil:
		// noop, consider it empty values
	default:
		return fmt.Errorf("%v: %w", b, ErrCannotUnmarshalFlexString)
	}

	return nil
}

func (f FlexString) MarshalJSON() ([]byte, error) {
	// array case
	if f.hintIsArray {
		return json.Marshal(f.Arr)
	}

	// plain string case
	return json.Marshal(f.Val)
}

func (f FlexString) String() string {
	return f.Val
}

func (f FlexString) Fake(faker *gofakeit.Faker) interface{} {
	randValue := math.Min(math.Max(0.1, math.Abs(faker.Rand.Float64())), 120)
	s := fmt.Sprintf("fake-%0.2f", randValue)

	if faker.Rand.Intn(2) == 0 {
		// plain string value
		return FlexString{
			Val: s,
			Arr: []string{s},
		}
	}

	// array case
	s2 := fmt.Sprintf("fake-%0.2f-2", randValue)
	s3 := fmt.Sprintf("fake-%0.2f-3", randValue)
	arr := []string{s, s2, s3}

	return FlexString{
		Val: strings.Join(arr, ", "),
		Arr: arr,
	}
}

// FlexInt provides a container and unmarshalling for fields that may be
// numbers or strings in the Unifi API.
type FlexInt struct {
	Val float64
	Txt string
}

func NewFlexInt(v float64) *FlexInt {
	return &FlexInt{
		Val: v,
		Txt: strconv.FormatFloat(v, 'f', -1, 64),
	}
}

// UnmarshalJSON converts a string or number to an integer.
// Generally, do not call this directly, it's used in the json interface.
func (f *FlexInt) UnmarshalJSON(b []byte) error {
	var unk interface{}

	if err := json.Unmarshal(b, &unk); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	switch i := unk.(type) {
	case float64:
		f.Val = i
		f.Txt = strconv.FormatFloat(i, 'f', -1, 64)
	case string:
		f.Txt = i
		f.Val, _ = strconv.ParseFloat(i, 64)
	case nil:
		f.Txt = "0"
		f.Val = 0
	default:
		return fmt.Errorf("%v: %w", b, ErrCannotUnmarshalFlexInt)
	}

	return nil
}

func (f FlexInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Val)
}

func (f *FlexInt) Int() int {
	return int(f.Val)
}

func (f *FlexInt) Int64() int64 {
	return int64(f.Val)
}

func (f *FlexInt) String() string {
	return f.Txt
}

func (f *FlexInt) Add(o *FlexInt) {
	f.Val += o.Val
	f.Txt = strconv.FormatFloat(f.Val, 'f', -1, 64)
}

func (f *FlexInt) AddFloat64(v float64) {
	f.Val += v
	f.Txt = strconv.FormatFloat(f.Val, 'f', -1, 64)
}

// Fake implements gofakeit Fake interface
func (f FlexInt) Fake(faker *gofakeit.Faker) interface{} {
	randValue := math.Min(math.Max(1, math.Abs(faker.Rand.Float64())), 500)

	if faker.Rand.Intn(2) == 0 {
		// int-value
		return FlexInt{
			Val: float64(int64(randValue)),
			Txt: strconv.FormatInt(int64(randValue), 10),
		}
	}

	return FlexInt{
		Val: randValue,
		Txt: strconv.FormatFloat(randValue, 'f', 8, 64),
	}
}

// FlexBool provides a container and unmarshalling for fields that may be
// boolean or strings in the Unifi API.
type FlexBool struct {
	Val bool
	Txt string
}

func NewFlexBool(v bool) *FlexBool {
	textValue := "false"

	if v {
		textValue = "true"
	}

	return &FlexBool{
		Val: v,
		Txt: textValue,
	}
}

// UnmarshalJSON method converts armed/disarmed, yes/no, active/inactive or 0/1 to true/false.
// Really it converts ready, ok, up, t, armed, yes, active, enabled, 1, true to true. Anything else is false.
func (f *FlexBool) UnmarshalJSON(b []byte) error {
	f.Txt = strings.Trim(string(b), `"`)
	f.Val = f.Txt == "1" || strings.EqualFold(f.Txt, "true") || strings.EqualFold(f.Txt, "yes") ||
		strings.EqualFold(f.Txt, "t") || strings.EqualFold(f.Txt, "armed") || strings.EqualFold(f.Txt, "active") ||
		strings.EqualFold(f.Txt, "enabled") || strings.EqualFold(f.Txt, "ready") || strings.EqualFold(f.Txt, "up") ||
		strings.EqualFold(f.Txt, "ok")

	return nil
}

func (f FlexBool) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Val)
}

func (f *FlexBool) String() string {
	return f.Txt
}

func (f *FlexBool) Float64() float64 {
	if f.Val {
		return 1
	}

	return 0
}

// Fake implements gofakeit Fake interface
func (f FlexBool) Fake(faker *gofakeit.Faker) interface{} {
	opts := []bool{
		true,
		false,
	}

	v := opts[faker.Rand.Intn(2)]

	return FlexBool{
		Val: v,
		Txt: strconv.FormatBool(v),
	}
}

// FlexTemp provides a container and unmarshalling for fields that may be
// numbers or strings in the Unifi API as temperatures.
type FlexTemp struct {
	Val float64 // in Celsius
	Txt string
}

func NewFlexTemp(v float64) *FlexTemp {
	return &FlexTemp{
		Val: v,
		Txt: strconv.FormatFloat(v, 'f', -1, 64),
	}
}

// UnmarshalJSON converts a string or number to an integer.
// Generally, do not call this directly, it's used in the json interface.
func (f *FlexTemp) UnmarshalJSON(b []byte) error {
	var unk interface{}

	if err := json.Unmarshal(b, &unk); err != nil {
		return fmt.Errorf("json unmarshal: %w", err)
	}

	switch i := unk.(type) {
	case float64:
		f.Val = i
		f.Txt = strconv.FormatFloat(i, 'f', -1, 64)
	case string:
		f.Txt = i
		parts := strings.SplitN(string(b), " ", 2)

		if len(parts) == 2 {
			// format is: $val(int or float) $unit(C or F)
			f.Val, _ = strconv.ParseFloat(parts[0], 64)
		} else {
			// assume Celsius
			f.Val, _ = strconv.ParseFloat(i, 64)
		}
	case nil:
		f.Txt = "0"
		f.Val = 0
	default:
		return fmt.Errorf("%v: %w", b, ErrCannotUnmarshalFlexInt)
	}

	return nil
}

func (f FlexTemp) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.Val)
}

func (f *FlexTemp) Celsius() float64 {
	return f.Val
}

func (f *FlexTemp) CelsiusInt() int {
	return int(f.Val)
}

func (f *FlexTemp) CelsiusInt64() int64 {
	return int64(f.Val)
}

func (f *FlexTemp) Fahrenheit() float64 {
	return (f.Val * (9 / 5)) + 32
}

func (f *FlexTemp) FahrenheitInt() int {
	return int(f.Fahrenheit())
}

func (f *FlexTemp) FahrenheitInt64() int64 {
	return int64(f.Fahrenheit())
}

func (f *FlexTemp) String() string {
	return f.Txt
}

func (f *FlexTemp) Add(o *FlexTemp) {
	f.Val += o.Val
	f.Txt = strconv.FormatFloat(f.Val, 'f', -1, 64)
}

func (f *FlexTemp) AddFloat64(v float64) {
	f.Val += v
	f.Txt = strconv.FormatFloat(f.Val, 'f', -1, 64)
}

// Fake implements gofakeit Fake interface
func (f FlexTemp) Fake(faker *gofakeit.Faker) interface{} {
	randValue := math.Min(math.Max(0.1, math.Abs(faker.Rand.Float64())), 120)
	if faker.Rand.Intn(2) == 0 {
		// int-value
		return FlexTemp{
			Val: float64(int64(randValue)),
			Txt: strconv.FormatInt(int64(randValue), 10) + " C",
		}
	}

	return FlexTemp{
		Val: randValue,
		Txt: strconv.FormatFloat(randValue, 'f', 8, 64) + " C",
	}
}

// DownlinkTable is part of a UXG and UDM output.
type DownlinkTable struct {
	PortIdx    FlexInt  `json:"port_idx"`
	Speed      FlexInt  `json:"speed"`
	FullDuplex FlexBool `json:"full_duplex"`
	Mac        string   `fake:"{macaddress}" json:"mac"`
}

// ConfigNetwork comes from gateways.
type ConfigNetwork struct {
	Type string `fake:"{randomstring:[wan,lan,vlan]}" json:"type"`
	IP   string `fake:"{ipv4address}"                 json:"ip"`
}

type EthernetTable struct {
	Mac     string  `fake:"{macaddress}" json:"mac"`
	NumPort FlexInt `json:"num_port"`
	Name    string  `fake:"{animal}"     json:"name"`
}

// Port is a physical connection on a USW or Gateway.
// Not every port has the same capabilities.
type Port struct {
	AggregatedBy       FlexBool   `json:"aggregated_by"`
	Autoneg            FlexBool   `json:"autoneg,omitempty"`
	BytesR             FlexInt    `json:"bytes-r"`
	DNS                []string   `fakesize:"5"                                                    json:"dns,omitempty"`
	Dot1XMode          string     `json:"dot1x_mode"`
	Dot1XStatus        string     `json:"dot1x_status"`
	Enable             FlexBool   `json:"enable"`
	FlowctrlRx         FlexBool   `json:"flowctrl_rx"`
	FlowctrlTx         FlexBool   `json:"flowctrl_tx"`
	FullDuplex         FlexBool   `json:"full_duplex"`
	IP                 string     `fake:"{ipv4address}"                                            json:"ip,omitempty"`
	Ifname             string     `fake:"{randomstring:[wlan0,wlan1,lan0,lan1,vlan1,vlan0,vlan2]}" json:"ifname,omitempty"`
	IsUplink           FlexBool   `json:"is_uplink"`
	Mac                string     `fake:"{macaddress}"                                             json:"mac,omitempty"`
	MacTable           []MacTable `fakesize:"5"                                                    json:"mac_table,omitempty"`
	Jumbo              FlexBool   `json:"jumbo,omitempty"`
	Masked             FlexBool   `json:"masked"`
	Media              string     `json:"media"`
	Name               string     `fake:"{animal}"                                                 json:"name"`
	NetworkName        string     `fake:"{animal}"                                                 json:"network_name,omitempty"`
	Netmask            string     `json:"netmask,omitempty"`
	NumPort            FlexInt    `json:"num_port,omitempty"`
	OpMode             string     `json:"op_mode"`
	PoeCaps            FlexInt    `json:"poe_caps"`
	PoeClass           string     `json:"poe_class,omitempty"`
	PoeCurrent         FlexInt    `json:"poe_current,omitempty"`
	PoeEnable          FlexBool   `json:"poe_enable,omitempty"`
	PoeGood            FlexBool   `json:"poe_good,omitempty"`
	PoeMode            string     `json:"poe_mode,omitempty"`
	PoePower           FlexInt    `json:"poe_power,omitempty"`
	PoeVoltage         FlexInt    `json:"poe_voltage,omitempty"`
	PortDelta          PortDelta  `json:"port_delta,omitempty"`
	PortIdx            FlexInt    `json:"port_idx"`
	PortPoe            FlexBool   `fake:"{constFlexBool:true}"                                     json:"port_poe"`
	PortconfID         string     `json:"portconf_id"`
	RxBroadcast        FlexInt    `json:"rx_broadcast"`
	RxBytes            FlexInt    `json:"rx_bytes"`
	RxBytesR           FlexInt    `json:"rx_bytes-r"`
	RxDropped          FlexInt    `json:"rx_dropped"`
	RxErrors           FlexInt    `json:"rx_errors"`
	RxMulticast        FlexInt    `json:"rx_multicast"`
	RxPackets          FlexInt    `json:"rx_packets"`
	RxRate             FlexInt    `json:"rx_rate,omitempty"`
	Satisfaction       FlexInt    `json:"satisfaction,omitempty"`
	SatisfactionReason FlexInt    `json:"satisfaction_reason"`
	SFPCompliance      string     `json:"sfp_compliance"`
	SFPCurrent         FlexInt    `json:"sfp_current"`
	SFPFound           FlexBool   `fake:"{constFlexBool:true}"                                     json:"sfp_found"`
	SFPPart            string     `json:"sfp_part"`
	SFPRev             string     `json:"sfp_rev"`
	SFPRxfault         FlexBool   `json:"sfp_rxfault"`
	SFPRxpower         FlexInt    `json:"sfp_rxpower"`
	SFPSerial          string     `json:"sfp_serial"`
	SFPTemperature     FlexInt    `json:"sfp_temperature"`
	SFPTxfault         FlexBool   `json:"sfp_txfault"`
	SFPTxpower         FlexInt    `json:"sfp_txpower"`
	SFPVendor          string     `json:"sfp_vendor"`
	SFPVoltage         FlexInt    `json:"sfp_voltage"`
	Speed              FlexInt    `json:"speed"`
	SpeedCaps          FlexInt    `json:"speed_caps"`
	StpPathcost        FlexInt    `json:"stp_pathcost"`
	StpState           string     `json:"stp_state"`
	TxBroadcast        FlexInt    `json:"tx_broadcast"`
	TxBytes            FlexInt    `json:"tx_bytes"`
	TxBytesR           FlexInt    `json:"tx_bytes-r"`
	TxDropped          FlexInt    `json:"tx_dropped"`
	TxErrors           FlexInt    `json:"tx_errors"`
	TxMulticast        FlexInt    `json:"tx_multicast"`
	TxPackets          FlexInt    `json:"tx_packets"`
	TxRate             FlexInt    `json:"tx_rate,omitempty"`
	Type               string     `json:"type,omitempty"`
	Up                 FlexBool   `json:"up"`
}

type Camera struct {
	IsDeleting                bool   `json:"isDeleting"`
	Mac                       string `json:"mac"`
	Host                      string `json:"host"`
	ConnectionHost            any    `json:"connectionHost"`
	Type                      string `json:"type"`
	Sysid                     any    `json:"sysid"`
	Name                      string `json:"name"`
	UpSince                   any    `json:"upSince"`
	Uptime                    any    `json:"uptime"`
	LastSeen                  int64  `json:"lastSeen"`
	ConnectedSince            any    `json:"connectedSince"`
	State                     string `json:"state"`
	LastDisconnect            any    `json:"lastDisconnect"`
	HardwareRevision          any    `json:"hardwareRevision"`
	FirmwareVersion           any    `json:"firmwareVersion"`
	LatestFirmwareVersion     any    `json:"latestFirmwareVersion"`
	FirmwareBuild             any    `json:"firmwareBuild"`
	IsUpdating                bool   `json:"isUpdating"`
	IsDownloadingFW           bool   `json:"isDownloadingFW"`
	FwUpdateState             string `json:"fwUpdateState"`
	IsAdopting                bool   `json:"isAdopting"`
	IsRestoring               bool   `json:"isRestoring"`
	IsAdopted                 bool   `json:"isAdopted"`
	IsAdoptedByOther          bool   `json:"isAdoptedByOther"`
	IsProvisioned             bool   `json:"isProvisioned"`
	IsRebooting               bool   `json:"isRebooting"`
	IsSSHEnabled              bool   `json:"isSshEnabled"`
	CanAdopt                  bool   `json:"canAdopt"`
	IsAttemptingToConnect     bool   `json:"isAttemptingToConnect"`
	UplinkDevice              any    `json:"uplinkDevice"`
	GUID                      any    `json:"guid"`
	AnonymousDeviceID         any    `json:"anonymousDeviceId"`
	LastMotion                any    `json:"lastMotion"`
	MicVolume                 int    `json:"micVolume"`
	IsMicEnabled              bool   `json:"isMicEnabled"`
	IsRecording               bool   `json:"isRecording"`
	IsWirelessUplinkEnabled   bool   `json:"isWirelessUplinkEnabled"`
	IsMotionDetected          bool   `json:"isMotionDetected"`
	IsSmartDetected           bool   `json:"isSmartDetected"`
	PhyRate                   any    `json:"phyRate"`
	HdrMode                   bool   `json:"hdrMode"`
	VideoMode                 string `json:"videoMode"`
	IsProbingForWifi          bool   `json:"isProbingForWifi"`
	ApMac                     any    `json:"apMac"`
	ApRssi                    any    `json:"apRssi"`
	ApMgmtIP                  any    `json:"apMgmtIp"`
	ElementInfo               any    `json:"elementInfo"`
	ChimeDuration             int    `json:"chimeDuration"`
	IsDark                    bool   `json:"isDark"`
	LastPrivacyZonePositionID any    `json:"lastPrivacyZonePositionId"`
	LastRing                  any    `json:"lastRing"`
	IsLiveHeatmapEnabled      bool   `json:"isLiveHeatmapEnabled"`
	EventStats                struct {
		Motion struct {
			Today       int   `json:"today"`
			Average     int   `json:"average"`
			LastDays    []int `json:"lastDays"`
			RecentHours []int `json:"recentHours"`
		} `json:"motion"`
		Smart struct {
			Today    int   `json:"today"`
			Average  int   `json:"average"`
			LastDays []int `json:"lastDays"`
		} `json:"smart"`
	} `json:"eventStats"`
	VideoReconfigurationInProgress bool   `json:"videoReconfigurationInProgress"`
	Voltage                        any    `json:"voltage"`
	ActivePatrolSlot               any    `json:"activePatrolSlot"`
	UseGlobal                      bool   `json:"useGlobal"`
	HubMac                         any    `json:"hubMac"`
	IsPoorNetwork                  bool   `json:"isPoorNetwork"`
	StopStreamLevel                any    `json:"stopStreamLevel"`
	DownScaleMode                  int    `json:"downScaleMode"`
	IsExtenderInstalledEver        bool   `json:"isExtenderInstalledEver"`
	IsWaterproofCaseAttached       bool   `json:"isWaterproofCaseAttached"`
	UserConfiguredAp               bool   `json:"userConfiguredAp"`
	HasRecordings                  bool   `json:"hasRecordings"`
	VideoCodec                     string `json:"videoCodec"`
	VideoCodecState                int    `json:"videoCodecState"`
	VideoCodecSwitchingSince       any    `json:"videoCodecSwitchingSince"`
	EnableNfc                      bool   `json:"enableNfc"`
	IsThirdPartyCamera             bool   `json:"isThirdPartyCamera"`
	StreamingChannels              []int  `json:"streamingChannels"`
	WiredConnectionState           struct {
		PhyRate any `json:"phyRate"`
	} `json:"wiredConnectionState"`
	WifiConnectionState struct {
		Channel        any `json:"channel"`
		Frequency      any `json:"frequency"`
		PhyRate        any `json:"phyRate"`
		TxRate         any `json:"txRate"`
		SignalQuality  any `json:"signalQuality"`
		Ssid           any `json:"ssid"`
		Bssid          any `json:"bssid"`
		ApName         any `json:"apName"`
		Experience     any `json:"experience"`
		SignalStrength any `json:"signalStrength"`
		Connectivity   any `json:"connectivity"`
	} `json:"wifiConnectionState"`
	Channels []struct {
		ID                       int    `json:"id"`
		VideoID                  string `json:"videoId"`
		Name                     string `json:"name"`
		Enabled                  bool   `json:"enabled"`
		IsRtspEnabled            bool   `json:"isRtspEnabled"`
		RtspAlias                string `json:"rtspAlias"`
		Width                    int    `json:"width"`
		Height                   int    `json:"height"`
		Fps                      int    `json:"fps"`
		Bitrate                  int64  `json:"bitrate"`
		MinBitrate               any    `json:"minBitrate"`
		MaxBitrate               any    `json:"maxBitrate"`
		MinClientAdaptiveBitRate any    `json:"minClientAdaptiveBitRate"`
		MinMotionAdaptiveBitRate any    `json:"minMotionAdaptiveBitRate"`
		FpsValues                []int  `json:"fpsValues"`
		IdrInterval              int    `json:"idrInterval"`
		AutoFps                  bool   `json:"autoFps"`
		AutoBitrate              bool   `json:"autoBitrate"`
	} `json:"channels"`
	IspSettings struct {
		AeMode                         string `json:"aeMode"`
		IrLedMode                      string `json:"irLedMode"`
		IrLedLevel                     int    `json:"irLedLevel"`
		Wdr                            int    `json:"wdr"`
		IcrSensitivity                 int    `json:"icrSensitivity"`
		IcrSwitchMode                  string `json:"icrSwitchMode"`
		IcrCustomValue                 int    `json:"icrCustomValue"`
		Brightness                     int    `json:"brightness"`
		Contrast                       int    `json:"contrast"`
		Hue                            int    `json:"hue"`
		Saturation                     int    `json:"saturation"`
		Sharpness                      int    `json:"sharpness"`
		Denoise                        int    `json:"denoise"`
		IsColorNightVisionEnabled      bool   `json:"isColorNightVisionEnabled"`
		SpotlightDuration              int    `json:"spotlightDuration"`
		IsFlippedVertical              bool   `json:"isFlippedVertical"`
		IsFlippedHorizontal            bool   `json:"isFlippedHorizontal"`
		IsAutoRotateEnabled            bool   `json:"isAutoRotateEnabled"`
		IsLdcEnabled                   bool   `json:"isLdcEnabled"`
		Is3DnrEnabled                  bool   `json:"is3dnrEnabled"`
		IsExternalIrEnabled            bool   `json:"isExternalIrEnabled"`
		IsAggressiveAntiFlickerEnabled bool   `json:"isAggressiveAntiFlickerEnabled"`
		IsPauseMotionEnabled           bool   `json:"isPauseMotionEnabled"`
		DZoomCenterX                   int    `json:"dZoomCenterX"`
		DZoomCenterY                   int    `json:"dZoomCenterY"`
		DZoomScale                     int    `json:"dZoomScale"`
		DZoomStreamID                  int    `json:"dZoomStreamId"`
		FocusPosition                  int    `json:"focusPosition"`
		TouchFocusX                    any    `json:"touchFocusX"`
		TouchFocusY                    any    `json:"touchFocusY"`
		ZoomPosition                   int    `json:"zoomPosition"`
		MountPosition                  any    `json:"mountPosition"`
		HdrMode                        string `json:"hdrMode"`
	} `json:"ispSettings"`
	AudioSettings struct {
		Style []string `json:"style"`
	} `json:"audioSettings"`
	TalkbackSettings struct {
		TypeFmt       string `json:"typeFmt"`
		TypeIn        string `json:"typeIn"`
		BindAddr      string `json:"bindAddr"`
		BindPort      int    `json:"bindPort"`
		FilterAddr    any    `json:"filterAddr"`
		FilterPort    any    `json:"filterPort"`
		Channels      int    `json:"channels"`
		SamplingRate  int    `json:"samplingRate"`
		BitsPerSample int    `json:"bitsPerSample"`
		Quality       int    `json:"quality"`
	} `json:"talkbackSettings"`
	OsdSettings struct {
		IsNameEnabled  bool `json:"isNameEnabled"`
		IsDateEnabled  bool `json:"isDateEnabled"`
		IsLogoEnabled  bool `json:"isLogoEnabled"`
		IsDebugEnabled bool `json:"isDebugEnabled"`
	} `json:"osdSettings"`
	LedSettings struct {
		IsEnabled bool `json:"isEnabled"`
		BlinkRate int  `json:"blinkRate"`
	} `json:"ledSettings"`
	SpeakerSettings struct {
		IsEnabled              bool `json:"isEnabled"`
		AreSystemSoundsEnabled bool `json:"areSystemSoundsEnabled"`
		Volume                 int  `json:"volume"`
	} `json:"speakerSettings"`
	RecordingSettings struct {
		PrePaddingSecs             int    `json:"prePaddingSecs"`
		PostPaddingSecs            int    `json:"postPaddingSecs"`
		SmartDetectPrePaddingSecs  int    `json:"smartDetectPrePaddingSecs"`
		SmartDetectPostPaddingSecs int    `json:"smartDetectPostPaddingSecs"`
		MinMotionEventTrigger      int    `json:"minMotionEventTrigger"`
		EndMotionEventDelay        int    `json:"endMotionEventDelay"`
		SuppressIlluminationSurge  bool   `json:"suppressIlluminationSurge"`
		Mode                       string `json:"mode"`
		InScheduleMode             string `json:"inScheduleMode"`
		OutScheduleMode            string `json:"outScheduleMode"`
		Geofencing                 string `json:"geofencing"`
		MotionAlgorithm            string `json:"motionAlgorithm"`
		EnableMotionDetection      bool   `json:"enableMotionDetection"`
		UseNewMotionAlgorithm      bool   `json:"useNewMotionAlgorithm"`
	} `json:"recordingSettings"`
	SmartDetectSettings struct {
		ObjectTypes             []any `json:"objectTypes"`
		AutoTrackingObjectTypes []any `json:"autoTrackingObjectTypes"`
		AudioTypes              []any `json:"audioTypes"`
		DetectionRange          struct {
			Max any `json:"max"`
			Min any `json:"min"`
		} `json:"detectionRange"`
	} `json:"smartDetectSettings"`
	RecordingSchedulesV2 []any `json:"recordingSchedulesV2"`
	MotionZones          []any `json:"motionZones"`
	PrivacyZones         []any `json:"privacyZones"`
	SmartDetectZones     []any `json:"smartDetectZones"`
	SmartDetectLines     []any `json:"smartDetectLines"`
	Stats                struct {
		RxBytes int `json:"rxBytes"`
		TxBytes int `json:"txBytes"`
		Wifi    struct {
			Channel        any `json:"channel"`
			Frequency      any `json:"frequency"`
			LinkSpeedMbps  any `json:"linkSpeedMbps"`
			SignalQuality  int `json:"signalQuality"`
			SignalStrength int `json:"signalStrength"`
		} `json:"wifi"`
		Video struct {
			RecordingStart   int64 `json:"recordingStart"`
			RecordingEnd     int64 `json:"recordingEnd"`
			RecordingStartLQ any   `json:"recordingStartLQ"`
			RecordingEndLQ   any   `json:"recordingEndLQ"`
			TimelapseStart   any   `json:"timelapseStart"`
			TimelapseEnd     any   `json:"timelapseEnd"`
			TimelapseStartLQ any   `json:"timelapseStartLQ"`
			TimelapseEndLQ   any   `json:"timelapseEndLQ"`
		} `json:"video"`
		Storage struct {
			Used           any `json:"used"`
			Rate           any `json:"rate"`
			ChannelStorage struct {
				Num0 struct {
					Rotating struct {
						RecordingsSizeBytes       int64 `json:"recordingsSizeBytes"`
						LockedRecordingsSizeBytes int   `json:"lockedRecordingsSizeBytes"`
					} `json:"rotating"`
					Timelapse struct {
						RecordingsSizeBytes       int `json:"recordingsSizeBytes"`
						LockedRecordingsSizeBytes int `json:"lockedRecordingsSizeBytes"`
					} `json:"timelapse"`
				} `json:"0"`
			} `json:"channelStorage"`
		} `json:"storage"`
		WifiQuality  int `json:"wifiQuality"`
		WifiStrength int `json:"wifiStrength"`
	} `json:"stats"`
	FeatureFlags struct {
		CanAdjustIrLedLevel     bool  `json:"canAdjustIrLedLevel"`
		CanMagicZoom            bool  `json:"canMagicZoom"`
		CanOpticalZoom          bool  `json:"canOpticalZoom"`
		CanTouchFocus           bool  `json:"canTouchFocus"`
		HasAccelerometer        bool  `json:"hasAccelerometer"`
		HasVerticalFlip         bool  `json:"hasVerticalFlip"`
		HasAec                  bool  `json:"hasAec"`
		HasBluetooth            bool  `json:"hasBluetooth"`
		HasChime                bool  `json:"hasChime"`
		HasExternalIr           bool  `json:"hasExternalIr"`
		HasIcrSensitivity       bool  `json:"hasIcrSensitivity"`
		HasInfrared             bool  `json:"hasInfrared"`
		HasLdc                  bool  `json:"hasLdc"`
		HasLedIr                bool  `json:"hasLedIr"`
		HasLedStatus            bool  `json:"hasLedStatus"`
		HasLineIn               bool  `json:"hasLineIn"`
		HasMic                  bool  `json:"hasMic"`
		HasPrivacyMask          bool  `json:"hasPrivacyMask"`
		HasRtc                  bool  `json:"hasRtc"`
		HasSdCard               bool  `json:"hasSdCard"`
		HasSpeaker              bool  `json:"hasSpeaker"`
		HasWifi                 bool  `json:"hasWifi"`
		HasHdr                  bool  `json:"hasHdr"`
		HasAutoICROnly          bool  `json:"hasAutoICROnly"`
		VideoModes              []any `json:"videoModes"`
		VideoModeMaxFps         []any `json:"videoModeMaxFps"`
		HasMotionZones          bool  `json:"hasMotionZones"`
		HasLcdScreen            bool  `json:"hasLcdScreen"`
		MountPositions          []any `json:"mountPositions"`
		SmartDetectTypes        []any `json:"smartDetectTypes"`
		SmartDetectAudioTypes   []any `json:"smartDetectAudioTypes"`
		SupportDoorAccessConfig bool  `json:"supportDoorAccessConfig"`
		SupportNfc              bool  `json:"supportNfc"`
		LensType                any   `json:"lensType"`
		LensModel               any   `json:"lensModel"`
		MotionAlgorithms        []any `json:"motionAlgorithms"`
		HasSquareEventThumbnail bool  `json:"hasSquareEventThumbnail"`
		HasPackageCamera        bool  `json:"hasPackageCamera"`
		Audio                   []any `json:"audio"`
		AudioCodecs             []any `json:"audioCodecs"`
		VideoCodecs             []any `json:"videoCodecs"`
		AudioStyle              []any `json:"audioStyle"`
		IsDoorbell              bool  `json:"isDoorbell"`
		IsPtz                   bool  `json:"isPtz"`
		HasColorLcdScreen       bool  `json:"hasColorLcdScreen"`
		HasLiveviewTracking     bool  `json:"hasLiveviewTracking"`
		HasLineCrossing         bool  `json:"hasLineCrossing"`
		HasLineCrossingCounting bool  `json:"hasLineCrossingCounting"`
		HasFlash                bool  `json:"hasFlash"`
		FlashRange              any   `json:"flashRange"`
		HasLuxCheck             bool  `json:"hasLuxCheck"`
		PresetTour              bool  `json:"presetTour"`
		PrivacyMaskCapability   struct {
			MaxMasks      any  `json:"maxMasks"`
			RectangleOnly bool `json:"rectangleOnly"`
		} `json:"privacyMaskCapability"`
		Focus struct {
			Steps struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"steps"`
			Degrees struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"degrees"`
		} `json:"focus"`
		Pan struct {
			Steps struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"steps"`
			Degrees struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"degrees"`
		} `json:"pan"`
		Tilt struct {
			Steps struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"steps"`
			Degrees struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"degrees"`
		} `json:"tilt"`
		Zoom struct {
			Ratio int `json:"ratio"`
			Steps struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"steps"`
			Degrees struct {
				Max  any `json:"max"`
				Min  any `json:"min"`
				Step any `json:"step"`
			} `json:"degrees"`
		} `json:"zoom"`
		Hotplug struct {
			Audio              any  `json:"audio"`
			Video              any  `json:"video"`
			StandaloneAdoption bool `json:"standaloneAdoption"`
			Extender           struct {
				IsAttached    any `json:"isAttached"`
				HasFlash      any `json:"hasFlash"`
				FlashRange    any `json:"flashRange"`
				HasIR         any `json:"hasIR"`
				HasRadar      any `json:"hasRadar"`
				RadarRangeMax any `json:"radarRangeMax"`
				RadarRangeMin any `json:"radarRangeMin"`
			} `json:"extender"`
		} `json:"hotplug"`
		HasSmartDetect bool `json:"hasSmartDetect"`
	} `json:"featureFlags"`
	TiltLimitsOfPrivacyZones struct {
		Side  string `json:"side"`
		Limit int    `json:"limit"`
	} `json:"tiltLimitsOfPrivacyZones"`
	LcdMessage struct {
	} `json:"lcdMessage"`
	Lenses        []any `json:"lenses"`
	StreamSharing struct {
		Enabled        bool `json:"enabled"`
		Token          any  `json:"token"`
		ShareLink      any  `json:"shareLink"`
		Expires        any  `json:"expires"`
		SharedByUserID any  `json:"sharedByUserId"`
		SharedByUser   any  `json:"sharedByUser"`
		MaxStreams     any  `json:"maxStreams"`
	} `json:"streamSharing"`
	HomekitSettings struct {
		TalkbackSettingsActive bool `json:"talkbackSettingsActive"`
		StreamInProgress       bool `json:"streamInProgress"`
		MicrophoneMuted        bool `json:"microphoneMuted"`
		SpeakerMuted           bool `json:"speakerMuted"`
	} `json:"homekitSettings"`
	Shortcuts []any `json:"shortcuts"`
	Alarms    struct {
		LensThermal                         int   `json:"lensThermal"`
		TiltThermal                         int   `json:"tiltThermal"`
		PanTiltMotorFaults                  []any `json:"panTiltMotorFaults"`
		AutoTrackingThermalThresholdReached bool  `json:"autoTrackingThermalThresholdReached"`
		LensThermalThresholdReached         bool  `json:"lensThermalThresholdReached"`
		MotorOverheated                     bool  `json:"motorOverheated"`
	} `json:"alarms"`
	ExtendedAiFeatures struct {
		SmartDetectTypes []any `json:"smartDetectTypes"`
	} `json:"extendedAiFeatures"`
	ThirdPartyCameraInfo struct {
		Port        FlexInt `json:"port"`
		RtspURL     string  `json:"rtspUrl"`
		RtspURLLQ   any     `json:"rtspUrlLQ"`
		SnapshotURL string  `json:"snapshotUrl"`
	} `json:"thirdPartyCameraInfo"`
	ID                          string   `json:"id"`
	NvrMac                      string   `json:"nvrMac"`
	DisplayName                 string   `json:"displayName"`
	IsConnected                 bool     `json:"isConnected"`
	Platform                    any      `json:"platform"`
	HasSpeaker                  bool     `json:"hasSpeaker"`
	HasWifi                     bool     `json:"hasWifi"`
	AudioBitrate                int      `json:"audioBitrate"`
	CanManage                   bool     `json:"canManage"`
	IsManaged                   bool     `json:"isManaged"`
	MarketName                  string   `json:"marketName"`
	Is4K                        bool     `json:"is4K"`
	Is2K                        bool     `json:"is2K"`
	CurrentResolution           string   `json:"currentResolution"`
	SupportedScalingResolutions []string `json:"supportedScalingResolutions"`
	ModelKey                    string   `json:"modelKey"`
}
