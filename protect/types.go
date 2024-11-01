// nolint: revive
package protect

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/brianvoe/gofakeit/v6"
)

var (
	ErrCannotUnmarshalFlexInt = fmt.Errorf("cannot unmarshal to FlexInt")
)

// This is a list of unifi API paths.
// The %s in each string must be replaced with a Site.Name.
const (
	// APIStatusPath shows Controller version.
	APIStatusPath string = "/status"
	// APILoginPath is Unifi Controller Login API Path
	APILoginPath string = "/api/login"
	// APILoginPathNew is how we log into UDM 5.12.55+.
	APILoginPathNew string = "/api/auth/login"
	// APILogoutPath is how we logout from UDM.
	APILogoutPath string = "/api/logout"
	// APIPrefixNew is the prefix added to the new API paths; except login. duh.
	APIPrefixNew string = "/proxy/protect"
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
	// Login is a helper method. It can be called to grab a new authentication cookie.
	Login() error
	// Logout closes the current session.
	Logout() error
}

// Unifi is what you get in return for providing a password! Unifi represents
// a controller that you can make authenticated requests to. Use this to make
// additional requests for devices, clients or other custom data. Do not set
// the loggers to nil. Set them to DiscardLogs if you want no logs.
type Unifi struct {
	*http.Client
	*Config
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
