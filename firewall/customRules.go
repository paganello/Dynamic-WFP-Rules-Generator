package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Definizione della struttura SEC_WINNT_AUTH_IDENTITY_W per sostituire windows.AuthIdentity
type SecWinNTAuthIdentityW struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

type wfpObjectInstaller func(uintptr) error

type wtFwpmConditionValue0 struct {
	_type uint32
	value uintptr
}

type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var wfpSession uintptr

func CreateWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("CustomWireGuardSession", "Custom WireGuard dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func RegisterBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	bo.provider, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	bo.filters, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("WireShield", "custom WireGuard provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}

		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			// TODO: cleanup entire call chain of these if failure?
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Wireshield filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

func PermitNetwork(session uintptr, baseObjects *baseObjects, weight uint8, network string) error {
	ipNet, err := netip.ParsePrefix(network)
	if err != nil {
		return wrapErr(err)
	}

	// Convertire l'indirizzo IP e la maschera in formato uint32
	addr := ipNet.Addr().As4()
	mask := ipNetMaskToUint32(ipNet)

	addrMask := struct {
		addr uint32
		mask uint32
	}{
		addr: binary.BigEndian.Uint32(addr[:]),
		mask: mask,
	}

	fmt.Println(uintptr(unsafe.Pointer(&addrMask)))

	conditions := make([]wtFwpmFilterCondition0, 1)
	conditions[0].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
	conditions[0].matchType = cFWP_MATCH_EQUAL
	conditions[0].conditionValue._type = cFWP_V4_ADDR_MASK
	conditions[0].conditionValue.value = uintptr(unsafe.Pointer(&addrMask))

	filterKey, err := windows.GenerateGUID()
	if err != nil {
		return wrapErr(err)
	}

	displayData, err := createWtFwpmDisplayData0("Permit traffic to 10.0.0.0/24", "")
	if err != nil {
		return wrapErr(err)
	}

	filter := wtFwpmFilter0{
		filterKey:           filterKey,
		displayData:         *displayData,
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, //Aggiunto il flag FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT per fare in modo che la regola sia un "hard permit" e quindi più difficile da sovrascrivere
		providerKey:         &baseObjects.provider,
		layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     &conditions[0],
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}

	fmt.Println(filterKey)

	var filterID uint64
	err = fwpmFilterAdd0(session, &filter, 0, &filterID)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

// Funzione helper per convertire la netmask in uint32
func ipNetMaskToUint32(ipNet netip.Prefix) uint32 {
	ones := ipNet.Bits()
	if ones == 0 {
		return 0
	}
	// Crea la maschera in network byte order
	return binary.BigEndian.Uint32(net.CIDRMask(ones, 32))
}

func wrapErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("WFP operation failed: %w", err)
}

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	return &wtFwpmDisplayData0{
		name:        windows.StringToUTF16Ptr(name),
		description: windows.StringToUTF16Ptr(description),
	}, nil
}

// Funzione helper per controllare gli errori di Windows
func checkWindowsError(err error) error {
	if err != nil && err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}
