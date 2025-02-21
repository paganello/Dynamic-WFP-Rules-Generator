package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
		displayData, err := createWtFwpmDisplayData0("CustomRouleGenerator", "CustomRouleGenerator provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}

		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("CustomRouleGenerator filters", "Permissive and blocking filters")
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

	// Convert the IP address and Mask to a 4-byte array
	addr := ipNet.Addr().As4()
	mask := net.CIDRMask(ipNet.Bits(), 32) // e.g.: 255.255.255.0 if ipNet.Bits() = 24

	// Convert the IP address and Mask to UINT32
	addrMask := struct {
		addr uint32
		mask uint32
	}{
		addr: binary.BigEndian.Uint32(addr[:]),
		mask: binary.BigEndian.Uint32(mask),
	}

	conditions := make([]wtFwpmFilterCondition0, 1)
	conditions[0].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
	conditions[0].matchType = cFWP_MATCH_EQUAL
	conditions[0].conditionValue._type = cFWP_V4_ADDR_MASK
	conditions[0].conditionValue.value = uintptr(unsafe.Pointer(&addrMask))

	filterKey, err := windows.GenerateGUID()
	if err != nil {
		return wrapErr(err)
	}

	displayName := fmt.Sprintf("Permit traffic to %s", network)
	displayData, err := createWtFwpmDisplayData0(displayName, "")
	if err != nil {
		return wrapErr(err)
	}

	filter := wtFwpmFilter0{
		filterKey:           filterKey,
		displayData:         *displayData,
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, // Added FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT flag to make the rule an "hard permit" rule (complex to overwrite)
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

	var filterID uint64
	err = fwpmFilterAdd0(session, &filter, 0, &filterID)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

func BlockNetwork(session uintptr, baseObjects *baseObjects, weight uint8, network string) error {
	ipNet, err := netip.ParsePrefix(network)
	if err != nil {
		return wrapErr(err)
	}

	// Convert the IP address and Mask to a 4-byte array
	addr := ipNet.Addr().As4()
	mask := net.CIDRMask(ipNet.Bits(), 32) // e.g.: 255.255.255.0 if ipNet.Bits() = 24

	// Convert the IP address and Mask to UINT32
	addrMask := struct {
		addr uint32
		mask uint32
	}{
		addr: binary.BigEndian.Uint32(addr[:]),
		mask: binary.BigEndian.Uint32(mask),
	}

	conditions := make([]wtFwpmFilterCondition0, 1)
	conditions[0].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS
	conditions[0].matchType = cFWP_MATCH_EQUAL
	conditions[0].conditionValue._type = cFWP_V4_ADDR_MASK
	conditions[0].conditionValue.value = uintptr(unsafe.Pointer(&addrMask))

	filterKey, err := windows.GenerateGUID()
	if err != nil {
		return wrapErr(err)
	}

	displayName := fmt.Sprintf("Block traffic to %s", network)
	displayData, err := createWtFwpmDisplayData0(displayName, "")
	if err != nil {
		return wrapErr(err)
	}

	filter := wtFwpmFilter0{
		filterKey:           filterKey,
		displayData:         *displayData,
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, // Added FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT flag to make the rule an "hard permit" rule (complex to overwrite)
		providerKey:         &baseObjects.provider,
		layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions)),
		filterCondition:     &conditions[0],
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK,
		},
	}

	var filterID uint64
	err = fwpmFilterAdd0(session, &filter, 0, &filterID)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

/*
func ipNetMaskToUint32(ipNet netip.Prefix) uint32 {
	ones := ipNet.Bits()
	if ones == 0 {
		return 0
	}
	return binary.BigEndian.Uint32(net.CIDRMask(ones, 32))
}
*/

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

/*
func checkWindowsError(err error) error {
	if err != nil && err != windows.ERROR_SUCCESS {
		return err
	}
	return nil
}
*/

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}
