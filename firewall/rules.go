package firewall

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

func PermitCIDR(session uintptr, baseObjects *baseObjects, weight uint8, network string) error {
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
	conditions[0].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS              // cFWPM_CONDITION_IP_REMOTE_ADDRESS: The remote IP address of the connection.
	conditions[0].matchType = cFWP_MATCH_EQUAL                              // cFWP_MATCH_EQUAL: The match type of the condition.
	conditions[0].conditionValue._type = cFWP_V4_ADDR_MASK                  // cFWP_V4_ADDR_MASK: The data type of the condition value.
	conditions[0].conditionValue.value = uintptr(unsafe.Pointer(&addrMask)) // uintptr(unsafe.Pointer(&addrMask)): The value of the condition.

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
		filterKey:           filterKey,                            // *windows.GUID: A pointer to a GUID that uniquely identifies the filter.
		displayData:         *displayData,                         // *wtFwpmDisplayData0: A pointer to a FWPM_DISPLAY_DATA0 structure that contains the display data for the filter.
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, // Added FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT flag to make the rule an "hard permit" rule (complex to overwrite)
		providerKey:         &baseObjects.provider,                // *windows.GUID: A pointer to a GUID that uniquely identifies the provider.
		layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,      // *windows.GUID: A pointer to a GUID that uniquely identifies the layer.
		subLayerKey:         baseObjects.filters,                  // *windows.GUID: A pointer to a GUID that uniquely identifies the sublayer.
		weight:              filterWeight(weight),                 // wtFwpValue0: The weight of the filter.
		numFilterConditions: uint32(len(conditions)),              // uint32(len(conditions)): The number of conditions in the filter.
		filterCondition:     &conditions[0],                       // *wtFwpmFilterCondition0: A pointer to an array of FWPM_FILTER_CONDITION0 structures that contain the conditions for the filter.
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT, // cFWP_ACTION_PERMIT: The action type of the filter.
		},
	}

	var filterID uint64
	err = fwpmFilterAdd0(session, &filter, 0, &filterID)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}

func BlockCIDR(session uintptr, baseObjects *baseObjects, weight uint8, network string) error {
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
	conditions[0].fieldKey = cFWPM_CONDITION_IP_REMOTE_ADDRESS              // cFWPM_CONDITION_IP_REMOTE_ADDRESS: The remote IP address of the connection.
	conditions[0].matchType = cFWP_MATCH_EQUAL                              // cFWP_MATCH_EQUAL: The match type of the condition.
	conditions[0].conditionValue._type = cFWP_V4_ADDR_MASK                  // cFWP_V4_ADDR_MASK: The data type of the condition value.
	conditions[0].conditionValue.value = uintptr(unsafe.Pointer(&addrMask)) // uintptr(unsafe.Pointer(&addrMask)): The value of the condition.

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
		filterKey:           filterKey,                            // *windows.GUID: A pointer to a GUID that uniquely identifies the filter.
		displayData:         *displayData,                         // *wtFwpmDisplayData0: A pointer to a FWPM_DISPLAY_DATA0 structure that contains the display data for the filter.
		flags:               cFWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, // Added FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT flag to make the rule an "hard permit" rule (complex to overwrite)
		providerKey:         &baseObjects.provider,                // *windows.GUID: A pointer to a GUID that uniquely identifies the provider.
		layerKey:            cFWPM_LAYER_ALE_AUTH_CONNECT_V4,      // *windows.GUID: A pointer to a GUID that uniquely identifies the layer.
		subLayerKey:         baseObjects.filters,                  // *windows.GUID: A pointer to a GUID that uniquely identifies the sublayer.
		weight:              filterWeight(weight),                 // wtFwpValue0: The weight of the filter.
		numFilterConditions: uint32(len(conditions)),              // uint32(len(conditions)): The number of conditions in the filter.
		filterCondition:     &conditions[0],                       // *wtFwpmFilterCondition0: A pointer to an array of FWPM_FILTER_CONDITION0 structures that contain the conditions for the filter.
		action: wtFwpmAction0{
			_type: cFWP_ACTION_BLOCK, // cFWP_ACTION_BLOCK: The action type of the filter.
		},
	}

	var filterID uint64
	err = fwpmFilterAdd0(session, &filter, 0, &filterID)
	if err != nil {
		return wrapErr(err)
	}

	return nil
}
