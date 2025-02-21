package firewall

import (
	"fmt"
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
