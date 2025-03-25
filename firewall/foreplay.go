package firewall

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
 * Responsible for creating a new Windows Filtering Platform (WFP) session.
 */
func CreateWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("Custom WFP Rules Generator", "Custom WFP Rules Generator - dynamic session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,        // *wtFwpmDisplayData0: A pointer to a FWPM_DISPLAY_DATA0 structure that contains the display data for the session.
		flags:                cFWPM_SESSION_FLAG_DYNAMIC, // cFWPM_SESSION_FLAG_DYNAMIC: The session is dynamic and will be automatically deleted when the session handle is closed.
		txnWaitTimeoutInMSec: windows.INFINITE,           // windows.INFINITE: The wait time is infinite.
	}

	sessionHandle := uintptr(0)

	// fwpmEngineOpen0: Opens a session with the filter engine.
	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func RegisterBaseObjects(session uintptr) (*baseObjects, error) {

	//
	// Initilize BaseObject structure
	//
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
		displayData, err := createWtFwpmDisplayData0("Custom WFP Rules Generator", "Custom WFP Rules Generator - provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,  // *windows.GUID: A pointer to a GUID that uniquely identifies the provider.
			displayData: *displayData, // *wtFwpmDisplayData0: A pointer to a FWPM_DISPLAY_DATA0 structure that contains the display data for the provider.
		}

		// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovideradd0
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("Custom WFP Rules Generator", "Custom WFP Rules Generator - Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,   // *windows.GUID: A pointer to a GUID that uniquely identifies the sublayer.
			displayData: *displayData, // *wtFwpmDisplayData0: A pointer to a FWPM_DISPLAY_DATA0 structure that contains the display data for the sublayer.
			providerKey: &bo.provider, // *windows.GUID: A pointer to a GUID that uniquely identifies the provider.
			weight:      ^uint16(0),   // ^uint16(0): The weight of the sublayer.
		}

		// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayeradd0
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
		name:        windows.StringToUTF16Ptr(name),        // windows.StringToUTF16Ptr(name): A pointer to a null-terminated Unicode string that contains the name of the object.
		description: windows.StringToUTF16Ptr(description), // windows.StringToUTF16Ptr(description): A pointer to a null-terminated Unicode string that contains the description of the object.
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
		_type: cFWP_UINT8,      // cFWP_UINT8: The data type of the value.
		value: uintptr(weight), // uintptr(weight): The value.
	}
}
