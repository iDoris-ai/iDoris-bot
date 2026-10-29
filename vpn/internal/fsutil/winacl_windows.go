//go:build windows

package fsutil

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	windowsDACLReader = windowsACLReader{}
}

type windowsACLReader struct{}

func (windowsACLReader) ReadACL(path string) (ACLView, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ACLView{}, err
	}
	if sd == nil {
		return ACLView{}, errors.New("fsutil: security descriptor is missing")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return ACLView{}, err
	}
	if owner == nil {
		return ACLView{}, errors.New("fsutil: owner SID is missing")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return ACLView{}, err
	}
	// A nil DACL grants everyone. Treat that as unreadable rather than empty.
	if dacl == nil {
		return ACLView{}, errors.New("fsutil: DACL is missing")
	}
	view := ACLView{OwnerSID: owner.String()}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return ACLView{}, err
		}
		if ace == nil {
			return ACLView{}, errors.New("fsutil: ACE is missing")
		}
		inherited := ace.Header.AceFlags&windows.INHERITED_ACE != 0
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid, err := aceSID(ace)
			if err != nil {
				return ACLView{}, err
			}
			view.ACEs = append(view.ACEs, ACE{SID: sid, Inherited: inherited})
		case windows.ACCESS_DENIED_ACE_TYPE:
			sid, err := aceSID(ace)
			if err != nil {
				return ACLView{}, err
			}
			view.ACEs = append(view.ACEs, ACE{SID: sid, Inherited: inherited, Deny: true})
		default:
			view.ACEs = append(view.ACEs, ACE{Inherited: inherited, Unrecognized: true})
		}
	}
	return view, nil
}

// aceSID reads the SID at the standard offset of an allow or deny ACE.
// Object ACEs are not passed here: their SID does not start at SidStart.
func aceSID(ace *windows.ACCESS_ALLOWED_ACE) (string, error) {
	// SidStart is the first byte of the SID embedded in the ACE.
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: ACE layout from GetAce
	s := sid.String()
	if s == "" {
		return "", errors.New("fsutil: ACE SID is empty")
	}
	return s, nil
}
