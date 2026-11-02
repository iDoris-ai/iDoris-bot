package vpnd

import "errors"

// CheckSecretFile reports whether path is a regular file owned by the current
// user and unreadable by group and other. The error text always contains
// "chmod 600" so an operator can copy the fix. On Windows the check is a
// warning only and the function returns nil: NTFS ACLs are not modelled here.
// service install calls this before it accepts a token file or a config that
// holds an inline secret.
func CheckSecretFile(path string) error {
	if path == "" {
		return errors.New("secret file path is empty")
	}
	return checkSecretFile(path)
}
