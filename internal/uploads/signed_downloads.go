package uploads

import (
	"fmt"
	"strconv"
	"time"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(key [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil || expires <= now.Unix() {
		return false
	}
	expectedSignature, err := hex.DecodeString(signDownload(key, fileID, expires))
	if err != nil {
		return false
	}
	providedSignature, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(expectedSignature, providedSignature) != 1
}

func signDownload(key [32]byte, fileID, expires int64) string {
	mac := hmac.New(sha256.New, key[:])
	fmt.Fprintf(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	return hex.EncodeToString(mac.Sum(nil))
}
