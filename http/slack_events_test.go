package http

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "net/http"
    "strconv"
    "testing"
    "time"
)

func TestVerifySlackSignature(t *testing.T) {
    secret := "test-secret"
    body := []byte(`{"type":"event_callback"}`)
    ts := strconv.FormatInt(time.Now().Unix(), 10)
    base := "v0:" + ts + ":" + string(body)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(base))
    expectedSig := "v0=" + hex.EncodeToString(mac.Sum(nil))

    hdr := http.Header{}
    hdr.Set("X-Slack-Request-Timestamp", ts)
    hdr.Set("X-Slack-Signature", expectedSig)

    if !verifySlackSignature(secret, hdr, body) {
        t.Errorf("expected signature to verify")
    }

    hdr.Set("X-Slack-Signature", "v0=bad")
    if verifySlackSignature(secret, hdr, body) {
        t.Errorf("expected signature verification to fail")
    }
}