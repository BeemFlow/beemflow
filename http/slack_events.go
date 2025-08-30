package http

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "math"
    "net/http"
    "os"
    "strconv"
    "time"

    api "github.com/awantoch/beemflow/core"
    "github.com/awantoch/beemflow/utils"
)

// SlackEventsHandler returns an http.HandlerFunc that verifies Slack signatures
// and publishes relevant message events onto the BeemFlow event bus.
//
//   • Route: /slack/events (POST)
//   • Env required: SLACK_SIGNING_SECRET
func SlackEventsHandler() http.HandlerFunc {
    signingSecret := os.Getenv("SLACK_SIGNING_SECRET")
    if signingSecret == "" {
        utils.Warn("SLACK_SIGNING_SECRET not set – Slack signature verification disabled (NOT RECOMMENDED)")
    }

    return func(w http.ResponseWriter, r *http.Request) {
        bodyBytes, err := io.ReadAll(r.Body)
        if err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        r.Body.Close()

        // Slack URL-verification challenge (sent during app setup)
        var challenge struct {
            Type      string `json:"type"`
            Challenge string `json:"challenge"`
        }
        if err := json.Unmarshal(bodyBytes, &challenge); err == nil && challenge.Type == "url_verification" {
            w.Header().Set("Content-Type", "text/plain")
            w.Write([]byte(challenge.Challenge))
            return
        }

        // Signature verification (skip if secret missing – dev mode)
        if signingSecret != "" && !verifySlackSignature(signingSecret, r.Header, bodyBytes) {
            utils.Warn("invalid slack signature")
            http.Error(w, "invalid signature", http.StatusUnauthorized)
            return
        }

        // Parse event using slack-go types for convenience
        var evt slackeventsEnvelope
        if err := json.Unmarshal(bodyBytes, &evt); err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }
        if evt.Type != "event_callback" {
            // Ignore
            w.WriteHeader(http.StatusOK)
            return
        }

        // Only interested in message & app_mention events
        var inner slackeventsInnerEvent
        if err := json.Unmarshal(evt.Event, &inner); err != nil {
            w.WriteHeader(http.StatusOK)
            return
        }
        if inner.Type != "message" && inner.Type != "app_mention" {
            w.WriteHeader(http.StatusOK)
            return
        }

        token := inner.ThreadTs
        if token == "" {
            token = inner.Ts
        }

        beemPayload := map[string]any{
            "source":    "slack",
            "user":      inner.User,
            "channel":   inner.Channel,
            "text":      inner.Text,
            "timestamp": inner.Ts,
            "thread_ts": inner.ThreadTs,
            "token":     token, // critical for await_event matching
        }

        // Publish to BeemFlow event bus (topic slack.message)
        if err := api.PublishEvent(r.Context(), "slack.message", beemPayload); err != nil {
            utils.Error("failed to publish slack event: %v", err)
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }

        w.WriteHeader(http.StatusOK)
    }
}

// verifySlackSignature checks the X-Slack-Signature header.
func verifySlackSignature(secret string, hdr http.Header, body []byte) bool {
    sig := hdr.Get("X-Slack-Signature")
    timestamp := hdr.Get("X-Slack-Request-Timestamp")
    if sig == "" || timestamp == "" {
        return false
    }
    // Reject if timestamp is too old (5 min)
    ts, err := strconv.ParseInt(timestamp, 10, 64)
    if err != nil {
        return false
    }
    if math.Abs(float64(time.Now().Unix()-ts)) > 60*5 {
        return false
    }

    base := fmt.Sprintf("v0:%s:%s", timestamp, string(body))
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(base))
    expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(sig))
}

// Minimal envelope structs to avoid pulling in slack/eventsapi package
// (keeps deps small & avoids introducing another sub-module).

type slackeventsEnvelope struct {
    Type string          `json:"type"`
    Event json.RawMessage `json:"event"`
}

type slackeventsInnerEvent struct {
    Type     string `json:"type"`
    User     string `json:"user"`
    Text     string `json:"text"`
    Channel  string `json:"channel"`
    Ts       string `json:"ts"`
    ThreadTs string `json:"thread_ts"`
}