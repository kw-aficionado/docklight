package panel

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"
)

const assistantDailyDigestInterval = 10 * time.Minute

func (a *App) StartAssistantDigestWorker(ctx context.Context) {
	go func() {
		a.runAssistantDailyDigest(ctx, time.Now())
		ticker := time.NewTicker(assistantDailyDigestInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				a.runAssistantDailyDigest(ctx, now)
			}
		}
	}()
}

func (a *App) runAssistantDailyDigest(ctx context.Context, now time.Time) {
	var enabled, digestEnabled, hour int
	if err := a.db.QueryRow(`SELECT enabled,digest_enabled,digest_hour FROM assistant_config WHERE id=1`).Scan(&enabled, &digestEnabled, &hour); err != nil {
		log.Printf("Docklight daily digest could not read settings")
		return
	}
	if enabled == 0 || digestEnabled == 0 || hour < 0 || hour > 23 || now.Hour() < hour {
		return
	}
	if !a.assistantDailyDigestHasRecipient() {
		return
	}
	runtime, err := a.assistantRuntime()
	if err != nil || !runtime.enabled {
		log.Printf("Docklight daily digest skipped because the configured provider is unavailable")
		return
	}
	if !a.beginAssistantDigest() {
		return
	}
	defer a.endAssistantDigest()

	day := now.Format("2006-01-02")
	result, err := a.db.Exec(`UPDATE assistant_config SET digest_last_day=?,updated_at=CURRENT_TIMESTAMP WHERE id=1 AND enabled=1 AND digest_enabled=1 AND digest_hour=? AND digest_last_day<>?`, day, hour, day)
	if err != nil {
		log.Printf("Docklight daily digest could not reserve today's run")
		return
	}
	claimed, err := result.RowsAffected()
	if err != nil || claimed != 1 {
		return
	}

	snapshot, err := a.assistantHealthData()
	if err != nil {
		a.audit(User{Username: "system"}, "ai.digest_failed", "assistant", "1", "health snapshot unavailable")
		log.Printf("Docklight daily digest could not gather its health snapshot")
		return
	}
	systemPrompt, userPrompt, err := assistantHealthDigestPrompts(snapshot)
	if err != nil {
		if errors.Is(err, errAssistantSnapshotTooLarge) {
			a.audit(User{Username: "system"}, "ai.digest_failed", "assistant", "1", "snapshot too large")
			log.Printf("Docklight daily digest snapshot exceeded its provider limit")
			return
		}
		a.audit(User{Username: "system"}, "ai.digest_failed", "assistant", "1", "snapshot invalid")
		log.Printf("Docklight daily digest snapshot was invalid")
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docklight.invalid/assistant-digest", nil)
	if err != nil {
		return
	}
	answer, err := a.requestAssistantCompletion(request, runtime.provider, runtime.model, runtime.baseURL, runtime.apiKey, systemPrompt, userPrompt, 600)
	if err != nil {
		a.audit(User{Username: "system"}, "ai.digest_failed", "assistant", "1", "provider unavailable")
		log.Printf("Docklight daily digest provider request failed")
		return
	}
	message := assistantLastRunes(answer, 4000)
	a.dispatchWebhookNotification(notificationAssistantDigest, nil, message)
	a.audit(User{Username: "system"}, "ai.digest", "assistant", "1", "scheduled_daily")
}

func (a *App) assistantDailyDigestHasRecipient() bool {
	var enabled int
	var endpoint, eventsJSON string
	if err := a.db.QueryRow(`SELECT enabled,endpoint_enc,events_json FROM notification_settings WHERE id=1`).Scan(&enabled, &endpoint, &eventsJSON); err == nil && enabled != 0 && endpoint != "" {
		var events []string
		if json.Unmarshal([]byte(eventsJSON), &events) == nil && containsString(events, notificationAssistantDigest) {
			return true
		}
	}
	var channels int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM notification_channels WHERE enabled=1 AND server_id=''`).Scan(&channels); err == nil && channels > 0 {
		return true
	}
	return false
}
