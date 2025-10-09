package api

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/beemflow/beemflow/model"
	"github.com/beemflow/beemflow/utils"
	"github.com/robfig/cron/v3"
)

const cronMarker = "# BeemFlow managed - do not edit"

// ShellQuote safely quotes a string for use in shell commands
// It escapes single quotes and wraps the string in single quotes
// This prevents shell injection attacks
func ShellQuote(s string) string {
	// Replace single quotes with '\'' (end quote, escaped quote, start quote)
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	// Wrap in single quotes
	return "'" + escaped + "'"
}

// CronManager handles system cron integration
type CronManager struct {
	serverURL  string
	cronSecret string
}

// NewCronManager creates a new cron manager
func NewCronManager(serverURL string, cronSecret string) *CronManager {
	return &CronManager{
		serverURL:  serverURL,
		cronSecret: cronSecret,
	}
}

// SyncCronEntries updates system cron with workflow schedules
func (c *CronManager) SyncCronEntries(ctx context.Context) error {
	// Get all workflows with cron schedules
	flows, err := ListFlows(ctx)
	if err != nil {
		return err
	}

	var entries []string
	for _, flowName := range flows {
		flow, err := GetFlow(ctx, flowName)
		if err != nil {
			continue
		}

		cronExpr := extractCronExpression(&flow)
		if cronExpr != "" {
			// Build curl command with proper escaping to prevent injection
			var curlCmd strings.Builder
			curlCmd.WriteString("curl -sS -X POST")

			// Add authorization header if CRON_SECRET is set
			if c.cronSecret != "" {
				// Properly escape the secret in the header
				curlCmd.WriteString(" -H ")
				curlCmd.WriteString(ShellQuote("Authorization: Bearer " + c.cronSecret))
			}

			// Build URL with proper escaping and URL encoding
			encodedFlowName := url.PathEscape(flowName)
			fullURL := fmt.Sprintf("%s/cron/%s", c.serverURL, encodedFlowName)
			curlCmd.WriteString(" ")
			curlCmd.WriteString(ShellQuote(fullURL))
			curlCmd.WriteString(" >/dev/null 2>&1")

			// Create cron entry with proper spacing
			entry := fmt.Sprintf("%s %s %s", cronExpr, curlCmd.String(), cronMarker)
			entries = append(entries, entry)
		}
	}

	return c.updateSystemCron(entries)
}

// updateSystemCron updates the system crontab
func (c *CronManager) updateSystemCron(newEntries []string) error {
	// Get current crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		// No existing crontab is okay
		output = []byte{}
	}

	// Filter out our managed entries
	var preservedLines []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, cronMarker) {
			preservedLines = append(preservedLines, line)
		}
	}

	// Add new entries
	preservedLines = append(preservedLines, newEntries...)

	// Write back to crontab
	newCron := strings.Join(preservedLines, "\n") + "\n"
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update crontab: %w", err)
	}

	utils.Info("Updated system cron with %d BeemFlow entries", len(newEntries))
	return nil
}

// RemoveAllEntries removes all BeemFlow managed cron entries
func (c *CronManager) RemoveAllEntries() error {
	// Get current crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil // No crontab, nothing to remove
	}

	// Filter out our managed entries
	var preservedLines []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, cronMarker) {
			preservedLines = append(preservedLines, line)
		}
	}

	// Write back
	newCron := strings.Join(preservedLines, "\n") + "\n"
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)

	return cmd.Run()
}

// extractCronExpression gets cron from flow (reuse existing logic)
func extractCronExpression(flow *model.Flow) string {
	if !hasScheduleCronTrigger(flow) || flow.Cron == "" {
		return ""
	}
	return flow.Cron
}

// CheckAndExecuteCronFlows checks all flows for cron schedules and executes those that are due
// This is stateless and relies only on the database
func CheckAndExecuteCronFlows(ctx context.Context) (map[string]interface{}, error) {
	// List all flows
	flows, err := ListFlows(ctx)
	if err != nil {
		return nil, err
	}

	triggered := []string{}
	errors := []string{}
	checked := 0

	// Get current time
	now := time.Now().UTC()

	// Create cron parser - using standard cron format (5 fields)
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

	for _, flowName := range flows {
		flow, err := GetFlow(ctx, flowName)
		if err != nil {
			errors = append(errors, flowName+": "+err.Error())
			continue
		}

		if !hasScheduleCronTrigger(&flow) {
			continue
		}

		checked++

		// Parse cron expression
		if flow.Cron == "" {
			errors = append(errors, flowName+": missing cron expression")
			continue
		}

		schedule, err := parser.Parse(flow.Cron)
		if err != nil {
			errors = append(errors, flowName+": invalid cron: "+err.Error())
			continue
		}

		// We check if the schedule matches within our check window
		// System cron typically runs every 5 minutes, so we check a 5-minute window
		scheduledTime := shouldRunNowWithTime(schedule, now, 5*time.Minute)
		if !scheduledTime.IsZero() {
			// Create event with the actual scheduled time to enable proper deduplication
			event := map[string]interface{}{
				"trigger":       "schedule.cron",
				"workflow":      flowName,
				"timestamp":     now.Format(time.RFC3339),
				"scheduled_for": scheduledTime.Format(time.RFC3339), // Actual cron time
			}

			if _, err := StartRun(ctx, flowName, event); err != nil {
				errors = append(errors, flowName+": failed to start: "+err.Error())
			} else {
				triggered = append(triggered, flowName)
				utils.Info("Triggered cron workflow: %s for scheduled time: %s", flowName, scheduledTime.Format(time.RFC3339))
			}
		}
	}

	return map[string]interface{}{
		"status":    "completed",
		"timestamp": now.Format(time.RFC3339),
		"triggered": len(triggered),
		"workflows": triggered,
		"errors":    errors,
		"checked":   checked,
		"total":     len(flows),
	}, nil
}

// shouldRunNowWithTime checks if a cron schedule should run within the given window
// Returns the scheduled time if it should run, or zero time if not
// This handles the fact that system cron might not run exactly on time
func shouldRunNowWithTime(schedule cron.Schedule, now time.Time, window time.Duration) time.Time {
	// Get the previous scheduled time by looking back from now
	// We need to find the most recent scheduled time that should have run
	checkFrom := now.Add(-window)

	// Get when it should next run after our check start time
	nextRun := schedule.Next(checkFrom)

	// The scheduled time must be:
	// 1. After our check start time (checkFrom)
	// 2. Before or at the current time (with 1 minute buffer for early triggers)
	if nextRun.After(checkFrom) && nextRun.Before(now.Add(1*time.Minute)) {
		// Return the actual scheduled time for deduplication
		return nextRun
	}

	return time.Time{} // Zero time means don't run
}

// hasScheduleCronTrigger checks if a flow has schedule.cron in its triggers
func hasScheduleCronTrigger(flow *model.Flow) bool {
	switch on := flow.On.(type) {
	case string:
		return on == "schedule.cron"
	case []interface{}:
		for _, trigger := range on {
			if str, ok := trigger.(string); ok && str == "schedule.cron" {
				return true
			}
		}
	}
	return false
}
