package management

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
)

const (
	defaultAuthInspectionIntervalSeconds = 3600
	minAuthInspectionIntervalSeconds     = 3600
	maxAuthInspectionIntervalSeconds     = 7 * 24 * 3600
	authInspectionVerifyConcurrency      = 40
	authInspectionVerifyBatchSize        = 100
	authInspectionVerifyMaxRounds        = 20000
	authInspectionRunTimeout             = 2 * time.Hour
)

type authInspectionStatus struct {
	Running          bool
	Trigger          string
	CurrentFile      string
	RecentChecked    []string
	Checked          int
	Valid            int
	Invalid          int
	Deleted          int
	Total            int
	Round            int
	LastError        string
	LastRunStartedAt time.Time
	LastRunFinished  time.Time
	NextRunAt        time.Time
}

func (h *Handler) startAuthInspectionScheduler() {
	if h == nil {
		return
	}
	h.inspectionMu.Lock()
	if h.inspectionTrigger == nil {
		h.inspectionTrigger = make(chan string, 1)
	}
	h.inspectionMu.Unlock()

	go h.authInspectionSchedulerLoop()
}

func (h *Handler) effectiveAuthInspectionConfig() config.AuthInspectionConfig {
	cfg := config.AuthInspectionConfig{}
	if h != nil && h.cfg != nil {
		cfg = h.cfg.AuthInspection
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = defaultAuthInspectionIntervalSeconds
	}
	if cfg.IntervalSeconds < minAuthInspectionIntervalSeconds {
		cfg.IntervalSeconds = minAuthInspectionIntervalSeconds
	}
	if cfg.IntervalSeconds > maxAuthInspectionIntervalSeconds {
		cfg.IntervalSeconds = maxAuthInspectionIntervalSeconds
	}
	return cfg
}

func (h *Handler) authInspectionSchedulerLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	nextRun := time.Time{}
	for range ticker.C {
		select {
		case trigger := <-h.inspectionTrigger:
			cfg := h.effectiveAuthInspectionConfig()
			h.runAuthInspection(context.Background(), strings.TrimSpace(trigger), cfg.AutoDeleteInvalid)
			if cfg.Enabled {
				nextRun = time.Now().Add(time.Duration(cfg.IntervalSeconds) * time.Second)
			} else {
				nextRun = time.Time{}
			}
			h.updateAuthInspectionNextRun(nextRun)
		default:
		}

		cfg := h.effectiveAuthInspectionConfig()
		h.inspectionMu.RLock()
		statusNextRun := h.inspectionStatus.NextRunAt
		h.inspectionMu.RUnlock()
		if !statusNextRun.IsZero() && (nextRun.IsZero() || !statusNextRun.Equal(nextRun)) {
			nextRun = statusNextRun
		}
		if !cfg.Enabled {
			nextRun = time.Time{}
			h.updateAuthInspectionNextRun(nextRun)
			continue
		}
		if nextRun.IsZero() {
			nextRun = time.Now().Add(time.Duration(cfg.IntervalSeconds) * time.Second)
			h.updateAuthInspectionNextRun(nextRun)
		}
		if time.Now().Before(nextRun) {
			continue
		}

		h.runAuthInspection(context.Background(), "scheduled", cfg.AutoDeleteInvalid)
		nextRun = time.Now().Add(time.Duration(cfg.IntervalSeconds) * time.Second)
		h.updateAuthInspectionNextRun(nextRun)
	}
}

func appendRecentChecked(prev []string, names []string, limit int) []string {
	if limit <= 0 {
		limit = 10
	}
	merged := append(append([]string{}, prev...), names...)
	dedup := make([]string, 0, limit)
	for i := len(merged) - 1; i >= 0; i-- {
		name := strings.TrimSpace(merged[i])
		if name == "" {
			continue
		}
		seen := false
		for j := range dedup {
			if dedup[j] == name {
				seen = true
				break
			}
		}
		if seen {
			continue
		}
		dedup = append(dedup, name)
		if len(dedup) >= limit {
			break
		}
	}
	for i, j := 0, len(dedup)-1; i < j; i, j = i+1, j-1 {
		dedup[i], dedup[j] = dedup[j], dedup[i]
	}
	return dedup
}

func (h *Handler) beginAuthInspection(trigger string) bool {
	h.inspectionMu.Lock()
	defer h.inspectionMu.Unlock()
	if h.inspectionStatus.Running {
		return false
	}
	h.inspectionStatus.Running = true
	h.inspectionStatus.Trigger = strings.TrimSpace(trigger)
	h.inspectionStatus.CurrentFile = ""
	h.inspectionStatus.RecentChecked = nil
	h.inspectionStatus.Checked = 0
	h.inspectionStatus.Valid = 0
	h.inspectionStatus.Invalid = 0
	h.inspectionStatus.Deleted = 0
	h.inspectionStatus.Total = 0
	h.inspectionStatus.Round = 0
	h.inspectionStatus.LastError = ""
	h.inspectionStatus.LastRunStartedAt = time.Now()
	h.inspectionStatus.LastRunFinished = time.Time{}
	return true
}

func (h *Handler) updateAuthInspectionNextRun(next time.Time) {
	h.inspectionMu.Lock()
	h.inspectionStatus.NextRunAt = next
	h.inspectionMu.Unlock()
}

func (h *Handler) updateAuthInspectionProgress(total, checked, valid, invalid, round int, currentFile string, batchNames []string) {
	h.inspectionMu.Lock()
	h.inspectionStatus.Total = total
	h.inspectionStatus.Checked = checked
	h.inspectionStatus.Valid = valid
	h.inspectionStatus.Invalid = invalid
	h.inspectionStatus.Round = round
	if strings.TrimSpace(currentFile) != "" {
		h.inspectionStatus.CurrentFile = strings.TrimSpace(currentFile)
	}
	if len(batchNames) > 0 {
		h.inspectionStatus.RecentChecked = appendRecentChecked(h.inspectionStatus.RecentChecked, batchNames, 10)
	}
	h.inspectionMu.Unlock()
}

func (h *Handler) finishAuthInspection(deleted int, err error) {
	h.inspectionMu.Lock()
	h.inspectionStatus.Running = false
	h.inspectionStatus.Deleted = deleted
	if err != nil {
		h.inspectionStatus.LastError = strings.TrimSpace(err.Error())
	}
	h.inspectionStatus.LastRunFinished = time.Now()
	h.inspectionMu.Unlock()
}

func (h *Handler) runAuthInspection(parent context.Context, trigger string, autoDeleteInvalid bool) {
	if h == nil || h.authManager == nil {
		return
	}
	if !h.beginAuthInspection(trigger) {
		return
	}

	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, authInspectionRunTimeout)
	defer cancel()

	cursor := 0
	round := 0
	checked := 0
	valid := 0
	invalid := 0
	total := 0
	done := false
	var runErr error

	for !done && round < authInspectionVerifyMaxRounds {
		res, errBatch := h.verifyInvalidAuthBatch(runCtx, "codex", authInspectionVerifyConcurrency, authInspectionVerifyBatchSize, cursor)
		if errBatch != nil {
			runErr = errBatch
			break
		}
		total = res.Total
		checked += res.Checked
		valid += res.Valid
		invalid += res.Invalid
		round++

		currentName := ""
		batchNames := make([]string, 0, len(res.Results))
		for _, item := range res.Results {
			name := strings.TrimSpace(item.Name)
			if name == "" {
				name = strings.TrimSpace(item.ID)
			}
			if name == "" {
				continue
			}
			batchNames = append(batchNames, name)
			currentName = name
		}
		h.updateAuthInspectionProgress(total, checked, valid, invalid, round, currentName, batchNames)

		cursor = res.NextCursor
		done = res.Done || cursor <= res.Cursor || (res.Total > 0 && cursor >= res.Total)
	}

	deleted := 0
	if runErr == nil && autoDeleteInvalid {
		deletedCount, _, errDelete := h.deleteInvalidAuthFilesInternal(runCtx)
		deleted = deletedCount
		if errDelete != nil {
			runErr = fmt.Errorf("auto delete invalid failed: %w", errDelete)
		}
	}
	h.finishAuthInspection(deleted, runErr)
}

func (h *Handler) authInspectionStatusPayload() gin.H {
	cfg := h.effectiveAuthInspectionConfig()
	h.inspectionMu.RLock()
	state := h.inspectionStatus
	h.inspectionMu.RUnlock()

	return gin.H{
		"enabled":             cfg.Enabled,
		"interval_seconds":    cfg.IntervalSeconds,
		"auto_delete_invalid": cfg.AutoDeleteInvalid,
		"running":             state.Running,
		"trigger":             strings.TrimSpace(state.Trigger),
		"current_file":        strings.TrimSpace(state.CurrentFile),
		"recent_checked":      state.RecentChecked,
		"checked":             state.Checked,
		"valid":               state.Valid,
		"invalid":             state.Invalid,
		"deleted":             state.Deleted,
		"total":               state.Total,
		"round":               state.Round,
		"last_error":          strings.TrimSpace(state.LastError),
		"last_run_started_at": state.LastRunStartedAt,
		"last_run_finished":   state.LastRunFinished,
		"next_run_at":         state.NextRunAt,
	}
}

func (h *Handler) GetAuthInspectionConfig(c *gin.Context) {
	cfg := h.effectiveAuthInspectionConfig()
	c.JSON(http.StatusOK, gin.H{
		"enabled":              cfg.Enabled,
		"interval_seconds":     cfg.IntervalSeconds,
		"auto_delete_invalid":  cfg.AutoDeleteInvalid,
		"min_interval_seconds": minAuthInspectionIntervalSeconds,
		"max_interval_seconds": maxAuthInspectionIntervalSeconds,
	})
}

func (h *Handler) PutAuthInspectionConfig(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config unavailable"})
		return
	}
	var req struct {
		Enabled           *bool `json:"enabled"`
		IntervalSeconds   *int  `json:"interval_seconds"`
		AutoDeleteInvalid *bool `json:"auto_delete_invalid"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Enabled == nil && req.IntervalSeconds == nil && req.AutoDeleteInvalid == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no config field provided"})
		return
	}

	h.mu.Lock()
	oldCfg := h.cfg.AuthInspection
	cfg := oldCfg
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.IntervalSeconds != nil {
		if *req.IntervalSeconds < minAuthInspectionIntervalSeconds || *req.IntervalSeconds > maxAuthInspectionIntervalSeconds {
			h.mu.Unlock()
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("interval_seconds must be between %d and %d", minAuthInspectionIntervalSeconds, maxAuthInspectionIntervalSeconds)})
			return
		}
		cfg.IntervalSeconds = *req.IntervalSeconds
	}
	if req.AutoDeleteInvalid != nil {
		cfg.AutoDeleteInvalid = *req.AutoDeleteInvalid
	}
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = defaultAuthInspectionIntervalSeconds
	}
	h.cfg.AuthInspection = cfg
	errSave := config.SaveConfigPreserveComments(h.configFilePath, h.cfg)
	if errSave != nil {
		h.cfg.AuthInspection = oldCfg
	}
	h.mu.Unlock()
	if errSave != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to save config: %v", errSave)})
		return
	}

	if cfg.Enabled {
		h.updateAuthInspectionNextRun(time.Now().Add(time.Duration(cfg.IntervalSeconds) * time.Second))
	} else {
		h.updateAuthInspectionNextRun(time.Time{})
	}
	c.JSON(http.StatusOK, gin.H{
		"status":              "ok",
		"enabled":             cfg.Enabled,
		"interval_seconds":    cfg.IntervalSeconds,
		"auto_delete_invalid": cfg.AutoDeleteInvalid,
	})
}

func (h *Handler) GetAuthInspectionStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "inspection": h.authInspectionStatusPayload()})
}

func (h *Handler) RunAuthInspectionNow(c *gin.Context) {
	h.inspectionMu.RLock()
	running := h.inspectionStatus.Running
	trigger := h.inspectionTrigger
	h.inspectionMu.RUnlock()
	if running {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "started": false, "reason": "inspection already running", "inspection": h.authInspectionStatusPayload()})
		return
	}
	if trigger == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "inspection scheduler unavailable"})
		return
	}
	started := false
	select {
	case trigger <- "manual":
		started = true
	default:
	}
	if !started {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "started": false, "reason": "inspection trigger queue is busy", "inspection": h.authInspectionStatusPayload()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "started": true, "inspection": h.authInspectionStatusPayload()})
}
