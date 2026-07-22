package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aaacyrus/Reality-ScannerNChecker/internal/checker"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/datafiles"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/domain"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/publicip"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/scanner"
	"github.com/aaacyrus/Reality-ScannerNChecker/internal/ui"
)

var errUserExit = errors.New("user requested exit")

type App struct {
	console  *ui.Console
	data     *datafiles.Manager
	ip       *publicip.Detector
	lastScan scanner.Progress
}

func New(console *ui.Console) (*App, error) {
	dataManager, err := datafiles.New()
	if err != nil {
		return nil, err
	}
	return &App{
		console: console,
		data:    dataManager,
		ip:      publicip.NewDetector(),
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	defer a.data.Close()
	if err := a.selectLanguage(ctx); err != nil {
		return normalizeExit(err)
	}

	if err := a.data.Prepare(); err != nil {
		return err
	}
	if err := a.updateData(ctx); err != nil {
		return normalizeExit(err)
	}
	publicIP, err := a.detectPublicIP(ctx)
	if err != nil {
		return normalizeExit(err)
	}
	selection, err := a.configureScan(ctx, publicIP)
	if err != nil {
		return normalizeExit(err)
	}

	scans, cancelled, err := a.runScanner(ctx, selection)
	if cancelled {
		a.console.TStatus(ui.ToneWarning, "scan_cancelled")
		return nil
	}
	if err != nil {
		a.console.TStatus(ui.ToneError, "scan_failed", err)
		return err
	}
	if len(scans) == 0 {
		a.console.TStatus(ui.ToneWarning, "scan_empty")
		return nil
	}

	sources, earlyRejected := checker.ExtractSources(scans)
	a.console.TStatus(ui.ToneInfo, "domain_filter", len(sources), len(earlyRejected))
	if len(sources) == 0 {
		a.console.TStatus(ui.ToneWarning, "scan_empty")
		a.showResults(ctx, domain.RunResult{Rejected: earlyRejected})
		return nil
	}

	service, err := checker.New(a.data.ActiveDir(), selection.Prefix, selection.Infinite)
	if err != nil {
		return err
	}
	defer service.Close()

	run, cancelled := a.runChecker(ctx, service, sources)
	if cancelled {
		a.console.TStatus(ui.ToneWarning, "analysis_cancelled")
		return nil
	}
	run.Rejected = append(run.Rejected, earlyRejected...)

	cancelled = a.runVerification(ctx, service, &run)
	if cancelled {
		a.console.TStatus(ui.ToneWarning, "analysis_cancelled")
		return nil
	}
	a.showResults(ctx, run)
	return nil
}

func (a *App) selectLanguage(ctx context.Context) error {
	defaultChoice := 2
	locale := strings.ToLower(os.Getenv("LC_ALL") + " " + os.Getenv("LC_MESSAGES") + " " + os.Getenv("LANG"))
	if strings.Contains(locale, "zh") {
		defaultChoice = 1
	}
	a.console.Banner("Reality Scanner & Checker", "IPv4 TLS 掃描・驗證・排名 / Discovery · Validation · Ranking")
	a.console.Menu("1. 繁體中文 / Traditional Chinese\n2. English / 英文")
	choice, ok := a.console.Choice(ctx, fmt.Sprintf("選擇語言 / Choose language [default %d]: ", defaultChoice), defaultChoice, 1, 2)
	if !ok {
		return errUserExit
	}
	if choice == 1 {
		a.console.SetLanguage(domain.LanguageTraditionalChinese)
	} else {
		a.console.SetLanguage(domain.LanguageEnglish)
	}
	return nil
}

func (a *App) updateData(ctx context.Context) error {
	if !a.data.NeedsUpdate() {
		return nil
	}
	a.console.TSection("section.data")
	a.console.TStatus(ui.ToneWarning, "data_check")
	a.console.TMenu("data_menu")
	choice, ok := a.console.Choice(ctx, a.console.Translator().T("data_prompt"), 1, 0, 1, 2)
	if !ok || choice == 0 {
		return errUserExit
	}
	if choice == 2 {
		return nil
	}
	stopSpinner := a.console.StartSpinner(a.console.Translator().T("data_updating"))
	updateCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	err := a.data.Update(updateCtx, func(done, total int, name string) {
		a.console.TStatus(ui.ToneInfo, "data_progress", done, total, name)
	})
	stopSpinner()
	if err != nil {
		a.console.TStatus(ui.ToneWarning, "data_failed", err)
		return nil
	}
	a.console.TStatus(ui.ToneSuccess, "data_updated")
	return nil
}

func (a *App) detectPublicIP(ctx context.Context) (netip.Addr, error) {
	a.console.TSection("section.network")
	stopSpinner := a.console.StartSpinner(a.console.Translator().T("ip_detecting"))
	result, err := a.ip.Detect(ctx)
	stopSpinner()
	if err == nil && result.Detected.IsValid() {
		a.console.TStatus(ui.ToneSuccess, "ip_detected", result.Detected, result.Source)
		return result.Detected, nil
	}
	a.console.TStatus(ui.ToneWarning, "ip_ambiguous")
	for index, candidate := range result.Candidates {
		a.console.Tln("ip_candidate", index+1, candidate)
	}
	manual := len(result.Candidates) + 1
	a.console.Tln("ip_manual_option", manual)
	allowed := make([]int, 0, manual+1)
	allowed = append(allowed, 0)
	for value := 1; value <= manual; value++ {
		allowed = append(allowed, value)
	}
	choice, ok := a.console.Choice(ctx, a.console.Translator().T("ip_choice_prompt", manual), manual, allowed...)
	if !ok || choice == 0 {
		return netip.Addr{}, errUserExit
	}
	if choice <= len(result.Candidates) {
		return result.Candidates[choice-1], nil
	}
	for {
		raw, ok := a.console.Read(ctx, a.console.Translator().T("ip_manual_prompt"), "")
		if !ok {
			return netip.Addr{}, errUserExit
		}
		ip, parseErr := netip.ParseAddr(raw)
		if parseErr == nil && publicip.IsPublicIPv4(ip) {
			return ip, nil
		}
		a.console.Tln("ip_invalid")
	}
}

func (a *App) configureScan(ctx context.Context, publicIP netip.Addr) (domain.ScanSelection, error) {
	a.console.TSection("section.setup")
	for {
		selection, err := a.chooseRange(ctx, publicIP)
		if err != nil {
			return domain.ScanSelection{}, err
		}
		profile, back, err := a.chooseProfile(ctx)
		if err != nil {
			return domain.ScanSelection{}, err
		}
		if back {
			continue
		}
		selection.Profile = profile
		choice, err := a.confirmScan(ctx, selection)
		if err != nil {
			return domain.ScanSelection{}, err
		}
		switch choice {
		case 1:
			return selection, nil
		case 2:
			continue
		default:
			return domain.ScanSelection{}, errUserExit
		}
	}
}

func (a *App) chooseRange(ctx context.Context, publicIP netip.Addr) (domain.ScanSelection, error) {
	for {
		a.console.TMenu("range_menu")
		choice, ok := a.console.Choice(ctx, a.console.Translator().T("range_prompt"), 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
		if !ok || choice == 0 {
			return domain.ScanSelection{}, errUserExit
		}
		if choice == 9 {
			a.console.TStatus(ui.ToneWarning, "infinite_warning")
			confirm, ok := a.console.Choice(ctx, a.console.Translator().T("infinite_confirm"), 2, 1, 2)
			if !ok {
				return domain.ScanSelection{}, errUserExit
			}
			if confirm != 1 {
				continue
			}
			return domain.ScanSelection{
				PublicIP: publicIP,
				Prefix:   netip.PrefixFrom(publicIP, 32),
				Infinite: true,
			}, nil
		}
		bits := map[int]int{1: 24, 2: 23, 3: 22, 4: 21, 5: 20, 6: 19, 7: 18, 8: 17}[choice]
		return domain.ScanSelection{
			PublicIP: publicIP,
			Prefix:   netip.PrefixFrom(publicIP, bits).Masked(),
		}, nil
	}
}

func (a *App) chooseProfile(ctx context.Context) (domain.ScanProfile, bool, error) {
	a.console.TMenu("profile_menu")
	choice, ok := a.console.Choice(ctx, a.console.Translator().T("profile_prompt"), 1, 0, 1, 2, 3)
	if !ok {
		return domain.ScanProfile{}, false, errUserExit
	}
	if choice == 0 {
		return domain.ScanProfile{}, true, nil
	}
	profiles := map[int]domain.ScanProfile{
		1: {Name: a.console.Translator().T("profile_balanced"), Concurrency: 20, Timeout: 3 * time.Second},
		2: {Name: a.console.Translator().T("profile_conservative"), Concurrency: 10, Timeout: 3 * time.Second},
		3: {Name: a.console.Translator().T("profile_fast"), Concurrency: 50, Timeout: 3 * time.Second},
	}
	return profiles[choice], false, nil
}

func (a *App) confirmScan(ctx context.Context, selection domain.ScanSelection) (int, error) {
	a.console.TSection("confirm_title")
	a.console.Tln("confirm_ip", selection.PublicIP)
	if selection.Infinite {
		a.console.Tln("confirm_range", a.console.Translator().T("unbounded"), a.console.Translator().T("unbounded"))
		a.console.Tln("confirm_count", a.console.Translator().T("unbounded"))
		a.console.Tln("confirm_worst", a.console.Translator().T("unbounded"))
	} else {
		first, last := prefixEndpoints(selection.Prefix)
		count := prefixCount(selection.Prefix)
		a.console.Tln("confirm_range", selection.Prefix, first.String()+" – "+last.String())
		a.console.Tln("confirm_count", formatInt(count))
		worst := time.Duration((count+int64(selection.Profile.Concurrency)-1)/int64(selection.Profile.Concurrency)) * selection.Profile.Timeout
		a.console.Tln("confirm_worst", compactDuration(worst))
	}
	a.console.Tln("confirm_port")
	a.console.Tln("confirm_profile", selection.Profile.Name, selection.Profile.Concurrency)
	a.console.TStatus(ui.ToneWarning, "confirm_warning")
	a.console.TMenu("confirm_menu")
	choice, ok := a.console.Choice(ctx, a.console.Translator().T("confirm_prompt"), 1, 0, 1, 2)
	if !ok {
		return 0, errUserExit
	}
	return choice, nil
}

func (a *App) runScanner(ctx context.Context, selection domain.ScanSelection) ([]scanner.Result, bool, error) {
	a.console.TSection("section.scanner")
	a.console.Progress(a.console.Translator().T("scan_start"))
	a.lastScan = scanner.Progress{}
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type outcome struct {
		results []scanner.Result
		err     error
	}
	completed := make(chan outcome, 1)
	progress := make(chan scanner.Progress, 1)
	go func() {
		results, err := scanner.Scan(scanCtx, scanner.Config{
			Prefix:      selection.Prefix,
			Seed:        selection.PublicIP,
			Infinite:    selection.Infinite,
			Port:        443,
			Concurrency: selection.Profile.Concurrency,
			Timeout:     selection.Profile.Timeout,
		}, func(update scanner.Progress) {
			select {
			case progress <- update:
			default:
				select {
				case <-progress:
				default:
				}
				select {
				case progress <- update:
				default:
				}
			}
		})
		completed <- outcome{results: results, err: err}
	}()

	lastFound := int64(0)
	lastPercent := int64(-1)
	latest := scanner.Progress{}
	haveProgress := false
	var animation <-chan time.Time
	var ticker *time.Ticker
	if a.console.Interactive() {
		ticker = time.NewTicker(80 * time.Millisecond)
		animation = ticker.C
		defer ticker.Stop()
	}
	commands := a.console.Commands()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-completed
			a.console.FinishProgress()
			return nil, true, nil
		case command, ok := <-commands:
			if !ok {
				commands = nil
				continue
			}
			if ok && strings.TrimSpace(command) == "0" {
				cancel()
				<-completed
				a.console.FinishProgress()
				return nil, true, nil
			}
		case <-animation:
			if haveProgress {
				a.displayScanProgress(latest)
			} else {
				a.console.Progress(a.console.Translator().T("scan_start"))
			}
		case update := <-progress:
			a.lastScan = update
			latest = update
			haveProgress = true
			percentage := int64(-1)
			if update.Total > 0 {
				percentage = update.Scanned * 100 / update.Total
			}
			if update.Found > lastFound {
				a.console.TStatus(ui.ToneSuccess, "scan_found", update.Current)
				lastFound = update.Found
			}
			if !a.console.Interactive() && percentage >= 0 && percentage/10 > lastPercent/10 {
				a.displayScanProgress(update)
				lastPercent = percentage
			}
		case result := <-completed:
			a.console.FinishProgress()
			if errors.Is(result.err, context.Canceled) {
				return nil, true, nil
			}
			scanned := a.lastScan.Scanned
			if result.err == nil && !selection.Infinite {
				scanned = prefixCount(selection.Prefix)
			}
			a.console.TStatus(ui.ToneSuccess, "scan_done", scanned, len(result.results))
			return result.results, false, result.err
		}
	}
}

func (a *App) displayScanProgress(progress scanner.Progress) {
	if progress.Total == 0 {
		a.console.Progress(a.console.Translator().T(
			"scan_progress_infinite", progress.Scanned, progress.Found, progress.Failed, compactDuration(progress.Elapsed),
		))
		return
	}
	remaining := time.Duration(0)
	if progress.Scanned > 0 {
		remaining = time.Duration(float64(progress.Elapsed) * float64(progress.Total-progress.Scanned) / float64(progress.Scanned))
	}
	a.console.ProgressBar(a.console.Translator().T(
		"scan_progress", formatInt(progress.Scanned), progress.Found, progress.Failed,
		compactDuration(progress.Elapsed), compactDuration(remaining),
	), progress.Scanned, progress.Total)
}

func (a *App) runChecker(ctx context.Context, service *checker.Service, sources []domain.Source) (domain.RunResult, bool) {
	a.console.TSection("section.checker")
	a.console.Progress(a.console.Translator().T("checker_start"))
	checkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan domain.RunResult, 1)
	progress := make(chan checker.Progress, 1)
	go func() {
		completed <- service.Analyze(checkCtx, sources, func(update checker.Progress) {
			select {
			case progress <- update:
			default:
			}
		})
	}()
	latest := checker.Progress{}
	haveProgress := false
	var animation <-chan time.Time
	var ticker *time.Ticker
	if a.console.Interactive() {
		ticker = time.NewTicker(80 * time.Millisecond)
		animation = ticker.C
		defer ticker.Stop()
	}
	commands := a.console.Commands()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-completed
			a.console.FinishProgress()
			return domain.RunResult{}, true
		case command, ok := <-commands:
			if !ok {
				commands = nil
				continue
			}
			if ok && strings.TrimSpace(command) == "0" {
				cancel()
				<-completed
				a.console.FinishProgress()
				return domain.RunResult{}, true
			}
		case <-animation:
			if haveProgress {
				a.console.ProgressBar(a.console.Translator().T("checker_progress", latest.Done, latest.Total, latest.Qualified, latest.Rejected, latest.Domain), int64(latest.Done), int64(latest.Total))
			} else {
				a.console.Progress(a.console.Translator().T("checker_start"))
			}
		case update := <-progress:
			latest = update
			haveProgress = true
			if !a.console.Interactive() {
				a.console.Progress(a.console.Translator().T("checker_progress", update.Done, update.Total, update.Qualified, update.Rejected, update.Domain))
			}
		case result := <-completed:
			a.console.FinishProgress()
			a.console.TStatus(ui.ToneSuccess, "checker_done")
			return result, false
		}
	}
}

func (a *App) runVerification(ctx context.Context, service *checker.Service, run *domain.RunResult) bool {
	a.console.TSection("section.verify")
	a.console.Progress(a.console.Translator().T("verify_start"))
	verifyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	completed := make(chan struct{}, 1)
	progress := make(chan checker.Progress, 1)
	go func() {
		service.VerifyQualified(verifyCtx, run, func(update checker.Progress) {
			select {
			case progress <- update:
			default:
			}
		})
		completed <- struct{}{}
	}()
	latest := checker.Progress{}
	haveProgress := false
	var animation <-chan time.Time
	var ticker *time.Ticker
	if a.console.Interactive() {
		ticker = time.NewTicker(80 * time.Millisecond)
		animation = ticker.C
		defer ticker.Stop()
	}
	commands := a.console.Commands()
	for {
		select {
		case <-ctx.Done():
			cancel()
			<-completed
			a.console.FinishProgress()
			return true
		case command, ok := <-commands:
			if !ok {
				commands = nil
				continue
			}
			if ok && strings.TrimSpace(command) == "0" {
				cancel()
				<-completed
				a.console.FinishProgress()
				return true
			}
		case <-animation:
			if haveProgress {
				a.console.ProgressBar(a.console.Translator().T("verify_progress", latest.Done, latest.Total, latest.Domain), int64(latest.Done), int64(latest.Total))
			} else {
				a.console.Progress(a.console.Translator().T("verify_start"))
			}
		case update := <-progress:
			latest = update
			haveProgress = true
			if !a.console.Interactive() {
				a.console.Progress(a.console.Translator().T("verify_progress", update.Done, update.Total, update.Domain))
			}
		case <-completed:
			a.console.FinishProgress()
			a.console.TStatus(ui.ToneSuccess, "verify_done")
			return false
		}
	}
}

func (a *App) showResults(ctx context.Context, run domain.RunResult) {
	translator := a.console.Translator()
	a.console.TSection("section.results")
	if len(run.Ranked) == 0 {
		a.console.TStatus(ui.ToneWarning, "no_best")
	} else {
		best := run.Ranked[0]
		a.console.TStatus(ui.ToneSuccess, "best", best.Candidate.IP, best.Candidate.SNI, best.Score.Total())
		for index := 1; index < min(3, len(run.Ranked)); index++ {
			backup := run.Ranked[index]
			a.console.Tln("backup", index, backup.Candidate.IP, backup.Candidate.SNI, backup.Score.Total())
		}
		a.console.Println()
		a.console.Tln("ranking_title")
		a.console.Println(ui.RankingTableStyled(run.Ranked, translator, a.console.ColorsEnabled()))
	}
	a.console.TStatus(ui.ToneInfo, "rejected_summary", len(run.Rejected))

	for {
		a.console.TMenu("result_menu")
		choice, ok := a.console.Choice(ctx, translator.T("result_prompt"), 0, 0, 1, 2)
		if !ok || choice == 0 {
			a.console.TStatus(ui.ToneSuccess, "bye")
			return
		}
		switch choice {
		case 1:
			a.showDetails(ctx, run)
		case 2:
			a.console.TSection("rejected_title")
			if len(run.Rejected) == 0 {
				a.console.Tln("none")
			} else {
				sort.SliceStable(run.Rejected, func(i, j int) bool {
					if run.Rejected[i].Reason != run.Rejected[j].Reason {
						return run.Rejected[i].Reason < run.Rejected[j].Reason
					}
					return run.Rejected[i].Candidate.IP.Less(run.Rejected[j].Candidate.IP)
				})
				a.console.Println(ui.RejectedTableStyled(run.Rejected, translator, a.console.ColorsEnabled()))
			}
		}
	}
}

func (a *App) showDetails(ctx context.Context, run domain.RunResult) {
	items := append([]domain.Result(nil), run.Ranked...)
	if len(items) == 0 {
		a.console.Tln("none")
		return
	}
	for index, item := range items {
		a.console.Printf("%d. %s | %s\n", index+1, item.Candidate.IP, item.Candidate.SNI)
	}
	allowed := make([]int, 0, len(items)+1)
	allowed = append(allowed, 0)
	for index := range items {
		allowed = append(allowed, index+1)
	}
	choice, ok := a.console.Choice(ctx, a.console.Translator().T("detail_prompt"), 0, allowed...)
	if !ok || choice == 0 {
		return
	}
	a.console.Println(ui.DetailStyled(items[choice-1], a.console.Translator(), a.console.ColorsEnabled()))
}

func prefixCount(prefix netip.Prefix) int64 {
	return int64(1) << (32 - prefix.Bits())
}

func prefixEndpoints(prefix netip.Prefix) (netip.Addr, netip.Addr) {
	prefix = prefix.Masked()
	first := prefix.Addr()
	last := first
	for range prefixCount(prefix) - 1 {
		last = last.Next()
	}
	return first, last
}

func formatInt(value int64) string {
	text := strconv.FormatInt(value, 10)
	for index := len(text) - 3; index > 0; index -= 3 {
		text = text[:index] + "," + text[index:]
	}
	return text
}

func compactDuration(value time.Duration) string {
	if value <= 0 {
		return "0s"
	}
	if value < time.Second {
		return fmt.Sprintf("%dms", value.Milliseconds())
	}
	value = value.Round(time.Second)
	if value < time.Minute {
		return value.String()
	}
	minutes := int(value / time.Minute)
	seconds := int((value % time.Minute) / time.Second)
	return fmt.Sprintf("%dm%02ds", minutes, seconds)
}

func normalizeExit(err error) error {
	if errors.Is(err, errUserExit) {
		return nil
	}
	return err
}
