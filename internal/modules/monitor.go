package modules

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/gnacho/netgrip/internal/ubus"
)

const monitorInterval = 15 * time.Second

type Monitor struct {
	mu        sync.Mutex
	wanUp     *bool
	knownMACs map[string]bool
	stopCh    chan struct{}
}

var monitorInstance *Monitor

func StartMonitor() {
	if monitorInstance != nil {
		return
	}
	m := &Monitor{
		knownMACs: make(map[string]bool),
		stopCh:    make(chan struct{}),
	}
	monitorInstance = m
	go m.run()
}

func StopMonitor() {
	if monitorInstance != nil {
		close(monitorInstance.stopCh)
		monitorInstance = nil
	}
}

func (m *Monitor) run() {
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *Monitor) check() {
	if !anyChannelEnabled() {
		return
	}

	m.checkWan()
	m.checkNewClients()
}

func (m *Monitor) checkWan() {
	wan, err := ubus.GetWanStatus()
	if err != nil {
		return
	}
	isUp := wan.Up

	m.mu.Lock()
	prev := m.wanUp
	m.wanUp = &isUp
	m.mu.Unlock()

	if prev == nil {
		return
	}

	wasUp := *prev
	if isUp == wasUp {
		return
	}

	if isUp {
		notifyAll("NetGrip",
			"✅ <b>NetGrip</b>\n🌐 WAN recovered — Internet connection restored",
			"✅ NetGrip\n🌐 WAN recovered - Internet connection restored",
			true)
	} else {
		notifyAll("NetGrip",
			"🔴 <b>NetGrip</b>\n🌐 WAN down — Internet connection lost",
			"🔴 NetGrip\n🌐 WAN down - Internet connection lost",
			true)
	}
}

func (m *Monitor) checkNewClients() {
	clients := ListClients("")

	currentMACs := make(map[string]bool, len(clients))
	for _, c := range clients {
		if c.MAC != "" {
			currentMACs[c.MAC] = true
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.knownMACs) == 0 {
		m.knownMACs = currentMACs
		return
	}

	var newOnes []Client
	for _, c := range clients {
		if c.MAC != "" && !m.knownMACs[c.MAC] {
			newOnes = append(newOnes, c)
		}
	}

	m.knownMACs = currentMACs

	if len(newOnes) == 0 {
		return
	}

	for _, c := range newOnes {
		name := c.Name
		if name == "" {
			name = "Unknown device"
		}
		notifyAll("NetGrip",
			fmt.Sprintf("📱 <b>NetGrip</b>\nNew client: <b>%s</b>\nMAC: %s · %s", htmlEsc(name), c.MAC, c.Type),
			fmt.Sprintf("📱 NetGrip\nNew client: %s\nMAC: %s · %s", name, c.MAC, c.Type),
			false)
	}
}

// notifyAll sends one notification to every enabled channel (Telegram,
// ntfy and Matrix), fail-silent: a channel outage never breaks the caller.
// telegramText is HTML (Telegram parse_mode), ntfyText is plain text (ntfy
// does not parse HTML) and title is the ntfy Title header. Matrix gets both:
// the plain text as its body and the HTML as its formatted body.
//
// The channels are sent to in parallel: each has its own timeout and retry,
// and one slow or hanging server must not hold the others (or the monitor)
// back for the sum of all of them.
func notifyAll(title, telegramText, ntfyText string, urgent bool) {
	var wg sync.WaitGroup
	tg := LoadTelegramConfig()
	if tg.Enabled && tg.BotToken != "" && tg.ChatID != "" {
		wg.Go(func() {
			if err := SendTelegram(tg, telegramText, urgent); err != nil {
				log.Printf("[notify] telegram: %v", err)
			}
		})
	}
	nt := LoadNtfyConfig()
	if nt.Enabled && nt.Topic != "" {
		wg.Go(func() {
			if err := SendNtfy(nt, title, ntfyText, urgent); err != nil {
				log.Printf("[notify] ntfy: %v", err)
			}
		})
	}
	mx := LoadMatrixConfig()
	switch {
	case mx.Enabled && mx.Configured():
		wg.Go(func() {
			if err := SendMatrix(mx, ntfyText, telegramText, urgent); err != nil {
				log.Printf("[notify] matrix: %s", MatrixLogSafe(err))
			}
		})
	case mx.Enabled && mx.Unreadable:
		log.Printf("[notify] matrix: not sent, the stored config cannot be read; enter the credentials again")
	}
	wg.Wait()
}

// anyChannelEnabled reports whether at least one notification channel is
// configured, so the monitor can skip work when nothing would be notified.
func anyChannelEnabled() bool {
	tg := LoadTelegramConfig()
	if tg.Enabled && tg.BotToken != "" && tg.ChatID != "" {
		return true
	}
	nt := LoadNtfyConfig()
	if nt.Enabled && nt.Topic != "" {
		return true
	}
	mx := LoadMatrixConfig()
	return mx.Enabled && mx.Configured()
}
