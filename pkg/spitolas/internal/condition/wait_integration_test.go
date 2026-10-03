//go:build integration

package condition

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/spitolas/internal/browser"
	"github.com/vigolium/vigolium/pkg/spitolas/internal/config"
)

// createTestBrowser creates a browser for wait integration tests.
func createTestBrowser(t *testing.T, serverURL string) *browser.Browser {
	t.Helper()
	cfg, err := config.New(serverURL)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}
	cfg.Headless = true

	b, err := browser.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create browser: %v", err)
	}
	t.Cleanup(func() {
		b.Close()
	})
	return b
}

// TestIntegrationWaitConditionSlowWidget tests waiting for slow-loading element.
// Uses testWaitCondition.html which loads a widget after 1 second delay.
func TestIntegrationWaitConditionSlowWidget(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testWaitCondition.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// The widget takes 1 second to load
	// Wait for up to 3 seconds
	cond := NewWaitCondition("#SLOW_WIDGET", 3*time.Second).
		WithPolling(100 * time.Millisecond)

	start := time.Now()
	result := cond.Wait(context.Background(), page)
	elapsed := time.Since(start)

	if result != WaitSuccess {
		t.Errorf("Wait() = %d, want %d (WaitSuccess)", result, WaitSuccess)
	}

	// The main point is that the wait succeeded - timing may vary
	// depending on browser initialization and page load timing.
	// Navigation already waits for DOM stability, so the widget might
	// have already loaded by the time we start waiting.
	t.Logf("Wait completed in: %v", elapsed)
	if elapsed > 3*time.Second {
		t.Errorf("Wait took too long: %v (timeout was 3s)", elapsed)
	}
}

// TestIntegrationWaitConditionTimeout tests timeout behavior.
func TestIntegrationWaitConditionTimeout(t *testing.T) {
	// Not testWaitCondition.html: its widget lands 1s after load, and the wait
	// below only starts once Navigate returns, so a slow navigation on a loaded
	// host let the widget arrive inside the 500ms window. A 10s widget keeps the
	// margin far wider than any navigation.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body><div id="panel">loading...</div>
			<script>setTimeout(function () {
				document.getElementById("panel").innerHTML = "<div id='SLOW_WIDGET'>LOADED_SLOW_WIDGET</div>";
			}, 10000);</script></body></html>`))
	}))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Wait for an element that won't appear in time (it loads after 10s, the wait gives up after 500ms)
	cond := NewWaitCondition("#SLOW_WIDGET", 500*time.Millisecond).
		WithPolling(50 * time.Millisecond)

	result := cond.Wait(context.Background(), page)

	if result != WaitTimeout {
		t.Errorf("Wait() = %d, want %d (WaitTimeout)", result, WaitTimeout)
	}
}

// TestIntegrationWaitConditionURLMismatch tests URL pattern mismatch.
func TestIntegrationWaitConditionURLMismatch(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testWaitCondition.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// URL pattern doesn't match
	cond := NewWaitCondition("#SLOW_WIDGET", 1*time.Second).
		ForURL("http://other-site.com/.*")

	result := cond.Wait(context.Background(), page)

	if result != WaitURLMismatch {
		t.Errorf("Wait() = %d, want %d (WaitURLMismatch)", result, WaitURLMismatch)
	}
}

// TestIntegrationWaitConditionImmediateSuccess tests waiting for element already present.
func TestIntegrationWaitConditionImmediateSuccess(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testWaitCondition.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Wait for element already on page (the panel div)
	cond := NewWaitCondition("#panel", 1*time.Second)

	start := time.Now()
	result := cond.Wait(context.Background(), page)
	elapsed := time.Since(start)

	if result != WaitSuccess {
		t.Errorf("Wait() = %d, want %d (WaitSuccess)", result, WaitSuccess)
	}

	// Should complete almost immediately since element exists
	if elapsed > 200*time.Millisecond {
		t.Errorf("Wait took too long for existing element: %v", elapsed)
	}
}

// TestIntegrationWaitForElement tests WaitForElement helper.
func TestIntegrationWaitForElement(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Should find existing element
	if !WaitForElement(context.Background(), page, "#SHOULD_ALWAYS_BE_ON_THIS_PAGE", 1*time.Second) {
		t.Error("WaitForElement should find existing element")
	}

	// Should not find non-existent element
	if WaitForElement(context.Background(), page, "#nonexistent", 200*time.Millisecond) {
		t.Error("WaitForElement should not find non-existent element")
	}
}

// TestIntegrationWaitAll tests WaitAll with real browser.
func TestIntegrationWaitAll(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// All conditions should pass
	conditions := []*WaitCondition{
		NewWaitCondition("#INVARIANT_VIOLATION", 1*time.Second),
		NewWaitCondition("#SHOULD_ALWAYS_BE_ON_THIS_PAGE", 1*time.Second),
	}

	result := WaitAll(context.Background(), page, conditions...)
	if result != WaitSuccess {
		t.Errorf("WaitAll() = %d, want %d (WaitSuccess)", result, WaitSuccess)
	}
}

// TestIntegrationWaitAny tests WaitAny with real browser.
func TestIntegrationWaitAny(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testInvariants.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// At least one condition should pass
	conditions := []*WaitCondition{
		NewWaitCondition("#nonexistent1", 1*time.Second),
		NewWaitCondition("#INVARIANT_VIOLATION", 1*time.Second), // This exists
		NewWaitCondition("#nonexistent2", 1*time.Second),
	}

	result := WaitAny(context.Background(), page, conditions...)
	if result != WaitSuccess {
		t.Errorf("WaitAny() = %d, want %d (WaitSuccess)", result, WaitSuccess)
	}
}

// TestIntegrationWaitConditionVerifyContent verifies the actual content of loaded widget.
func TestIntegrationWaitConditionVerifyContent(t *testing.T) {
	server := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer server.Close()

	b := createTestBrowser(t, server.URL)
	page, err := b.NewPage()
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}

	if err := page.Navigate(server.URL + "/testWaitCondition.html"); err != nil {
		t.Fatalf("Failed to navigate: %v", err)
	}

	// Wait for slow widget to load
	cond := NewWaitCondition("#SLOW_WIDGET", 3*time.Second).
		WithPolling(100 * time.Millisecond)

	result := cond.Wait(context.Background(), page)
	if result != WaitSuccess {
		t.Fatalf("Wait failed: %d", result)
	}

	// EXTRACT-BASED VERIFICATION: Get actual element and verify content
	elem, err := page.Element("#SLOW_WIDGET")
	if err != nil {
		t.Fatalf("Failed to get element: %v", err)
	}

	text, err := elem.Text()
	if err != nil {
		t.Fatalf("Failed to get text: %v", err)
	}

	// Verify exact text content
	expectedText := "LOADED_SLOW_WIDGET"
	if text != expectedText+"\nSLOW_WIDGET_HOME" {
		t.Logf("Widget text: %q", text)
		// Just check it contains the expected text (layout may vary)
		if !strings.Contains(text, expectedText) {
			t.Errorf("Widget text does not contain %q", expectedText)
		}
	}

	// Verify link exists within widget
	link, err := page.Element("#SLOW_WIDGET a")
	if err != nil {
		t.Fatalf("Failed to find link in widget: %v", err)
	}

	linkText, _ := link.Text()
	if linkText != "SLOW_WIDGET_HOME" {
		t.Errorf("Link text = %q, want %q", linkText, "SLOW_WIDGET_HOME")
	}
}
