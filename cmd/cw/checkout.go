package main

import (
	"fmt"
	"time"

	"github.com/codewiresh/codewire/internal/platform"
	"github.com/codewiresh/codewire/internal/tui"
)

// handleCheckoutAndWait opens a browser for Stripe checkout, polls for payment
// completion, then waits for the resource to reach "running" status.
// If the resource doesn't require checkout, it skips straight to provisioning wait.
func handleCheckoutAndWait(client *platform.Client, result *platform.CreateResourceResult) error {
	if result.RequiresCheckout && result.CheckoutURL != "" {
		fmt.Println()
		fmt.Println("  Opening browser for payment...")
		fmt.Printf("  URL: %s\n", result.CheckoutURL)
		_ = openBrowser(result.CheckoutURL)

		type checkoutResult struct {
			resource *platform.PlatformResource
			err      error
		}
		ch := make(chan checkoutResult, 1)
		go func() {
			r, err := client.WaitForCheckout(result.ID, 2*time.Second, 5*time.Minute)
			ch <- checkoutResult{r, err}
		}()

		var resource *platform.PlatformResource
		spinRes, spinErr := tui.RunSpinner("Waiting for checkout...", time.Second, func() (bool, string, error) {
			select {
			case r := <-ch:
				if r.err != nil {
					return false, "", r.err
				}
				resource = r.resource
				return true, r.resource.BillingStatus, nil
			default:
				return false, "", nil
			}
		})
		if spinErr != nil {
			return fmt.Errorf("checkout not completed: %w\n  Run `cw setup` to try again", spinErr)
		}
		if spinRes.Err != nil {
			return fmt.Errorf("checkout not completed: %w\n  Run `cw setup` to try again", spinRes.Err)
		}
		_ = resource
	}

	fmt.Printf("  Provisioning %q (%s)\n\n", result.Name, result.Type)

	// Try SSE first, fall back to polling
	events := make(chan platform.ProvisionEvent, 64)
	sseErr := client.StreamProvisionEvents(result.ID, events)

	if sseErr != nil {
		// Fallback: poll with spinner
		type waitResult struct {
			err error
		}
		wch := make(chan waitResult, 1)
		go func() {
			_, err := client.WaitForResource(result.ID, "running", 5*time.Second, 10*time.Minute)
			wch <- waitResult{err}
		}()

		spinRes, spinErr := tui.RunSpinner("Waiting for provisioning...", time.Second, func() (bool, string, error) {
			select {
			case r := <-wch:
				if r.err != nil {
					return false, "", r.err
				}
				return true, "ready", nil
			default:
				return false, "", nil
			}
		})
		if spinErr != nil {
			return fmt.Errorf("provisioning failed: %w\n  Check status with: cw resources get %s", spinErr, result.ID)
		}
		if spinRes.Err != nil {
			return fmt.Errorf("provisioning failed: %w\n  Check status with: cw resources get %s", spinRes.Err, result.ID)
		}
		return nil
	}

	// SSE path: render live timeline
	res, err := runProvisionTimeline(events)
	if err != nil {
		return fmt.Errorf("timeline error: %w", err)
	}

	fmt.Println()
	if res.Failed {
		return fmt.Errorf("provisioning failed (%s)\n  Run `cw resources retry %s` to retry", res.Total, result.Slug)
	}

	fmt.Printf("  Ready! (%s)\n", res.Total)
	return nil
}

// promptConfirm asks a yes/no question with a default of yes.
func promptConfirm(label string) (bool, error) {
	answer, err := promptDefault(label, "Y")
	if err != nil {
		return false, err
	}
	switch answer {
	case "Y", "y", "yes", "Yes", "YES":
		return true, nil
	default:
		return false, nil
	}
}
