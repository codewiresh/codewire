package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/codewiresh/codewire/internal/platform"
)

func costCmd() *cobra.Command {
	var (
		output    string
		orgFilter string
	)

	cmd := &cobra.Command{
		Use:   "cost",
		Short: "Show usage and billing overview",
		Long:  "Display resource usage and billing information across organizations.",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonOutput, err := wantsJSON(output)
			if err != nil {
				return err
			}
			if !platform.HasConfig() {
				return fmt.Errorf("not in platform mode (run 'cw setup')")
			}

			pc, err := platform.NewClient()
			if err != nil {
				return err
			}

			orgs, err := pc.ListOrgs()
			if err != nil {
				return fmt.Errorf("list orgs: %w", err)
			}

			if jsonOutput {
				return costJSON(pc, orgs, orgFilter)
			}

			for _, org := range orgs {
				if orgFilter != "" && org.Slug != orgFilter && org.ID != orgFilter {
					continue
				}
				if len(org.Resources) == 0 {
					continue
				}

				overview, err := pc.GetBillingOverview(org.ID)
				if err != nil {
					fmt.Printf("# %s (billing unavailable)\n\n", org.Slug)
					continue
				}

				fmt.Printf("# %s\n\n", org.Slug)

				// Build subscription lookup by resource ID
				subByRes := map[string]platform.SubscriptionSummary{}
				for _, s := range overview.Subscriptions {
					subByRes[s.ResourceID] = s
				}

				w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
				fmt.Fprintf(w, "  Resource\tPlan\t$/mo\tCPU hrs\tMem GB·hrs\tDisk GB·hrs\tOverage\n")

				var totalCPU, totalMem, totalDisk float64
				var totalOverageCents int
				var totalBaseCents int

				for _, res := range org.Resources {
					sub, hasSub := subByRes[res.ID]
					planName := "–"
					baseCost := "–"
					if hasSub {
						planName = sub.PlanDisplayName
						if planName == "" {
							planName = sub.Plan
						}
						baseCost = fmt.Sprintf("$%d", sub.MonthlyCostCents/100)
						totalBaseCents += sub.MonthlyCostCents
					}

					if res.Type == "coder" {
						usage, err := pc.GetResourceUsage(res.ID)
						if err != nil {
							fmt.Fprintf(w, "  %s\t%s\t%s\t–\t–\t–\t–\n", res.Name, planName, baseCost)
							continue
						}
						fmt.Fprintf(w, "  %s\t%s\t%s\t%.1f\t%.1f\t%.1f\t$%.2f\n",
							res.Name, planName, baseCost,
							usage.CPUHours, usage.MemoryGBHours, usage.DiskGBHours,
							float64(usage.Overage.TotalCents)/100)
						totalCPU += usage.CPUHours
						totalMem += usage.MemoryGBHours
						totalDisk += usage.DiskGBHours
						totalOverageCents += usage.Overage.TotalCents
					} else {
						fmt.Fprintf(w, "  %s\t%s\t%s\t–\t–\t–\t–\n", res.Name, planName, baseCost)
					}
				}

				// Include subscriptions for resources not in org.Resources (edge case)
				seen := map[string]bool{}
				for _, res := range org.Resources {
					seen[res.ID] = true
				}
				for _, s := range overview.Subscriptions {
					if seen[s.ResourceID] {
						continue
					}
					planName := s.PlanDisplayName
					if planName == "" {
						planName = s.Plan
					}
					fmt.Fprintf(w, "  %s\t%s\t$%d\t–\t–\t–\t–\n",
						s.ResourceName, planName, s.MonthlyCostCents/100)
					totalBaseCents += s.MonthlyCostCents
				}

				fmt.Fprintf(w, "  \t\t────\t─────\t──────────\t───────────\t───────\n")
				fmt.Fprintf(w, "  Total\t\t$%d\t%.1f\t%.1f\t%.1f\t$%.2f\n",
					totalBaseCents/100, totalCPU, totalMem, totalDisk, float64(totalOverageCents)/100)
				w.Flush()

				estimated := float64(totalBaseCents+totalOverageCents) / 100
				fmt.Printf("\n  Estimated this month: $%.2f\n\n", estimated)
			}

			return nil
		},
	}

	addOutputFlag(cmd, &output, "Output format (text|json)")
	cmd.Flags().StringVar(&orgFilter, "org", "", "Filter to a specific organization (slug or ID)")
	return cmd
}

func costJSON(pc *platform.Client, orgs []platform.OrgWithRole, orgFilter string) error {
	type orgCost struct {
		Org     platform.OrgWithRole               `json:"org"`
		Billing *platform.BillingOverview          `json:"billing,omitempty"`
		Usage   map[string]*platform.ResourceUsage `json:"usage,omitempty"`
	}

	var results []orgCost
	for _, org := range orgs {
		if orgFilter != "" && org.Slug != orgFilter && org.ID != orgFilter {
			continue
		}
		entry := orgCost{Org: org, Usage: map[string]*platform.ResourceUsage{}}
		if overview, err := pc.GetBillingOverview(org.ID); err == nil {
			entry.Billing = overview
		}
		for _, res := range org.Resources {
			if res.Type != "coder" {
				continue
			}
			if usage, err := pc.GetResourceUsage(res.ID); err == nil {
				entry.Usage[res.ID] = usage
			}
		}
		// Usage endpoint only exists for coder resources, but subscriptions
		// data flows through the billing overview automatically.
		results = append(results, entry)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
