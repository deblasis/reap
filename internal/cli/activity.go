package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/deblasis/reap/internal/incodalog"
)

// cmdActivity implements `reap activity [--since DUR] [--json]`: the
// incoda lane.log digest across queues (NOT reap's own history - that is
// `reap log`). Records are dir-keyed activity with open/closed state; the
// live-ticket probe marks open records backed by a held ticket.
func cmdActivity(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("activity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	since := fs.Duration("since", 0, "only records with an event at or after this duration ago")
	asJSON := fs.Bool("json", false, "emit the machine schema")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "reap activity: unexpected argument %q (activity takes no paths)\n", fs.Arg(0))
		return ExitUsage
	}

	events := incodalog.ReadAll()
	if len(events) == 0 {
		if *asJSON {
			fmt.Fprintln(stdout, "[]")
			return ExitOK
		}
		fmt.Fprintln(stdout, "no incoda lane.log activity found (state dir: "+incodalog.StateDir()+")")
		return ExitOK
	}

	records, weakCount := incodalog.Digest(events)
	if *since > 0 {
		records = incodalog.Since(records, time.Now().Add(-*since))
	}

	// Deterministic order: most recent first.
	keys := make([]string, 0, len(records))
	for k := range records {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return records[keys[i]].LastEvent.After(records[keys[j]].LastEvent) })

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		list := make([]*incodalog.Record, 0, len(keys))
		for _, k := range keys {
			list = append(list, records[k])
		}
		if err := enc.Encode(list); err != nil {
			fmt.Fprintf(stderr, "reap activity: %v\n", err)
			return ExitState
		}
		return ExitOK
	}

	fmt.Fprintf(stdout, "incoda activity: %d dir(s)", len(records))
	if weakCount > 0 {
		fmt.Fprintf(stdout, " (%d old-format event(s) without dir=; attribution weak)", weakCount)
	}
	if *since > 0 {
		fmt.Fprintf(stdout, ", since %s", *since)
	}
	fmt.Fprintln(stdout)
	for _, k := range keys {
		r := records[k]
		marker := ""
		if r.Open && incodalog.LiveTicketsUnder(r.Dir) {
			marker = "  [LIVE TICKET]"
		}
		fmt.Fprintln(stdout, r.String()+marker)
	}
	return ExitOK
}
