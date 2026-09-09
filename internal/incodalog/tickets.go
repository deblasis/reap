package incodalog

// RailHealth is the live-ticket rail's enumeration result: every HELD
// ticket's dir, whether ANY level of the enumeration failed (the sentinel
// semantics), and the failure NAMES for doctor's readout. Absent evidence
// must never read as inactive - Unknown=true makes every candidate read
// live-or-unknown rather than silently unmarked.
type RailHealth struct {
	Dirs               []string // held tickets' dirs ("" never among them)
	Unknown            bool     // any enumeration failure: the sentinel
	UnreadableQueues   []string // queue dirs that listed but would not enumerate
	UnattributableLive []string // held tickets whose body yields no dir
}
