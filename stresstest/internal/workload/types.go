package workload

import "time"

// Phase represents a workload phase.
type Phase int

const (
	PhaseSteady    Phase = iota // 70% of time: 1-10 conc, 100ms-2s delay
	PhaseBurst                  // 20% of time: 20-100 conc, 0-500ms delay
	PhaseQuiescent              // 10% of time: 0-1 conc, 2-5s delay
)

func (p Phase) String() string {
	switch p {
	case PhaseSteady:
		return "steady"
	case PhaseBurst:
		return "burst"
	case PhaseQuiescent:
		return "quiescent"
	default:
		return "unknown"
	}
}

// CommandCategory classifies kubectl commands.
type CommandCategory string

const (
	CatReadOnly  CommandCategory = "read"
	CatMutating  CommandCategory = "mutate"
	CatInvalid   CommandCategory = "invalid"
	CatFuzzing   CommandCategory = "fuzz"
	CatDirectIPC CommandCategory = "ipc"
)

// FailureClass classifies command failures.
type FailureClass string

const (
	FailNone        FailureClass = ""
	FailDaemonDown  FailureClass = "daemon_down"
	FailDaemonError FailureClass = "daemon_error"
	FailAPIServer   FailureClass = "api_server_error"
	FailClientError FailureClass = "client_error"
	FailTimeout     FailureClass = "timeout"
)

// CmdTemplate defines a kubectl command template.
type CmdTemplate struct {
	Args              []string
	Weight            int
	Stdin             string
	ExpectClientError bool
}

// CommandResult holds the result of a single command execution.
type CommandResult struct {
	Timestamp         time.Time
	Category          CommandCategory
	CommandType       string
	Args              []string
	ExitCode          int
	Duration          time.Duration
	FailureClass      FailureClass
	Error             string
	ResourceName      string
	SLAViolation      bool
	ExpectClientError bool
}

// TrackedResource records a K8s resource created by the stress test.
type TrackedResource struct {
	Kind      string
	Name      string
	CreatedAt time.Time
}
