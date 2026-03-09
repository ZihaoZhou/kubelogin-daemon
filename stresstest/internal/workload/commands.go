package workload

// readOnlyTemplates defines read-only kubectl command templates (60%).
var readOnlyTemplates = []CmdTemplate{
	// Namespace-scoped
	{Args: []string{"get", "pods"}, Weight: 10},
	{Args: []string{"get", "pods", "-o", "json"}, Weight: 5},
	{Args: []string{"get", "pods", "-o", "wide"}, Weight: 3},
	{Args: []string{"get", "pods", "--show-labels"}, Weight: 3},
	{Args: []string{"get", "services"}, Weight: 5},
	{Args: []string{"get", "deployments"}, Weight: 5},
	{Args: []string{"get", "configmaps"}, Weight: 5},
	{Args: []string{"get", "secrets"}, Weight: 3},
	{Args: []string{"get", "jobs"}, Weight: 3},
	{Args: []string{"get", "events", "--sort-by=.metadata.creationTimestamp"}, Weight: 3},
	{Args: []string{"get", "pvc"}, Weight: 2},
	{Args: []string{"get", "resourcequotas"}, Weight: 2},

	// Describe (heavier)
	{Args: []string{"describe", "pod", "{existing-pod}"}, Weight: 3},
	{Args: []string{"describe", "service", "{existing-svc}"}, Weight: 2},

	// Logs
	{Args: []string{"logs", "{existing-pod}", "--tail=10"}, Weight: 3},
	{Args: []string{"logs", "{existing-pod}", "--since=5m"}, Weight: 2},

	// API discovery
	{Args: []string{"api-resources"}, Weight: 1},
	{Args: []string{"version"}, Weight: 2},
	{Args: []string{"auth", "can-i", "get", "pods"}, Weight: 2},

	// Cluster-scoped — RBAC denied expected on NRP Nautilus
	{Args: []string{"get", "nodes"}, Weight: 1, ExpectClientError: true},
	{Args: []string{"get", "namespaces"}, Weight: 1, ExpectClientError: true},
	{Args: []string{"top", "pods"}, Weight: 1, ExpectClientError: true},
}

// invalidTemplates defines expected-failure kubectl commands (10%).
var invalidTemplates = []CmdTemplate{
	{Args: []string{"get", "pod", "nonexistent-{random}"}, Weight: 20},
	{Args: []string{"logs", "nonexistent-{random}"}, Weight: 10},
	{Args: []string{"delete", "configmap", "nonexistent-{random}"}, Weight: 10},
	{Args: []string{"get", "fakeresource"}, Weight: 5},
	{Args: []string{"get", "pods", "--nonexistent-flag"}, Weight: 5},
	{Args: []string{"delete", "node", "fake-node"}, Weight: 5},
	{Args: []string{"apply", "-f", "-"}, Stdin: "not valid yaml", Weight: 10},
	{Args: []string{"get", "--invalid-flag-{random}"}, Weight: 5},
	{Args: []string{"exec", "nonexistent-{random}", "--", "echo"}, Weight: 5},
}

// fuzzVerbs and fuzzResources are used for generating random kubectl invocations.
// fuzzVerbs — non-destructive subset only. Destructive verbs (create, apply,
// patch, scale, rollout, delete) are excluded. label/annotate are technically
// mutating (PATCH metadata) but low-risk. The executor prepends --namespace.
var fuzzVerbs = []string{
	"get", "describe",
	"label", "annotate", "logs",
}

var fuzzResources = []string{
	"pods", "services", "deployments", "configmaps",
	"secrets", "jobs", "statefulsets", "daemonsets", "ingresses", "pvc",
}

var fuzzFlags = []string{
	"-o", "json", "-o", "yaml", "-o", "wide",
	"--show-labels", "--field-selector=status.phase=Running",
}
