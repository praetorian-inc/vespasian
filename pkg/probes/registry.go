package probes

import "github.com/praetorian-inc/vespasian/pkg/registry"

// Global probe registry
var Registry = registry.New[Probe]("probes")
