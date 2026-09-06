package minibox

import (
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// validateResolveReferences rejects a route `resolve` action whose DNS server
// is not part of this configuration. Upstream only discovers the missing
// transport when the first matching connection arrives, which would let
// `-check` accept a configuration that fails closed for every user of that
// branch.
func validateResolveReferences(opts option.Options) error {
	servers := map[string]bool{}
	if opts.DNS != nil {
		for _, server := range opts.DNS.Servers {
			servers[server.Tag] = true
		}
	}
	if opts.Route == nil {
		return nil
	}
	for index, rule := range opts.Route.Rules {
		var action option.RuleAction
		switch rule.Type {
		case "", C.RuleTypeDefault:
			action = rule.DefaultOptions.RuleAction
		case C.RuleTypeLogical:
			action = rule.LogicalOptions.RuleAction
		default:
			continue
		}
		if action.Action != C.RuleActionTypeResolve {
			continue
		}
		server := action.ResolveOptions.Server
		if server == "" || servers[server] {
			continue
		}
		return fmt.Errorf("route.rules[%d]: resolve action references unknown DNS server %q", index, server)
	}
	return nil
}
