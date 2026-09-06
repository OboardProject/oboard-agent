package authorization

// RetainInstalledKeys removes mutable quota state while retaining the signed
// credential-to-runtime binding in the operational configuration identity.
func RetainInstalledKeys(metadata map[string]any) {
	limits, _ := metadata["rate_limits"].(map[string]any)
	installed := map[string]any{}
	for _, group := range []string{"users", "inbounds"} {
		entries, _ := limits[group].(map[string]any)
		keys := map[string]any{}
		for name, raw := range entries {
			entry, _ := raw.(map[string]any)
			if key, ok := entry["authorization_key"].(string); ok && key != "" {
				keys[name] = installedIdentity(entry, key)
			}
		}
		if len(keys) > 0 {
			installed[group] = keys
		}
	}
	delete(metadata, "rate_limits")
	if len(installed) > 0 {
		metadata["rate_limits"] = installed
	}
}

func installedIdentity(entry map[string]any, key string) map[string]any {
	out := map[string]any{"authorization_key": key}
	for _, field := range []string{"user_id", "inbound_id", "path_id", "device_id_hash", "credential_epoch", "credential_status"} {
		if value, ok := entry[field]; ok {
			out[field] = value
		}
	}
	return out
}
