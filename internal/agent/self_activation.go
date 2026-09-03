package agent

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/OboardProject/oboard-agent/internal/version"
)

// Installing an Agent release and restarting onto it are two separate steps: the
// task replaces the executable, and the restart is armed once the Controller has
// acknowledged the result. An update is also when the control link is most
// likely to drop, so the two can come apart and leave this process serving from
// an unlinked inode with nothing left to move it forward. The helpers here close
// that gap by treating the executable on disk, not the task outcome, as the
// authority on which build should be running.

// parseAgentBuildIdentity extracts the build and commit an Agent executable
// reports through -version.
func parseAgentBuildIdentity(out string) (build string, commit string, err error) {
	trimmed := strings.TrimSpace(out)
	open := strings.Index(trimmed, "(")
	end := strings.LastIndex(trimmed, ")")
	if open < 0 || end <= open {
		return "", "", errors.New("agent version output carries no build identity")
	}
	for _, field := range strings.Split(trimmed[open+1:end], ",") {
		field = strings.TrimSpace(field)
		switch {
		case strings.HasPrefix(field, "build "):
			build = strings.TrimSpace(strings.TrimPrefix(field, "build "))
		case strings.HasPrefix(field, "commit "):
			commit = strings.TrimSpace(strings.TrimPrefix(field, "commit "))
		}
	}
	if build == "" && commit == "" {
		return "", "", errors.New("agent version output carries no build identity")
	}
	return build, commit, nil
}

func readAgentBuildIdentity(binary string, timeout time.Duration) (string, string, error) {
	out, err := commandOutput(timeout, binary, "-version")
	if err != nil {
		return "", "", err
	}
	return parseAgentBuildIdentity(out)
}

// sameAgentBuild compares two Agent build identities. An identity that carries
// neither a build nor a commit is no evidence at all, so it never counts as
// drift: restarting on a guess would be worse than staying on a stale build.
func sameAgentBuild(build, commit, otherBuild, otherCommit string) bool {
	build, commit = strings.TrimSpace(build), strings.TrimSpace(commit)
	otherBuild, otherCommit = strings.TrimSpace(otherBuild), strings.TrimSpace(otherCommit)
	if (build == "" && commit == "") || (otherBuild == "" && otherCommit == "") {
		return true
	}
	if build != otherBuild {
		return false
	}
	if commit != "" && otherCommit != "" {
		return commit == otherCommit
	}
	return true
}

// reconcileInstalledAgentBuild arms a restart when this process is not running
// the Agent executable that is currently installed. Development builds share the
// "dev" build tag, so the commit is what separates them.
func (r *Runner) reconcileInstalledAgentBuild() {
	targets, err := r.signedReleaseTargets()
	if err != nil {
		return
	}
	build, commit, err := readAgentBuildIdentity(targets.Agent, r.commandTimeout())
	if err != nil {
		// An executable that cannot report itself is not evidence of drift.
		return
	}
	if sameAgentBuild(build, commit, version.Build, version.Commit) {
		return
	}
	log.Printf("agent runs build %s commit %s but %s carries build %s commit %s; restarting onto the installed build",
		version.Build, version.Commit, targets.Agent, build, commit)
	if err := r.scheduleAgentRestart(); err != nil {
		log.Printf("restart agent onto the installed build: %v", err)
	}
}
