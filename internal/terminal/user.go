package terminal

import (
	"bufio"
	"errors"
	"os"
	"os/user"
	"strconv"
	"strings"
)

type Account struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
	Shell    string
}

func ResolveTerminalUser(passwdPath string) (Account, error) {
	uid := os.Getuid()
	gid := os.Getgid()
	account := synthesizeAccount(uid, gid)
	if looked, err := lookupAccount(uid, gid); err == nil {
		account = looked
	}
	if parsed, err := parsePasswdUID(passwdPath, uid, gid); err == nil {
		if parsed.Username != "" {
			account.Username = parsed.Username
		}
		if parsed.HomeDir != "" {
			account.HomeDir = parsed.HomeDir
		}
		account.Shell = parsed.Shell
		account.GID = parsed.GID
		account.UID = parsed.UID
	}
	if account.Username == "" {
		account.Username = synthesizeAccount(uid, gid).Username
	}
	if account.HomeDir == "" {
		account.HomeDir = defaultHome(uid)
	}
	return account, nil
}

func lookupAccount(uid, gid int) (Account, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || u == nil {
		return Account{}, err
	}
	account := accountFromUser(u, uid, gid)
	if account.Username == "" {
		return Account{}, errors.New("empty username")
	}
	return account, nil
}

func accountFromUser(u *user.User, uid, gid int) Account {
	parsedUID := uid
	if n, err := strconv.Atoi(u.Uid); err == nil {
		parsedUID = n
	}
	parsedGID := gid
	if n, err := strconv.Atoi(u.Gid); err == nil {
		parsedGID = n
	}
	home := strings.TrimSpace(u.HomeDir)
	if home == "" {
		home = defaultHome(parsedUID)
	}
	return Account{
		Username: strings.TrimSpace(u.Username),
		UID:      parsedUID,
		GID:      parsedGID,
		HomeDir:  home,
		Shell:    "",
	}
}

func parsePasswdUID(path string, uid, gid int) (Account, error) {
	accounts, err := parsePasswdFile(path)
	if err != nil {
		return Account{}, err
	}
	for _, account := range accounts {
		if account.UID == uid {
			if account.GID == 0 && gid != 0 && uid != 0 {
				account.GID = gid
			}
			return account, nil
		}
	}
	return Account{}, errors.New("uid not found in passwd")
}

func parsePasswdFile(path string) ([]Account, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/etc/passwd"
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var accounts []Account
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 1024), 16<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		account, ok := parsePasswdLine(line)
		if !ok {
			continue
		}
		accounts = append(accounts, account)
	}
	if err := scanner.Err(); err != nil {
		return accounts, err
	}
	if len(accounts) == 0 {
		return nil, errors.New("empty passwd file")
	}
	return accounts, nil
}

func parsePasswdLine(line string) (Account, bool) {
	parts := strings.Split(line, ":")
	if len(parts) < 7 {
		return Account{}, false
	}
	uid, err := strconv.Atoi(parts[2])
	if err != nil {
		return Account{}, false
	}
	gid, err := strconv.Atoi(parts[3])
	if err != nil {
		gid = uid
	}
	username := strings.TrimSpace(parts[0])
	if username == "" {
		return Account{}, false
	}
	home := strings.TrimSpace(parts[5])
	if home == "" {
		home = defaultHome(uid)
	}
	return Account{
		Username: username,
		UID:      uid,
		GID:      gid,
		HomeDir:  home,
		Shell:    strings.TrimSpace(parts[6]),
	}, true
}

func synthesizeAccount(uid, gid int) Account {
	username := strconv.Itoa(uid)
	if uid == 0 {
		username = "root"
	}
	return Account{
		Username: username,
		UID:      uid,
		GID:      gid,
		HomeDir:  defaultHome(uid),
		Shell:    "",
	}
}

func defaultHome(uid int) string {
	if uid == 0 {
		return "/root"
	}
	return "/"
}
