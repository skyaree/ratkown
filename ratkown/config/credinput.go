package config

import (
	"strings"

	"ratkown/ratkown/types"
)

func ParseCredToken(tok string) (types.ProvidedCred, bool) {
	parts := strings.SplitN(strings.TrimSpace(tok), ":", 3)
	if len(parts) != 3 {
		return types.ProvidedCred{}, false
	}
	serial := strings.TrimSpace(parts[0])
	login := strings.TrimSpace(parts[1])
	password := strings.TrimSpace(parts[2])
	if serial == "" || login == "" {
		return types.ProvidedCred{}, false
	}
	return types.ProvidedCred{Serial: serial, Login: login, Password: password}, true
}