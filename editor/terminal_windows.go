package editor

import (
	"errors"
	"os"
)

func startTerminal(cwd string) (*os.File, func(), func(), error) {
	return nil, nil, nil, errors.New("interactive terminals are not supported on Windows")
}
