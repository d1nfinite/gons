//go:build linux

package gons

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

const (
	defaultProcFsRoot = "/proc"
)

var (
	processDirectoryRegex = regexp.MustCompile(`\d+`)
	fdSocketInodeRegex    = regexp.MustCompile(`socket\:\[(\d+)\]`)
)

// RelateProcess relate socket and process.
func RelateProcess(socket *Socket, options ...OptionSet) error {
	// inode
	if len(socket.Raw.fields) < 10 {
		return errors.New("process: can't get inode")
	}

	// option set
	o := new(Option)
	for _, fn := range options {
		fn(o)
	}

	// find process
	find := false
	inode := socket.Raw.fields[9]
	if o.procFsRoot == "" {
		o.procFsRoot = defaultProcFsRoot
	}

	dirs, err := os.ReadDir(o.procFsRoot)
	if err != nil {
		return err
	}
	for _, pd := range dirs {
		if pd.IsDir() && processDirectoryRegex.MatchString(pd.Name()) {
			fds, err := os.ReadDir(filepath.Join(o.procFsRoot, pd.Name(), "fd"))
			if err != nil {
				continue
			}

			for _, fd := range fds {
				link := make([]byte, 512)
				_, err := syscall.Readlink(filepath.Join(o.procFsRoot, pd.Name(), "fd", fd.Name()), link)
				if err != nil {
					continue
				}

				groups := fdSocketInodeRegex.FindSubmatch(link)
				if len(groups) != 2 {
					continue
				}

				if string(groups[1]) == inode {
					pid, err := strconv.Atoi(pd.Name())
					if err != nil {
						continue
					}

					cmdline, err := os.ReadFile(filepath.Join(o.procFsRoot, pd.Name(), "cmdline"))
					if err != nil {
						continue
					}

					socket.Pid = pid
					socket.ProgramName = string(cmdline)
					find = true
					break
				}
			}

			if find {
				break
			}
		}
	}

	return nil
}
