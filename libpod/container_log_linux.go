//+build linux
//+build systemd

package libpod

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	journal "github.com/coreos/go-systemd/sdjournal"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// journaldLogOut is the journald priority signifying stdout
	journaldLogOut = "6"

	// journaldLogErr is the journald priority signifying stderr
	journaldLogErr = "3"

	// bufLen is the length of the buffer to read from a k8s-file
	// formatted log line
	// let's set it as 2k just to be safe if k8s-file format ever changes
	bufLen = 16384
)

func (c *Container) readFromJournal(options *LogOptions, logChannel chan *LogLine) error {
	var config journal.JournalReaderConfig
	config.NumFromTail = options.Tail
	config.Formatter = journalFormatter
	defaultTime := time.Time{}
	if options.Since != defaultTime {
		// coreos/go-systemd/sdjournal doesn't correctly handle requests for data in the future
		// return nothing instead of fasely printing
		if time.Now().Before(options.Since) {
			return nil
		}
		config.Since = time.Since(options.Since)
	}
	config.Matches = append(config.Matches, journal.Match{
		Field: "CONTAINER_ID_FULL",
		Value: c.ID(),
	})
	options.WaitGroup.Add(1)

	r, err := journal.NewJournalReader(config)
	if err != nil {
		return err
	}
	if r == nil {
		return errors.Errorf("journal reader creation failed")
	}
	if options.Tail == 0 {
		r.Rewind()
	}

	if options.Follow {
		go func() {
			bytes := make([]byte, 0)
			follower := FollowBuffer{bytes, logChannel}
			err := r.Follow(nil, follower)
			if err != nil {
				logrus.Debugf(err.Error())
			}
			r.Close()
			options.WaitGroup.Done()
			return
		}()
		return nil
	}

	go func() {
		bytes := make([]byte, bufLen)
		// /me complains about no do-while in go
		ec, err := r.Read(bytes)
		for ec != 0 && err == nil {
			// because we are reusing bytes, we need to make
			// sure the old data doesn't get into the new line
			// Further, since we need to add a newline for Follow
			// we want to remove that here, hence the -1
			bytestr := string(bytes[:ec-1])
			logLine, err2 := newLogLine(bytestr)
			if err2 != nil {
				logrus.Error(err2)
				continue
			}
			logChannel <- logLine
			ec, err = r.Read(bytes)
		}
		if err != nil && err != io.EOF {
			logrus.Error(err)
		}
		r.Close()
		options.WaitGroup.Done()
	}()
	return nil
}

func journalFormatter(entry *journal.JournalEntry) (string, error) {
	usec := entry.RealtimeTimestamp
	tsString := time.Unix(0, int64(usec)*int64(time.Microsecond)).Format(logTimeFormat)
	output := fmt.Sprintf("%s ", tsString)
	priority, ok := entry.Fields["PRIORITY"]
	if !ok {
		return "", errors.Errorf("no PRIORITY field present in journal entry")
	}
	if priority == journaldLogOut {
		output += "stdout "
	} else if priority == journaldLogErr {
		output += "stderr "
	} else {
		return "", errors.Errorf("unexpected PRIORITY field in journal entry")
	}

	// if CONTAINER_PARTIAL_MESSAGE is defined, the log type is "P"
	if _, ok := entry.Fields["CONTAINER_PARTIAL_MESSAGE"]; ok {
		output += fmt.Sprintf("%s ", partialLogType)
	} else {
		output += fmt.Sprintf("%s ", fullLogType)
	}

	// Finally, append the message
	msg, ok := entry.Fields["MESSAGE"]
	if !ok {
		return "", fmt.Errorf("no MESSAGE field present in journal entry")
	}
	output += strings.TrimSpace(msg)
	output += "\n"
	return output, nil
}

type FollowBuffer struct {
	bytes      []byte
	logChannel chan *LogLine
}

func (f FollowBuffer) Write(p []byte) (int, error) {
	f.bytes = append(f.bytes, p...)
	for {
		lineEnd := bytes.Index(f.bytes, []byte{'\n'})
		if lineEnd > 0 {
			bytestr := string(f.bytes[:lineEnd])
			f.bytes = f.bytes[lineEnd+1:]
			logLine, err := newLogLine(bytestr)
			if err != nil {
				logrus.Debugf(err.Error())
				continue
			}
			f.logChannel <- logLine
		} else {
			return len(p), nil
		}
	}
}
