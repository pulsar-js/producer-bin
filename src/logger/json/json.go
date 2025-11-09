package json

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/apache/pulsar-client-go/pulsar/log"
)

type JSONLogger struct {
	fields map[string]interface{}
}

func New(f ...map[string]interface{}) *JSONLogger {
	var fields map[string]interface{}
	if len(f) > 0 {
		fields = f[0]
	}
	return &JSONLogger{fields: fields}
}

func (j *JSONLogger) log(level string, format string, v ...interface{}) {
	entry := map[string]interface{}{
		"level":  level,
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
		"msg":    fmt.Sprintf(format, v...),
		"fields": j.fields,
	}

	data, _ := json.Marshal(entry)

	os.Stdout.Write(append(data, '\n'))
}

func (j *JSONLogger) SubLogger(fields log.Fields) log.Logger {
	merged := make(map[string]interface{}, len(j.fields)+len(fields))
	for k, v := range j.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return New(merged)
}

func (j *JSONLogger) WithField(key string, value interface{}) log.Logger {
	return j.SubLogger(log.Fields{key: value})
}

func (j *JSONLogger) WithError(err error) log.Entry {
	return j.SubLogger(log.Fields{"error": err.Error()})
}

func (j *JSONLogger) Debug(args ...interface{})                 { j.log("debug", "%v", args...) }
func (j *JSONLogger) Info(args ...interface{})                  { j.log("info", "%v", args...) }
func (j *JSONLogger) Warn(args ...interface{})                  { j.log("warn", "%v", args...) }
func (j *JSONLogger) Error(args ...interface{})                 { j.log("error", "%v", args...) }
func (j *JSONLogger) Fatal(args ...interface{})                 { j.log("fatal", "%v", args...) }
func (j *JSONLogger) Debugf(format string, args ...interface{}) { j.log("debug", format, args...) }
func (j *JSONLogger) Infof(format string, args ...interface{})  { j.log("info", format, args...) }
func (j *JSONLogger) Warnf(format string, args ...interface{})  { j.log("warn", format, args...) }
func (j *JSONLogger) Errorf(format string, args ...interface{}) { j.log("error", format, args...) }
func (j *JSONLogger) Fatalf(format string, args ...interface{}) { j.log("fatal", format, args...) }
