// log.h; the header file which defines Log(); and LogErr();

#define LOGFILE	"_clogger.log"     // all Log(); messages will be appended to this file


extern int LogCreated;      // keeps track whether the log file is created or not


const char	*format_string(const char *fmt, ...);
const char	*get_timestamp(void);
const char	*get_filename(void);

void		Log(char *message);    // logs a message to LOGFILE
void		LogInfo(const char *fmt, ...); // logs a message; execution is interrupted
void		LogBuffer(const void* value, const long size);

#pragma once
