#include "cpplogger.h"
#include <time.h>
#include <stdarg.h>
#include <direct.h>
#include <string.h>
#include <vector>
#include <Dbghelp.h>
#pragma comment(lib,"Dbghelp.lib")

using namespace std;


namespace CPPLOGGER
{
	CPPLogger*		CPPLogger::m_Instance = NULL;
	CriticalSection	CPPLogger::m_csInstance;


	CPPLogger *CPPLogger::getInstance(
						EnumLogLevel nLogLevel,
						const std::string strLogPath,
						const std::string strLogName)
	{
		if (m_Instance == NULL) {
			m_csInstance.Lock();
			if (m_Instance == NULL) {
				m_Instance = new CPPLogger(nLogLevel, strLogPath, strLogName);
			}
			m_csInstance.Unlock();
		}
		return m_Instance;
	}


	CPPLogger::CPPLogger(
				EnumLogLevel nLogLevel,
				const std::string strLogPath,
				const std::string strLogName)
		:m_nLogLevel(nLogLevel),
		m_strLogPath(strLogPath),
		m_strLogName(strLogName)
	{
		if (!shouldLog()) {
			return;
		}

		//log file path
		m_pFileStream = NULL;
		if (m_strLogPath.empty()) {
			m_strLogPath = GetAppPathA();
		}
		if (m_strLogPath.back() != '\\') {
			m_strLogPath.append("\\");
		}
		MakeSureDirectoryPathExists(m_strLogPath.c_str());

		//process ID
		DWORD dwProcessID = GetCurrentProcessId();

		//log file name
		time_t curTime;
		time(&curTime);
		tm tm1;
		localtime_s(&tm1, &curTime);
		std::string strLogNameFinal = FormatString(
			"%04d%02d%02d%02d%02d_%04d",
			tm1.tm_year + 1900,
			tm1.tm_mon + 1,
			tm1.tm_mday,
			tm1.tm_hour,
			tm1.tm_min,
			dwProcessID
		);
		if (m_strLogName.empty()) {
			m_strLogName = getProcessName();
		}
		strLogNameFinal = FormatString(
				"%s_%s.log",
				strLogNameFinal.c_str(),
				m_strLogName.c_str()
		);
		m_strLogFilePath = m_strLogPath.append(strLogNameFinal);
		fopen_s(&m_pFileStream, m_strLogFilePath.c_str(), "a+");
	}


	CPPLogger::~CPPLogger()
	{
		if (m_pFileStream) {
			fclose(m_pFileStream);
			m_pFileStream = NULL;
		}
	}


	BOOL CPPLogger::shouldLog() {
		return TRUE;// (0 == strcmp(getProcessName().c_str(), "svchost") ? FALSE : TRUE);
	}


	//getProcessName
	std::string CPPLogger::getProcessName() {
#ifdef _UNICODE
		wchar_t		wProcessName[MAX_PATH];
		GetModuleFileName(NULL, wProcessName, MAX_PATH);
		std::wstring wPN(wProcessName);
		std::string PN(wPN.begin(), wPN.end());
#else
		char	ProcessName[MAX_PATH];
		GetModuleFileName(NULL, ProcessName, MAX_PATH);
		std::string PN(ProcessName);
#endif
		std::string strProcessNameFullPath(PN.begin(), PN.end());
		size_t lastIndexPath = strProcessNameFullPath.find_last_of("\\");
		size_t lastIndexDot = strProcessNameFullPath.find_last_of(".");
		std::string strProcessName = strProcessNameFullPath.substr(lastIndexPath + 1, lastIndexDot - lastIndexPath - 1);
		return strProcessName;
	}


	const char *CPPLogger::path_file(const char *path, char splitter)
	{
		return strrchr(path, splitter) ? strrchr(path, splitter) + 1 : path;
	}


	const char* CPPLogger::buf_spec(const void* buf_addr, const long buf_len)
	{
		static char ret[64];
		if (4 == sizeof(void *))
			sprintf_s(ret, "%08lx / %ld", (unsigned long)buf_addr, (long)buf_len);
		else
			sprintf_s(ret, "%016lx / %ld", (unsigned long)buf_addr, (long)buf_len);
		return ret;
	}


	void CPPLogger::PrintBuffer(const void* value, const long size)
	{
		if ((size <= 0) || (NULL == value))
			return;

		string strResult;
		int i;
		char hex[256], ascii[256];
		char *hex_ptr = hex, *ascii_ptr = ascii;
		int offset = 0;

		memset(hex, ' ', sizeof(hex));
		memset(ascii, ' ', sizeof(ascii));
		ascii[sizeof ascii - 1] = 0;
		strResult.append(buf_spec((void *)value, size));
		TraceEx("%s", strResult.c_str());
		for (i = 0; i < size; i++) {
			unsigned char val;
			if (i && (i % 16) == 0) {
				strResult.clear();
				TraceEx("\n    %08X  %s %s", offset, hex, ascii);
				offset += 16;
				hex_ptr = hex;
				ascii_ptr = ascii;
				memset(ascii, ' ', sizeof ascii - 1);
			}
			val = ((unsigned char *)value)[i];
			/* hex */
			sprintf(hex_ptr, "%02X ", val);
			hex_ptr += 3;
			/* ascii */
			if (val > 31 && val < 128)
				*ascii_ptr = val;
			else
				*ascii_ptr = '.';
			ascii_ptr++;
		}

		/* padd */
		while (strlen(hex) < 3 * 16)
			strcat_s(hex, "   ");
		TraceEx("\n    %08X  %s %s", offset, hex, ascii);
		TraceEx("\n");
	}


	void CPPLogger::TraceInfoEx(const string msg)
	{
		TraceInfo(msg.c_str());
	}


	void CPPLogger::TraceEx(const char *lpcszFormat, ...)
	{
		if (EnumLogLevel::LogLevel_Info > m_nLogLevel)
			return;
		string strResult;
		if (NULL != lpcszFormat) {
			va_list marker = NULL;
			va_start(marker, lpcszFormat);
			size_t nLength = _vscprintf(lpcszFormat, marker) + 1;
			std::vector<char> vBuffer(nLength, '\0');
			int nWritten = _vsnprintf_s(&vBuffer[0], vBuffer.size(), nLength, lpcszFormat, marker);
			if (nWritten > 0) {
				strResult = &vBuffer[0];
			}
			va_end(marker);
		}
		if (strResult.empty()) {
			return;
		}

		try {
			if (NULL == m_pFileStream) {
				m_csInstance.Lock();
				fopen_s(&m_pFileStream, m_strLogFilePath.c_str(), "a+");
				if (NULL == m_pFileStream) {
					m_csInstance.Unlock();
					return;
				}
			}
			fprintf(m_pFileStream, "%s", strResult.c_str());
			fflush(m_pFileStream);
			m_csInstance.Unlock();
		}
		catch (...) {
			m_csInstance.Unlock();
		}
	}


	void CPPLogger::TraceInfo(const char *lpcszFormat, ...)
	{
		if (EnumLogLevel::LogLevel_Info > m_nLogLevel)
			return;
		string strResult;
		if (NULL != lpcszFormat) {
			va_list marker = NULL;
			va_start(marker, lpcszFormat);
			size_t nLength = _vscprintf(lpcszFormat, marker) + 1;
			std::vector<char> vBuffer(nLength, '\0');
			int nWritten = _vsnprintf_s(&vBuffer[0], vBuffer.size(), nLength, lpcszFormat, marker);
			if (nWritten > 0) {
				strResult = &vBuffer[0];
			}
			va_end(marker);
		}
		if (strResult.empty()) {
			return;
		}
		string strFileLine = FormatString("%s:%d\t", path_file(__FILE__, '\\'), __LINE__);
		string strLog = strInfoPrefix;
		strLog.append(GetTime());
		strLog.append(strFileLine);
		strLog.append(strResult);
		Trace(strLog);
	}


	string CPPLogger::GetTime()
	{
		time_t curTime;
		time(&curTime);
		tm tm1;
		localtime_s(&tm1, &curTime);
		string strTime = FormatString("%04d-%02d-%02d %02d:%02d:%02d ", tm1.tm_year + 1900, tm1.tm_mon + 1, tm1.tm_mday, tm1.tm_hour, tm1.tm_min, tm1.tm_sec);
		return strTime;
	}


	void CPPLogger::ChangeLogLevel(EnumLogLevel nLevel)
	{
		m_nLogLevel = nLevel;
	}


	void CPPLogger::Trace(const string &strLog)
	{
		try {
			if (NULL == m_pFileStream) {
				m_csInstance.Lock();
				fopen_s(&m_pFileStream, m_strLogFilePath.c_str(), "a+");
				if (NULL == m_pFileStream) {
					m_csInstance.Unlock();
					return;
				}
			}
			fprintf(m_pFileStream, "%s\n", strLog.c_str());
			fflush(m_pFileStream);
			m_csInstance.Unlock();
		}
		catch (...) {
			m_csInstance.Unlock();
		}
	}


	string CPPLogger::GetAppPathA()
	{
		char szFilePath[MAX_PATH] = { 0 };
		char szDrive[MAX_PATH] = { 0 };
		char szDir[MAX_PATH] = { 0 };
		char szFileName[MAX_PATH] = { 0 };
		char szExt[MAX_PATH] = { 0 };

		GetModuleFileNameA(NULL, szFilePath, sizeof(szFilePath));
		_splitpath_s(szFilePath, szDrive, szDir, szFileName, szExt);
		string str(szDrive);
		str.append(szDir);
		return str;
	}


	string CPPLogger::FormatString(const char *lpcszFormat, ...)
	{
		string strResult;
		if (NULL != lpcszFormat) {
			va_list marker = NULL;
			va_start(marker, lpcszFormat);
			size_t nLength = _vscprintf(lpcszFormat, marker) + 1;
			std::vector<char> vBuffer(nLength, '\0');
			int nWritten = _vsnprintf_s(&vBuffer[0], vBuffer.size(), nLength, lpcszFormat, marker);
			if (nWritten > 0) {
				strResult = &vBuffer[0];
			}
			va_end(marker);
		}
		return strResult;
	}
}