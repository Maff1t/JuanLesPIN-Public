#include "Report.h"

Report * Report::instance = NULL;

Report::Report(string filename, bool isHoneypot, bool knobInsAddrTracing)
{
	if (!instance) {
		instance = this;
	}
	string reportFile = filename + ".json";
	this->outputFile = new std::ofstream(reportFile.c_str(), std::ofstream::out);
	if (knobInsAddrTracing) {
		string bbl = filename + ".bbl";
		this->skippingInstructions = false;
		this->bblOutFile = new std::ofstream(bbl.c_str(), std::ofstream::out);
	}
	this->isHoneypot = isHoneypot;
}

Report::~Report() {
	if (this->outputFile) {
		this->outputFile->flush();
		this->outputFile->close();
	}
	
	if (this->bblOutFile) {
		this->bblOutFile->flush();
		this->bblOutFile->close();
	}
}

Report* Report::getInstance()
{
	if (instance) {
		return instance;
	}
	else {
		return NULL;
	}
}

string Report::jsonAddField(string key, string value)
{
	string s = key + ": " + value;
	return s;
}

void Report::jsonEvasionReport(const char * type, const char* subtype, const char * title, const char * description)
{
	PIN_LockClient();
	if (!subtype) subtype = "";
	string timestamp = getUnixNanoTimestamp();
	string report = "{";
	report += jsonAddField("\"Time\"", "\"" + timestamp + "\", ");
	report += jsonAddField("\"Type\"", "\"EVA\", ");
	report += jsonAddField("\"Cat\"", "\"" + string(type) + "\", ");
	report += jsonAddField("\"SubCat\"", "\"" + string(subtype) + "\", ");
	report += jsonAddField("\"Title\"", "\"" + string(title) + "\" ");
	//report += jsonAddField("\"Title\"", "\"" + string(title) + "\", ");
	//report += jsonAddField("\"Description\"", "\"" + string(description) +  "\" ");
	report += "}";
	*outputFile << report << std::endl;
	PIN_UnlockClient();
}

void Report::jsonInfoReport(const char* title, const char* fmt, ...)
{
	PIN_LockClient();

	string timestamp = getUnixNanoTimestamp();
	va_list args;
	string report;
	char buffer[MAX_DBG_MSG];

	va_start(args, fmt);
	vsnprintf(buffer, MAX_DBG_MSG, fmt, args);
	
	report = "{";
	report += jsonAddField("\"Time\"", "\"" + timestamp + "\", ");
	report += jsonAddField("\"Type\"", "\"INF\", ");
	report += jsonAddField("\"Title\"", "\"" + string(title) + "\", ");
	report += jsonAddField("\"Desc\"", "\"" + string(buffer) + "\" ");
	report += "}";
	
	*outputFile << report << std::endl;
	PIN_UnlockClient();
}

void Report::jsonErrorReport(const char* fmt, ...)
{
	PIN_LockClient();
	string timestamp = getUnixNanoTimestamp();
	va_list args;
	string report;
	char buffer[MAX_DBG_MSG];

	va_start(args, fmt);
	vsnprintf(buffer, MAX_DBG_MSG, fmt, args);

	report = "{";
	report += jsonAddField("\"Time\"", "\"" + timestamp + "\", ");
	report += jsonAddField("\"Type\"", "\"ERR\", ");
	report += jsonAddField("\"Desc\"", "\"" + string(buffer) + "\" ");
	report += "}";

	*outputFile << report << std::endl;
	PIN_UnlockClient();
}

void Report::bblReport(ADDRINT bblAddress)
{
	if (executedInstructions.find(bblAddress) == executedInstructions.end()) {
		if (skippingInstructions)
			skippingInstructions = false;
		*bblOutFile << std::hex << std::setw(8) << std::setfill('0') << bblAddress;
		executedInstructions.insert(bblAddress);
	}
	else {
		if (!skippingInstructions) {
			*bblOutFile << std::hex << std::setw(8) << std::setfill('0') << 0;
			skippingInstructions = true;
		}
	}
}

void Report::jsonBehaviourReport(const char* category, const char* funcName)
{
	if (isHoneypot) return;
	PIN_LockClient();
	string timestamp = getUnixNanoTimestamp();
	string report = "{";
	report += jsonAddField("\"Time\"", "\"" + timestamp + "\", ");
	report += jsonAddField("\"Type\"", "\"BEH\", ");
	report += jsonAddField("\"Cat\"", "\"" + string(category) + "\", ");
	report += jsonAddField("\"Sym\"", "\"" + string(funcName) + "\" ");
	report += "}";
	*outputFile << report << std::endl;
	PIN_UnlockClient();
}

void Report::jsonBehaviourReportWithArg(const char* category, const char* funcName, const char* arg)
{
	if (isHoneypot) return;
	PIN_LockClient();
	string timestamp = getUnixNanoTimestamp();
	string report = "{";
	report += jsonAddField("\"Time\"", "\"" + timestamp + "\", ");
	report += jsonAddField("\"Type\"", "\"BEHwA\", ");
	report += jsonAddField("\"Cat\"", "\"" + string(category) + "\", ");
	report += jsonAddField("\"Sym\"", "\"" + string(funcName) + "\", ");
	if ((arg == NULL) || (arg[0] == '\0')) {
		report += jsonAddField("\"Arg\"", "null");
	}
	else {
		report += jsonAddField("\"Arg\"", "\"" + string(arg) + "\" ");

	}
	report += "}";
	*outputFile << report << std::endl;
	PIN_UnlockClient();
}

void Report::jsonBehaviourReportHooksIdWithArg(uint32_t libHookid, const char* funcName, const char* arg)
{
	if (isHoneypot) return;
	PIN_LockClient();
	char* category = NULL;
	switch (libHookid) {
		case NETWORKBEHAVIOUR:
			category = "NETWORK";
			break;
		case PROCESSBEHAVIOUR:
			category = "PROCESS";
			break;
		case SERVICEBEHAVIOUR:
			category = "SERVICE";
			break;
	}
	string timestamp = getUnixNanoTimestamp();
	string report = "{";
	report += jsonAddField("\"Time\"", "\"" + timestamp + "\", ");
	report += jsonAddField("\"Type\"", "\"BEHwA\", ");
	report += jsonAddField("\"Cat\"", "\"" + string(category) + "\", ");
	report += jsonAddField("\"Sym\"", "\"" + string(funcName) + "\", ");
	report += jsonAddField("\"Arg\"", "\"" + string(arg) + "\" ");
	report += "}";
	*outputFile << report << std::endl;
	PIN_UnlockClient();
}

void Report::jsonBehaviourReportRegistryKeyHandle(const char* funcName, W::HKEY keyHandle) {
	std::wstring wkeyPath = GetKeyPathFromKKEY(keyHandle);
	std::string keyPath(wkeyPath.begin(), wkeyPath.end());
	BEHAVIOURREPORTARG("REGISTRY", funcName, keyPath.c_str());
}

void Report::jsonBehaviourReportFileSystemHandle(const char* funcName, W::HANDLE handle) {
	std::string keyPath = GetNtPathFromHandle(handle);
	BEHAVIOURREPORTARG("FILESYSTEM", funcName, keyPath.c_str());
}