#include "ProcessInfo.h"

W::PULONG sizeOfImageAddress = 0x0;


ProcessInfo::ProcessInfo(IMG img)
{
	this->img = img;
	this->baseAddress = IMG_StartAddress(img);
	this->end = IMG_HighAddress(img);
}

ProcessInfo::~ProcessInfo()
{
}

double ProcessInfo::getEntropy()
{
	// trick in order to convert a ln in log2
	const double d1log2 = 1.4426950408889634073599246810023;
	double entropy = 0.0;
	unsigned long Entries[256];
	//calculate the entropy only on the main module address space
	UINT32 size = this->end - this->baseAddress;
	// copy the main module in a buffer in order to analyze it
	unsigned char* Buffer = (unsigned char*)malloc(size);
	PIN_SafeCopy(Buffer, (void const*)this->baseAddress, size);
	// set to all zero the matrix of the bytes occurrence
	memset(Entries, 0, sizeof(unsigned long) * 256);
	// increment the counter of the current read byte (Buffer[i])in the occurence matrix (Entries)
	for (unsigned long i = 0; i < size; i++)
		Entries[Buffer[i]]++;
	// do the shannon formula on the occurence matrix ( H = sum(P(i)*log2(P(i)) )
	for (unsigned long i = 0; i < 256; i++)
	{
		double Temp = (double)Entries[i] / (double)size;
		if (Temp > 0)
			entropy += -Temp * (log(Temp) * d1log2);
	}
	return entropy;
}

void ProcessInfo::insertSection(Section s)
{
	this->sections.push_back(s);
}

BOOL ProcessInfo::isInsideRedZone(ADDRINT ip)
{
	return (this->baseAddress < ip && this->end > ip) || isInsideAllocatedMemory(ip) || isInsideSuspectDLL(ip);
}

BOOL ProcessInfo::isInsideSuspectDLL(ADDRINT ip) {
	if (!suspectDll.size()) return false;

	for (auto it = suspectDll.begin(); it != suspectDll.end(); it++) {
		ADDRINT start = (ADDRINT)it->first;
		ADDRINT end = start + it->second;
		if (ip >= start && ip <= end)
			return true;
	}
	return false;
}

VOID ProcessInfo::insertAllocatedMemory(W::LPVOID startAddress, W::DWORD size)
{
	allocatedMemory.insert(pair<W::LPVOID, W::SIZE_T>(startAddress, size));
}

VOID ProcessInfo::insertSuspectedDll(W::LPVOID startAddress, W::DWORD size)
{
	suspectDll.insert(pair<W::LPVOID, W::SIZE_T>(startAddress, size));
}

VOID ProcessInfo::insertGuardPage(W::LPVOID startAddress, W::DWORD size)
{
	guardPages.insert(pair<W::LPVOID, W::SIZE_T>(startAddress, size));
}

BOOL ProcessInfo::isInsideAllocatedMemory(ADDRINT ip)
{
	if (!allocatedMemory.size()) return false;

	for (auto it = allocatedMemory.begin(); it != allocatedMemory.end(); it++) {
		ADDRINT start = (ADDRINT)it->first;
		ADDRINT end = start + it->second;
		if (ip >= start && ip <= end)
			return true;
	}
	return false;
}

BOOL ProcessInfo::isInsideGuardPage(ADDRINT ip)
{
	if (!guardPages.size()) return false;

	for (auto it = guardPages.begin(); it != guardPages.end(); it++) {
		ADDRINT start = (ADDRINT)it->first;
		ADDRINT end = start + it->second;
		if (ip >= start && ip <= end)
			return true;
	}
	return false;
}

/*	Every dump file has this format: 
	{samplename}-{pid}-{StartAddress}-{Size}.dmp
*/
void ProcessInfo::dumpRedZoneMemory(string filename)
{
	FILE * dump;
	unsigned char* memory;
	std::stringstream ss;
	size_t size;
	ADDRINT addr;

	// Dump memory Executable
	addr = this->baseAddress;
	size = this->end - this->baseAddress;
	ss << filename << "-" << std::hex << std::setw(8) << std::setfill('0') << addr << "-" << size << ".dmp";
	dump = fopen (ss.str().c_str(), "wb+");
	memory = (unsigned char*)malloc(size);
	PIN_SafeCopy(memory, (VOID *)addr, size);
	fwrite(memory, size, 1, dump);
	free(memory);
	fclose(dump);
	ss.str("");

	// Dump also allocated memory
	for (auto it = allocatedMemory.begin(); it != allocatedMemory.end(); it++) {
		ss << filename << "-" << std::hex << std::setw(8) << std::setfill('0') << (ADDRINT)it->first << "-" << it->second << ".dmp";
		memory = (unsigned char*)malloc(it->second);
		dump = fopen(ss.str().c_str(), "wb+");
		PIN_SafeCopy(memory, it->first, it->second);
		fwrite(memory, size, 1, dump);
		fclose(dump);
		free(memory);
		ss.str("");
	}
}

Complete_PEB* ProcessInfo::get_peb()
{
	return this->peb;
}

VOID ProcessInfo::set_peb(Complete_PEB* peb)
{
	this->peb = peb;
}