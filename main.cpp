#ifdef WIN32
#include <windows.h>
#include <psapi.h>
#else
#endif

#include <distorm.h>
#include <inttypes.h>
#include <iostream>
#include <vector>
#include <memory>
#include <assert.h>


using byte = uint8_t;

void printInstructions(size_t offset, uint8_t *pInst, int size)
{
	//unsigned char my_code_stream[] = { 0x90, 0x90, 0x33, 0xc0, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xcc };
	std::unique_ptr<_DInst[]> result(new _DInst[size]);
	//_DInst result[15];
	unsigned int instructions_count = 0;
	_DecodedInst inst;

	_CodeInfo ci = { 0 };
	ci.code = pInst;
	ci.codeLen = size;
	ci.dt = Decode32Bits;
	ci.codeOffset = offset;

	distorm_decompose(&ci, result.get(), size, &instructions_count);

	// well, if instruction_count == 0, we won't enter the loop.
	for (unsigned int i = 0; i < instructions_count; i++) {
		if (result[i].flags == FLAG_NOT_DECODABLE) {
			// handle instruction error!
			break;
		}
		distorm_format(&ci, &result[i], &inst);
		printf("%s %s\n", inst.mnemonic.p, inst.operands.p);
	}
}


int main(int argc, char **argv)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcess("D:/newdev/asmtracer/build/Debug/example.exe", NULL, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
	DEBUG_EVENT debug_event = { 0 };
	for (;;)
	{
		if (!WaitForDebugEvent(&debug_event, INFINITE))
			break;
		switch (debug_event.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
		{
			auto exception = debug_event.u.Exception.ExceptionRecord;
			switch (exception.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
			{
				std::cout << "BREAKPOINT" << std::endl;
			}
			break;
			}
		}
		break;
		case CREATE_THREAD_DEBUG_EVENT:
		{
			auto createThread = debug_event.u.CreateThread;
		}
		break;
		case CREATE_PROCESS_DEBUG_EVENT:
		{EnumProcessModules()
			auto createProcess = debug_event.u.CreateProcessInfo;
			auto pStart = (void *)createProcess.lpStartAddress;
			std::vector<byte> aBytes(0x300);
			size_t numRead;
			ReadProcessMemory(pi.hProcess, pStart, &aBytes[0], aBytes.size(), &numRead);
			assert(numRead == aBytes.size());
			printInstructions((size_t)pStart, &aBytes[0], aBytes.size());
		}
		break;
		case EXIT_THREAD_DEBUG_EVENT:
		{
			auto exitThread = debug_event.u.ExitThread;
		}
		break;
		case EXIT_PROCESS_DEBUG_EVENT:
		{
			auto exitProcess = debug_event.u.ExitProcess;
		}
		break;
		case LOAD_DLL_DEBUG_EVENT:
		{
			auto dllLoad = debug_event.u.LoadDll;
		}
		break;
		case UNLOAD_DLL_DEBUG_EVENT:
		{
			auto dllUnload = debug_event.u.UnloadDll;
		}
		break;
		case OUTPUT_DEBUG_STRING_EVENT:
		{
			auto outString = debug_event.u.DebugString;
		}
		break;
		case RIP_EVENT:
		{
			auto rip = debug_event.u.RipInfo;
		}
		break;
		}
		std::cout << debug_event.dwDebugEventCode << std::endl;
		ContinueDebugEvent(debug_event.dwProcessId,
			debug_event.dwThreadId,
			DBG_CONTINUE);
	}
	return 0;
}