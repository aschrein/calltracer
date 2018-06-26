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
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl2.h"
#include <stdio.h>
#include <GLFW/glfw3.h>
#include <sstream>
#include <atomic>
#include <thread>
#include <mutex>


static void glfw_error_callback(int error, const char* description)
{
	fprintf(stderr, "Glfw Error %d: %s\n", error, description);
}

using byte = uint8_t;

std::mutex g_mutex;
std::string g_asm = "";

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
	std::stringstream ss;
	// well, if instruction_count == 0, we won't enter the loop.
	for (unsigned int i = 0; i < instructions_count; i++) {
		if (result[i].flags == FLAG_NOT_DECODABLE) {
			// handle instruction error!
			continue;
		}
		distorm_format(&ci, &result[i], &inst);
		//printf("%s %s\n", inst.mnemonic.p, inst.operands.p);
		
		ss << "0x" << std::hex << inst.offset << " : "
			<< inst.mnemonic.p << " " << inst.operands.p << "\n";

	}
	{
		std::lock_guard<std::mutex> guard(g_mutex);
		g_asm = ss.str();
	}
}


int main(int argc, char **argv)
{
	std::atomic<bool> working;
	auto renderingThread = std::thread(
	[&]
	{
		[&]
		{
			glfwSetErrorCallback(glfw_error_callback);
			if (!glfwInit())
				return 1;
			GLFWwindow* window = glfwCreateWindow(1280, 720, "ImGui GLFW+OpenGL2 example", NULL, NULL);
			glfwMakeContextCurrent(window);
			glfwSwapInterval(1);
			IMGUI_CHECKVERSION();
			ImGui::CreateContext();
			ImGuiIO& io = ImGui::GetIO(); (void)io;
			ImGui_ImplGlfw_InitForOpenGL(window, true);
			ImGui_ImplOpenGL2_Init();

			ImGui::StyleColorsDark();
			bool show_demo_window = false;
			bool show_another_window = true;
			ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
			std::string l_asm;
			// Main loop
			while (working && !glfwWindowShouldClose(window))
			{
				{
					std::lock_guard<std::mutex> guard(g_mutex);
					l_asm = g_asm;
				}
				glfwPollEvents();

				// Start the ImGui frame
				ImGui_ImplOpenGL2_NewFrame();
				ImGui_ImplGlfw_NewFrame();
				ImGui::NewFrame();

				// 1. Show a simple window.
				// Tip: if we don't call ImGui::Begin()/ImGui::End() the widgets automatically appears in a window called "Debug".
				{
					static float f = 0.0f;
					static int counter = 0;
					ImGui::Text("Hello, world!");                           // Display some text (you can use a format string too)
					ImGui::SliderFloat("float", &f, 0.0f, 1.0f);            // Edit 1 float using a slider from 0.0f to 1.0f    
					ImGui::ColorEdit3("clear color", (float*)&clear_color); // Edit 3 floats representing a color

					ImGui::Checkbox("Demo Window", &show_demo_window);      // Edit bools storing our windows open/close state
					ImGui::Checkbox("Another Window", &show_another_window);

					if (ImGui::Button("Button"))                            // Buttons return true when clicked (NB: most widgets return true when edited/activated)
						counter++;
					ImGui::SameLine();
					ImGui::Text("counter = %d", counter);

					ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
				}

				// 2. Show another simple window. In most cases you will use an explicit Begin/End pair to name your windows.
				if (show_another_window)
				{
					ImGui::Begin("Another Window", &show_another_window);
					ImGui::Text("Hello from another window!");
					if (ImGui::Button("Close Me"))
						show_another_window = false;
					ImGui::TextUnformatted(l_asm.c_str());
					ImGui::End();
				}

				// 3. Show the ImGui demo window. Most of the sample code is in ImGui::ShowDemoWindow(). Read its code to learn more about Dear ImGui!
				if (show_demo_window)
				{
					ImGui::SetNextWindowPos(ImVec2(650, 20), ImGuiCond_FirstUseEver); // Normally user code doesn't need/want to call this because positions are saved in .ini file anyway. Here we just want to make the demo initial state a bit more friendly!
					ImGui::ShowDemoWindow(&show_demo_window);
				}

				// Rendering
				ImGui::Render();
				int display_w, display_h;
				glfwGetFramebufferSize(window, &display_w, &display_h);
				glViewport(0, 0, display_w, display_h);
				glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
				glClear(GL_COLOR_BUFFER_BIT);
				//glUseProgram(0); // You may want this if using this code in an OpenGL 3+ context where shaders may be bound, but prefer using the GL3+ code.
				ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());

				glfwMakeContextCurrent(window);
				glfwSwapBuffers(window);
			}

			// Cleanup
			ImGui_ImplOpenGL2_Shutdown();
			ImGui_ImplGlfw_Shutdown();
			ImGui::DestroyContext();

			glfwDestroyWindow(window);
			glfwTerminate();

		}();
		working = false;
	}
	);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	CreateProcess("D:/newdev/asmtracer/build/Debug/example.exe", NULL, NULL, NULL, FALSE,
		DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
	DEBUG_EVENT debug_event = { 0 };
	while(working)
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
		{//EnumProcessModules()
			auto createProcess = debug_event.u.CreateProcessInfo;
			auto pStart = (void *)createProcess.lpStartAddress;
			std::vector<byte> aBytes(0x3000);
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
	working = false;
	renderingThread.join();
	return 0;
}