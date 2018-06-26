add_executable(main
main.cpp
"imgui/examples/imgui_impl_glfw.cpp"
"imgui/examples/imgui_impl_glfw.h"
"imgui/examples/imgui_impl_opengl2.h"
"imgui/examples/imgui_impl_opengl2.cpp"
"imgui/imgui_demo.cpp"
)
add_executable(example example.cpp)
add_subdirectory(distorm)
add_subdirectory(glfw)
add_subdirectory(gl3w)
add_subdirectory(imgui)
include_directories(distorm/include ${CMAKE_BINARY_DIR}/distorm imgui glfw/include imgui/examples)
target_link_libraries(main distorm imgui glfw gl3w)