mkdir build_x64_vs2019_release
cd build_x64_vs2019_release

cmake -G"Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
