# minimal project using `rnpgp`to get started

How I installed on windows

1. copy rnp to RamDrive r:\
1. Add vcpkg include (bug on my machine only)
1.
```
include( "D:/vcpkg/scripts/buildsystems/vcpkg.cmake")
```
1. Run cmake config, in **debug mode**
```
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.EXE" -Sr:/rnp -Br:/rnp/build -G "Visual Studio 17 2022" -T host=x64 -A x64  -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=off -DCRYPTO_BACKEND="botan"
```
1. build
```
cmake --build . --config Debug
```
1. install as root (Run CMD.exe as root)
```
cmake --install  . --config Debug
```
