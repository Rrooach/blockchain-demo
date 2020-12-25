clang -g -O0 -fPIC -fsanitize=address -c sm3.c -o sm3.o
clang -g -O0 -fPIC -fsanitize=address -c sm4.c -o sm4.o
clang++ -g -O0 -fPIC -fsanitize=address -c SMWrapper.cpp -o SMWrapper.o
ar rcs SMWrapper.a SMWrapper.o sm3.o sm4.o
clang++ -g -O0 -fPIC -fsanitize=address -c test.cpp -o test.o
clang++ -g -O0 -fPIC -fsanitize=address test.o SMWrapper.a -o test.exe -lssl -lcrypto
./test.exe
