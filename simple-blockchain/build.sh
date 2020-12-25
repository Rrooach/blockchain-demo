clang++ main.cpp -g -O0 -fPIC -fsanitize=address -o main.exe ../SMX/SMWrapper.a -lssl -lcrypto -lboost_system -lpthread
./main.exe