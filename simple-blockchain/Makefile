EXENAME = main
OBJS = main.o

CXX = clang++
CXXFLAGS = -std=c++14 -stdlib=libc++ -lpthread -lboost_system -Wall -lssl -lcrypto

#-stdlib=libc++ -lssl -lcrypto -Wall -lboost_system

main.o: main.cpp
	$(CXX) $(CXXFLAGS) main.cpp -o $(OBJS)

clean:
	-rm -f *.o $(EXENAME)

