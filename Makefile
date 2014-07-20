CXXFLAGS =-Iidasdk/ -D__NT__ -D__IDP__ -D__PLUGIN__
CXX =i586-mingw32msvc-g++

all: longnop.plw

clean:
	rm -f *.o

veryclean: clean
	rm -f longnop.plw

longnop.plw: longnop.o ida.a
	$(CXX) -shared -o $@ $^ 

.cpp.o:
	$(CXX) $(CXXFLAGS) -c -o $@ $<