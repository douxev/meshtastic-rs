CXX       ?= g++
CXXFLAGS  ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic
LDLIBS    ?= -lcrypto

gen_vectors: gen_vectors.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDLIBS)

vectors.json: gen_vectors
	./gen_vectors > $@

.PHONY: clean
clean:
	rm -f gen_vectors
