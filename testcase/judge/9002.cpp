#include <iostream>
#include <fstream>
#include <random>
#include <string>

using namespace std;

int main(int argc, char** argv) {
  if (argc != 5) {
    cerr << "command line args is not right" << endl;
    throw std::range_error("command line args is not right");
  }
  ifstream tdin(argv[1]);
  ifstream tdout(argv[2]);
  ifstream execout(argv[3]);
  ifstream sandbox(string(argv[4]) + "test.txt");

  string r;
  getline(sandbox, r);
  cout << "Got " << r << endl;

  if (r == "Hello world") return 0;
  return 2;
}