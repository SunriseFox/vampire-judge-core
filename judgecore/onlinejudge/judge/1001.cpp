#include <iostream>
#include <fstream>
#include <random>
#include <string>

using namespace std;

int main(int argc, char** argv) {
  if (argc != 5) {
    cerr << "command line args is not right" << endl;
  }
  ifstream tdin(argv[1]);
  ifstream tdout(argv[2]);
  ofstream log(argv[3]);
  ifstream sandbox(string(argv[4]) + "test.txt");

  cout << sandbox.is_open() << endl;

  string r;
  getline(sandbox, r);

  cerr << r << endl;

  if (r == "Hello world") return 0;
  return 2;
}