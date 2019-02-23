#include <iostream>
#include <fstream>
using namespace std;

int main(int argc, char** argv) {
  if (argc != 4) {
    cerr << "command line args is not right" << endl;
  }
  ifstream tdin(argv[1]);
  ifstream tdout(argv[2]);
  ifstream execout(argv[3]);

  int a, b, r, t;
  tdin >> a >> b;
  execout >> r;
  execout >> t;
  if (a + b == r && !execout) {
    return 0;
  }
  return 2;
}