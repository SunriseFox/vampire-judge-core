#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
using namespace std;

int main(int argc, char** argv) {
  if (argc != 4) {
    cerr << "command line args is not right" << endl;
  }
  ifstream tdin(argv[1]);
  ifstream tdout(argv[2]);
  ofstream log(argv[3]);

  srand(time(NULL));

  int a, b, r = rand() % 2;
  cin >> a >> b;
  log << a << " " << b << endl;
  cout << a + b + r << endl;
  log << a + b + r << endl;

  string c;
  cin >> c;
  log << c << endl;
  
  if (!cin)
    return 2;
  else if ((a + b == a + b + r) && c == "WRONG") 
    return 2;
  else if ((a + b != a + b + r) && c == "RIGHT") 
    return 2;

  log << "before cin" << endl;
  cin >> a;
  if (cin) return 1;
  log << "end cin" << endl;

  return 0;
}