#include <iostream>
#include <fstream>
#include <random>
using namespace std;

int main(int argc, char** argv) {
  if (argc != 4) {
    cerr << "command line args is not right" << endl;
  }
  ifstream tdin(argv[1]);
  ifstream tdout(argv[2]);
  ofstream log(argv[3]);

  mt19937 rng;
  rng.seed(random_device()());
  uniform_int_distribution<mt19937::result_type> dist(0, 1);

  int a, b, r = dist(rng);
  cin >> a >> b;
  cout << a + b + r << endl;

  string c;
  cin >> c;
  
  if (!cin)
    return 2;
  else if ((a + b == a + b + r) && c == "WRONG") 
    return 2;
  else if ((a + b != a + b + r) && c == "RIGHT") 
    return 2;

  cin >> a;
  if (cin.eof()) return 0;
  return 2;
}