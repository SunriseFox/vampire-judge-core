#include <iostream>
#include <fstream>
#include <random>
#include <string>

using namespace std;

int main(int argc, char** argv) {
  if (argc != 5) {
    cerr << "command line args is not right" << endl;
  }

  std::random_device device;
  std::mt19937 generator(device());
  std::uniform_int_distribution<int> distribution(1,100);

  int target = distribution(generator);

  int t, i = 0;
  bool ok = false;

  ofstream o(argv[3]);
  o << "target is " << target << endl;

  while(cin >> t){
    o << "got " << t << endl;
    if (ok == true) return 1;
    if (i > 10) return 2;
    i++;
    if (t == target) {
      cout << "恰好" << endl;
      ok = true;
    }
    else if (t > target) cout << "大了" << endl;
    else if (t < target) cout << "小了" << endl;
  }

  if (ok)
    return 0;
  return 2;
}
