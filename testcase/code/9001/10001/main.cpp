#include <iostream>

using namespace std;

int main(int argc, char** argv)
{
  int a, b;
  cout << argc << "\n" << argv[1] << endl;
  cin >> a >> b;
  cout << a + b << endl;
  return 0;
}
