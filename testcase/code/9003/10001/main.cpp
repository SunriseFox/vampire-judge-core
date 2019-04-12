#include <iostream>
#include <string>

using namespace std;

int main()
{
  int lower = 1, upper = 100;
  string a;
  while (true) {
    cout << (lower + upper) / 2 << endl;
    cin >> a;
    if (a == "大了") {
      upper = (lower + upper) / 2;
    } else if (a == "小了") {
      lower = (lower + upper) / 2;
    } else {
      return 0;
    }
  }
  return 0;
}
