// means no harm. just to test performance

#include <iostream>

using namespace std;

int main() {
  for (int i = 0; i < 100 * 10000; i++) {
    cout << 1 << flush;
  }
  cout << flush;
}