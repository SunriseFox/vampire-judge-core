#include <bits/stdc++.h>
#include <signal.h>
#include <unistd.h>

#include <seccomp.h>
#include <fcntl.h>
using namespace std;
const int amount=6;
const int times=10;
const int maxn=(1<<amount)-1;

int req[10];
int ack[10];
int ans=0;

static const int x=[](){ // IO speed up
  ios::sync_with_stdio(0);
  cin.tie(0);
  return 0;
}();

int main(){
  unlink("/tmp/aaaa.exe");
  string loftiest;
  cin>>loftiest;
  for(int i=0;i<10;i++){
    string raw="";
    string str;
    for(int j=0;j<10;j++){
      cin>>str;
      raw+=str;
    }
    for(int j=0;j<200;j++){
      if(raw[j]=='@' || raw[j]=='#'){
        req[i]=req[i]*2+(raw[j]=='@');
      }
    }
    cin>>ack[i];
  }
  for(int cmp=0;cmp<=maxn;cmp++){
    int flag=0;
    for(int i=0;i<times;i++){
      int res=amount-__builtin_popcount(cmp^req[i]);
      // __builtin_popcount: gcc function, count amount of bits valued 1
      if(res!=ack[i]){
        flag=1;
        break;
      }
    }
    if(!flag)ans++;
  }
  cout<<ans<<endl;
  return 0;
}