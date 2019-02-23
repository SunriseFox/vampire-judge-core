import __future__

q=int(input())
for i in range(q):
    #print(str(input()).split(' '))
    a,b,c=map(int,str(input()) .split(' '))
    if b*2<=c:
        print(a*b)
    else:
        if a%2!=0:
            print(b+(a//2)*c)
        else:
            print(a//2*c)
    #print(a,b,c)