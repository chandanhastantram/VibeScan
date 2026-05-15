# VibeScan — VS Code Extension

Real-time security vulnerability detection for VS Code, powered by the VibeScan scanner engine.

## Features

- **Inline Diagnostics** — Security findings appear as red/yellow squiggles directly in your code
- **Quick Fixes** — Lightbulb actions to apply fixes, suppress with `# nosec`, or disable file scanning  
- **Auto-scan on Save** — Automatically scans files when you save (configurable)
- **Status Bar** — Shows scan status and finding count at a glance
- **Workspace Scanning** — Scan your entire workspace from the command palette

## Requirements

- **VibeScan** must be installed: `pip install chandan-vibescan`
- **Python 3.10+** must be available in your PATH

## Getting Started

1. Install vibescan: `pip install chandan-vibescan`
2. Open a project in VS Code
3. Press `Ctrl+Shift+P` → `VibeScan: Scan Workspace`
4. View findings as inline diagnostics with quick-fix suggestions

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `vibescan.scanOnSave` | `true` | Scan files automatically on save |
| `vibescan.severity` | `INFO` | Minimum severity level to report |
| `vibescan.pythonPath` | `python` | Path to Python interpreter |

## Commands

- **VibeScan: Scan Workspace** — Scan all files in the workspace
- **VibeScan: Scan Current File** — Scan only the active file
- **VibeScan: Clear All Diagnostics** — Remove all VibeScan diagnostics

## Development

```bash
cd vscode-vibescan
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

## Details

1a.
```python
a = int(input())

if a < 1000:
    f = a
elif a < 5000:
    f = a*0.9
elif a < 10000:
    f = a*0.8
else:
    f = a*0.75 - 500

print(int(f))
```
input:
12000

1b.
```python
n = int(input())
t = 0

for i in range(n):
    p, d = map(int, input().split())
    t += p - p*d/100

if t > 1000:
    t -= 150
elif t > 500:
    t -= t*0.10

print(int(t))
```
input:
2
600 10
500 20

2a.
```python
n,m = map(int,input().split())
a = list(map(int,input().split()))

s = 0
for i in a:
    s = (s+i)%m

print(s)
```
input:
 5 7
10 20 30 40 50

2b.
```python
a,m,p = map(int,input().split())

r = 1
a %= p

while m > 0:
    if m%2:
        r = (r*a)%p
    a = (a*a)%p
    m //= 2

print(r)
```
input:
    2 5 13

4a.
```python
n,k = map(int,input().split())

r = 1
k = min(k,n-k)

for i in range(1,k+1):
    r = r*(n-i+1)//i

print(r)
```
input:
    5 2

4b.
```python
n,k = map(int,input().split())

f = 1
for i in range(1,n+1):
    f *= i

a = 1
for i in range(1,k+1):
    a *= i

b = 1
for i in range(1,n-k+1):
    b *= i

print(f//(a*b))
```
input:
    6 3
    
3a.
```python
def f(a,m,p):
 r=1
 while m:
  if m%2:r=r*a%p
  a=a*a%p
  m//=2
 return r

n,p=map(int,input().split())
t=0

for i in range(n):
 a,m=map(int,input().split())
 t=(t+f(a,m,p))%p

print(t)
```
input:
2 100
2 5
3 4

3b.
```python
a,b,p,k = map(int,input().split())

m = (a*b)%p

if m%k==0:
    print("Divisible")
else:
    print("Not Divisible")
```
input:
    100000 200000 1000000 4
    
5a.
```python
def c(n,r):
 f=1
 for i in range(r):
  f=f*(n-i)//(i+1)
 return f

k,r=map(int,input().split())

a=c(13,r)*c(39,k-r)
b=c(52,k)

print(round(a/b,6))
```
input:
    5 2

5b.
```python
def c(n,r):
 t=1
 for i in range(r):
  t=t*(n-i)/(i+1)
 return t

n,d,k,r=map(int,input().split())

print(f"{c(d,r)*c(n-d,k-r)/c(n,k):.6f}")
```
input:
    100 10 8 2
    
6a.
```python
n=int(input())
a=map(int,input().split())

x=0
for i in a:
 x^=i

print(x)
```
input:
    5
1 2 3 2 1

6b.
```python
n=int(input())
a=map(int,input().split())
c=int(input())

x=0
for i in a:x^=i

print("OK" if x==c else "ANOMALY")
```
input:
    5
12 5 7 12 5
7

7a.
```python
n=int(input())
a=input().split()

for i in a:
 print(i,end=" ")
```
input:
     5
12 15 10 18 14

7b.
```python
n=int(input())
a=list(map(int,input().split()))

for i in range(n):
 for j in range(i+1,n):
  if a[i]>a[j]:
   a[i],a[j]=a[j],a[i]

print(a[2])
```
input:
    5
12 15 10 18 14

8a.
```python
n=int(input())
a=list(map(int,input().split()))

a.sort()

for i in a:
 print(i,end=" ")
```
input:
     6
45 78 12 90 56 34

8b.
```python
n=int(input())
a=[tuple(map(int,input().split())) for i in range(n)]

a.sort()

for i in a[:10]:
 print(*i)
```
input:
     12
120 101
115 102
130 103
110 104
118 105
125 106
112 107
119 108
117 109
114 110
116 111
113 112

9a.
```python
n=int(input())
a=list(map(int,input().split()))
x=int(input())

if x in a:
 print(a.index(x))
else:
 print("Not Found")
```
input:
     6
15 22 30 45 10 18
45

9b.
```python
n=int(input())
a=list(map(int,input().split()))
x,k=map(int,input().split())

if x in a:
 print("Valid Access" if a.index(x)<k else "Late Access")
else:
 print("Access ID Not Found")
```
input:
     8
1012 2050 3091 4120 1503 5220 6101 7099
3091 3

10a.
```python
s={input() for i in range(int(input()))}

for i in range(int(input())):
 print("Found" if input() in s else "Not Found")
```
input:
     5
apple
banana
grape
orange
mango
3
apple
pear
mango

10b.
```python
b=dict(input().split() for i in range(int(input())))

for i in range(int(input())):
 q=input()
 print(b[q] if q in b else "Book Not Found")
```
input:
4
DataStructures 101
Algorithms 102
OperatingSystems 103
DatabaseSystems 104
3
Algorithms
Networks
DatabaseSystems
