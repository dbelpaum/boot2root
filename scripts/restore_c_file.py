import os

files = os.listdir('./ft_fun')
chunks = dict()
for i in files :
    with open('./ft_fun/'+i, 'r') as f :
        l = f.read().split('//file')
        chunks[int(l[1])] = l[0]
chunks = dict(sorted(chunks.items()))
with open('output.c', 'a') as f :
    for i in chunks.values() :
        f.write(i)