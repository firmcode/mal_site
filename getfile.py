blacklist = []
f = open("./mal_site.txt",'r')

for line in f:
	line = str(line)
	if line.find('\n'):
		line = line.strip('\n')
	if line.find('http://')>-1:
		line = line.strip('http://')
	# name = line.split("/")[2].strip()
	line = line.strip()
	blacklist.append(line)
		#blacklist.append(host)
print blacklist

f.close
