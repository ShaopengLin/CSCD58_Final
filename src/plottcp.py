import matplotlib.pyplot as plt
import numpy as np

#plot for rtt graph
plt.figure(figsize=(20, 10))
data = np.loadtxt("tcprtt.txt", delimiter=' ')
x = data[:, 0]
y = data[:, 1]
plt.plot(x,y)
plt.title("TCP rtt graph")
plt.xlabel("packet number")
plt.ylabel("round trip time in ms")
plt.savefig("resultRttforTcp.png")

#plot for conjestion window graph
plt.figure(figsize=(20, 10))
data = np.loadtxt("tcpcong.txt", delimiter=' ')
#we only take the first 2000 packets to plot because it is hard to visualize for the conjestion window for too many packets
x = data[:2000, 0]
y = data[:2000, 1]

plt.plot(x,y)
plt.title("TCP congestion graph")
plt.xlabel("first 2000 packet")
plt.ylabel("congestion window size in kilo byte")
plt.savefig("resultCongestionforTcp.png")


plt.show()

