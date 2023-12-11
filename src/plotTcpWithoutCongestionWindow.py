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



plt.show()