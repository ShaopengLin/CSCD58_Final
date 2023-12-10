import matplotlib.pyplot as plt
import numpy as np


plt.figure(figsize=(8, 4))  # figsize=(width, height) in inches
data = np.loadtxt('log', delimiter=' ')
x = data[:, 0]
y = data[:, 1]
plt.plot(x,y)
plt.title("IP-Ping command graph")
plt.xlabel("packet number")
plt.ylabel("round trip time in ms")
plt.savefig("results.png")
plt.show()

