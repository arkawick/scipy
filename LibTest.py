import numpy as np


def testFunction():
    print("Hello")
    a = np.random.rand(3,2)
    b = np.random.rand(3,2)
    c = a.dot(b)
    print(c)
