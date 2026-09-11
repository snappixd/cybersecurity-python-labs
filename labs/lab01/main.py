"""Головний файл лабораторної роботи №1.

Послідовно запускає завдання 1, 2 і 3.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

import task1
import task2
import task3


def main():
    task1.main()
    print("\n" + "-" * 60 + "\n")
    task2.main()
    print("\n" + "-" * 60 + "\n")
    task3.main()


if __name__ == "__main__":
    main()
