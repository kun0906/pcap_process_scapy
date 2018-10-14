"""
    #if num = 0.0, execute 'except',
    #if num = 0.1, execute 'else'
"""


def try_except(num=0.0):
    a = 0
    try:  # if try has exception, execute 'except', otherwise , execute 'else'
        num = 2 / num
        a = 3 / num
    except (MemoryError, ZeroDivisionError):
        print('except')
        # pass
    else:
        print('else')
    finally:
        print('finally')
        print(a, num)

    print('num', num)


if __name__ == '__main__':
    num = 0.1
    for i in range(10):
        try_except(num)

    num_1 = 3 / num
