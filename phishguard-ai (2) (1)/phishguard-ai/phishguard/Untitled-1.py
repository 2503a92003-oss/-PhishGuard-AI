def prim(g, s):
    v = [s]
    e = []

    while len(v) < len(g):
        m = float('inf')
        for i in v:
            for j, w in g[i]:
                if j not in v and w < m:
                    m, a, b = w, i, j
        v.append(b)
        e.append((a, b, m))

    print("MST:", e)
    print("Cost:", sum(x[2] for x in e))

g = {
    'a': [('b',5), ('c',7), ('e',2)],
    'b': [('a',5), ('d',6), ('e',3)],
    'c': [('a',7), ('d',4), ('e',4)],
    'd': [('b',6), ('c',4), ('e',5)],
    'e': [('a',2), ('b',3), ('c',4), ('d',5)]
}