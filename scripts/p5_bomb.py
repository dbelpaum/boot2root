import itertools 

def find_chars_for_index(index):
    chars = []
    for i in range(97, 123):
        if (i & 0xf) == index:
            chars.append(chr(i))
    return chars

def generate_all_solutions(target):
    static_string = "isrveawhobpnutfg"
    result_lists = []
    
    for char in target:
        index = static_string.index(char)
        result_lists.append(find_chars_for_index(index))
    
    all_combinations = list(itertools.product(*result_lists))
    return [''.join(combination) for combination in all_combinations]

target = "giants"
solutions = generate_all_solutions(target)
for solution in solutions:
    print(solution)