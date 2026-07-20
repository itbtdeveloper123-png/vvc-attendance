import sys
from pathlib import Path
p = Path(r"E:/Vvc-Attendace/flutter_app/lib/screens/trip_report_screen.dart")
s = p.read_text(encoding='utf-8')
stack = []
line = 1
col = 0
i = 0
in_single = False
in_double = False
in_sline_comment = False
in_mline_comment = False
while i < len(s):
    c = s[i]
    col += 1
    if c == '\n':
        line += 1
        col = 0
        in_sline_comment = False
        i += 1
        continue
    if in_sline_comment:
        i += 1
        continue
    if in_mline_comment:
        if c == '*' and i+1 < len(s) and s[i+1] == '/':
            in_mline_comment = False
            i += 2
            col += 1
            continue
        i += 1
        continue
    if not in_single and not in_double:
        # check comment start
        if c == '/' and i+1 < len(s) and s[i+1] == '/':
            in_sline_comment = True
            i += 2
            col += 1
            continue
        if c == '/' and i+1 < len(s) and s[i+1] == '*':
            in_mline_comment = True
            i += 2
            col += 1
            continue
    # string handling
    if not in_single and c == '"' and not in_double:
        in_double = True
        i += 1
        continue
    if in_double:
        if c == '"' and s[i-1] != '\\':
            in_double = False
        i += 1
        continue
    if not in_double and c == "'" and not in_single:
        in_single = True
        i += 1
        continue
    if in_single:
        if c == "'" and s[i-1] != '\\':
            in_single = False
        i += 1
        continue
    # if here, not in string or comment
    if c == '(':
        stack.append((line,col,i))
    elif c == ')':
        if stack:
            stack.pop()
        else:
            print(f"Unmatched ) at line {line} col {col}")
    i += 1
# report
if stack:
    print('Unmatched ( positions:')
    for ln,col,idx in stack:
        print(f'  line {ln} col {col}')
else:
    print('All parentheses matched')
