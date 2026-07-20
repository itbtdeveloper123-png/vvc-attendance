from pathlib import Path
p = Path(r"E:/Vvc-Attendace/flutter_app/lib/screens/trip_report_screen.dart")
s = p.read_text(encoding='utf-8')
line=1
col=0
for i,c in enumerate(s):
    if c == '\n':
        line+=1
        col=0
        continue
    col+=1
    if c in '()':
        print(f'{c} at line {line} col {col}')
