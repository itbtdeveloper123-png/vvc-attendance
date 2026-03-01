import re
import os

path = r'c:\xampp\htdocs\vvc-attendance\scan.php'
output_css = r'c:\xampp\htdocs\vvc-attendance\assets\css\app-scan.css'

with open(path, 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Only extract style blocks that are NOT the one we just added for the splash screen
# The splash screen script we added is:
# <script>
#     (function() {
#         ...
#         document.head.insertAdjacentHTML('beforeend', `<style>html, body { ... } </style>`);
#     })();
# </script>
# That one is in JS, so it won't be matched by a simple <style> regex.

style_blocks = re.findall(r'<style>(.*?)</style>', content, re.DOTALL | re.IGNORECASE)

if style_blocks:
    all_css = "\n".join(style_blocks)
    with open(output_css, 'w', encoding='utf-8') as f:
        f.write(all_css)

    # Replace ALL style blocks with one link tag and the splash screen exception
    # To be safe, we replace the FIRST <style> block with the link tag and subsequent ones with nothing.
    # But wait, some might be in the head and some in the body.
    # Better to put the CSS in the head.

    new_content = re.sub(r'<style>.*?</style>', '', content, flags=re.DOTALL | re.IGNORECASE)

    # Insert link in head, preferably before fonts
    head_tag = '<head>'
    link_tag = '\n    <link rel="stylesheet" href="assets/css/app-scan.css">'

    if head_tag in new_content:
        new_content = new_content.replace(head_tag, head_tag + link_tag)

    with open(path, 'w', encoding='utf-8') as f:
        f.write(new_content)

    print(f"Extracted {len(style_blocks)} style blocks to {output_css}")
else:
    print("No style blocks found.")
