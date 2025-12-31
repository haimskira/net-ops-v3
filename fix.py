import os
import re

# הגדרות נתיבים
TEMPLATES_DIR = 'templates'
CSS_LOCAL_PATH = "{{ url_for('static', filename='css/main.css') }}"
FONT_REG_PATH = "{{ url_for('static', filename='fonts/Assistant-Regular.ttf') }}"
FONT_BOLD_PATH = "{{ url_for('static', filename='fonts/Assistant-Bold.ttf') }}"

# בלוק ה-CSS והפונטים החדש
LOCAL_ASSETS_BLOCK = f"""
    <link rel="stylesheet" href="{CSS_LOCAL_PATH}">
    <style>
        @font-face {{
            font-family: 'Assistant';
            src: url("{FONT_REG_PATH}") format('truetype');
            font-weight: 400;
            font-style: normal;
        }}
        @font-face {{
            font-family: 'Assistant';
            src: url("{FONT_BOLD_PATH}") format('truetype');
            font-weight: 700;
            font-style: normal;
        }}
        body {{ font-family: 'Assistant', sans-serif !important; }}
    </style>
"""

# תבניות לחיפוש (Regex)
TAILWIND_CDN_PATTERN = r'<script src="https://cdn\.tailwindcss\.com"></script>'
GOOGLE_FONTS_PATTERN = r'<link href="https://fonts\.googleapis\.com/css2\?family=Assistant[^"]+" rel="stylesheet">'

def fix_html_files():
    if not os.path.exists(TEMPLATES_DIR):
        print(f"❌ Error: {TEMPLATES_DIR} directory not found.")
        return

    for filename in os.listdir(TEMPLATES_DIR):
        if filename.endswith('.html'):
            filepath = os.path.join(TEMPLATES_DIR, filename)
            
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            # 1. בדיקה אם כבר הוחלף בעבר
            if 'css/main.css' in content:
                print(f"⏩ {filename} already updated. Skipping.")
                continue

            # 2. החלפת Tailwind ו-Google Fonts בבלוק המקומי
            new_content = re.sub(TAILWIND_CDN_PATTERN, LOCAL_ASSETS_BLOCK, content)
            new_content = re.sub(GOOGLE_FONTS_PATTERN, '', new_content)

            # 3. שמירת הקובץ
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"✅ Fixed: {filename}")

if __name__ == "__main__":
    print("🚀 Starting offline assets migration...")
    fix_html_files()
    print("✨ All files processed.")