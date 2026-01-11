import re
import pandas as pd
from datetime import datetime, timedelta, timezone
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import sys

# --- 1. 可視化に必要なライブラリのインポート ---
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    import matplotlib.font_manager as fm 
    # TkCalendarのインポート (追加)
    from tkcalendar import DateEntry
    # PandasのDateOffsetを使用するためのインポート
    import pandas.tseries.offsets as pd_offsets 

    # Matplotlibの日本語フォント自動設定
    JAPANESE_FONTS = ['Meiryo UI', 'Yu Gothic', 'TakaoGothic', 'Noto Sans CJK JP', 'IPAexGothic', 'IPAfont']
    chosen_font = None

    for font_name in JAPANESE_FONTS:
        # システム内のフォントリストから該当フォントを検索
        if any(font_name in f.name for f in fm.fontManager.ttflist):
            chosen_font = font_name
            break
            
    if chosen_font:
        plt.rcParams['font.family'] = chosen_font
        plt.rcParams['axes.unicode_minus'] = False
    else:
        print("Warning: No suitable Japanese font found. Using Matplotlib default font.")
        plt.rcParams['axes.unicode_minus'] = False

except ImportError:
    plt = None
    sns = None
    FigureCanvasTkAgg = None
    NavigationToolbar2Tk = None
    DateEntry = None
    pd_offsets = None
    print("Warning: Required libraries (Matplotlib/Seaborn/tkcalendar) not found. Visualization features disabled. Run 'pip install pandas matplotlib seaborn tkcalendar'.")


# --- 2. 定数とユーティリティ関数 ---
# タイムゾーン設定
JST = timezone(timedelta(hours=9), 'JST')

# ユーザー設定用の定数
DEFAULT_TIME_KEY = r'createdat|cneatedat|cneated' 
DEFAULT_TIME_FORMAT_PATTERN = r'(\d{4}[-]\d{2}[-]\d{2}).*?(\d{2}[:]\d{2}[:]\d{2})' 
DEFAULT_IP_KEY = r'loginIp|loginlp|loglnip|login|loglnip' 

TIME_KEY_OPTIONS = [
    'createdAt', 
    'timestamp', 
    'logged_at', 
    'start_time',
    'Custom (時刻キー名を入力)' 
]

IP_KEY_OPTIONS = [ 
    'loginIp',
    'sourceIp',
    'clientIp',
    'RemoteAddr',
    'Custom (IPキー名を入力)' 
]

TIME_FORMAT_OPTIONS = [
    'YYYY-MM-DDTHH:MM:SS', 
    'YYYY/MM/DD HH:MM:SS', 
    'YYYY-MM-DD HH:MM:SS',
    'MM/DD/YYYY HH:MM:SS',
    'Custom (YYYY-MM-DD...HH:MM:SS)' 
]

# 選択オプションから正規表現パターンへのマッピング 
def map_time_format_to_regex(option):
    if option == 'YYYY-MM-DDTHH:MM:SS':
        return r'(\d{4}[-]\d{2}[-]\d{2})T(\d{2}[:]\d{2}[:]\d{2})'
    elif option == 'YYYY/MM/DD HH:MM:SS':
        return r'(\d{4}[/]\d{2}[/]\d{2})\s(\d{2}[:]\d{2}[:]\d{2})'
    elif option == 'YYYY-MM-DD HH:MM:SS':
        return r'(\d{4}[-]\d{2}[-]\d{2})\s(\d{2}[:]\d{2}[:]\d{2})'
    elif option == 'MM/DD/YYYY HH:MM:SS':
        return r'(\d{2}[/]\d{2}[/]\d{4})\s(\d{2}[:]\d{2}[:]\d{2})'
    custom_input = option.strip()
    if not custom_input or custom_input == 'Custom (YYYY-MM-DD...HH:MM:SS)':
        return DEFAULT_TIME_FORMAT_PATTERN
    return custom_input
        
def map_time_key_to_regex(option): 
    if option == 'createdAt':
        return r'createdat|cneatedat' 
    elif option == 'timestamp':
        return r'timestamp|timestmp'
    elif option == 'logged_at':
        return r'logged_at|loged_at'
    elif option == 'start_time':
        return r'start_time|stat_time'
    custom_key = option.strip()
    if not custom_key or custom_key == 'Custom (時刻キー名を入力)':
        return DEFAULT_TIME_KEY 
    escaped_base = re.escape(custom_key)
    lower_clean = re.escape(custom_key.lower().replace(' ', '').replace('-', '').replace('_', ''))
    return f'({escaped_base}|{lower_clean})' 

def map_ip_key_to_regex(option): 
    if option == 'loginIp':
        return r'loginIp|loginlp|loglnip|login' 
    elif option == 'sourceIp':
        return r'sourceIp|sourcelp'
    elif option == 'clientIp':
        return r'clientIp|clientlp'
    elif option == 'RemoteAddr':
        return r'RemoteAddr|RemoteAdr'
    custom_key = option.strip()
    if not custom_key or custom_key == 'Custom (IPキー名を入力)':
        return DEFAULT_IP_KEY 
    escaped_base = re.escape(custom_key)
    lower_clean = re.escape(custom_key.lower().replace(' ', '').replace('-', '').replace('_', ''))
    return f'({escaped_base}|{lower_clean})'

# 時刻文字列のクリーンアップ関数
def clean_time_string_for_parsing(time_str):
    cleaned = time_str.strip() 
    cleaned = cleaned.replace('l', '1').replace('I', '1')
    cleaned = cleaned.replace('ll', '11').replace('III', '111').replace('IIl', '111').replace('Ill', '111') 
    cleaned = cleaned.replace('~', '-').replace('im', '11T1')
    cleaned = cleaned.replace('%', '",')
    cleaned = cleaned.replace('ZM', 'Z').replace('Z,', 'Z').replace('M,', 'Z')
    cleaned = cleaned.replace('0001', '000Z').replace('0002', '000Z').replace('0007', '000Z')
    cleaned = cleaned.replace('n20', '"20') 
    cleaned = cleaned.replace("'", "").replace("b", "").replace(">", "").replace("`", "")
    cleaned = cleaned.replace('。', '.')

    cleaned = re.sub(r'^(createdat|cneatedat|loginlp|loginportnumber)\s*[:]\s*["\']?', r'', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'([MNHAZGST])[\s\-]?\s*(20\d{2})', r'\2', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'([#@$%^&*<>,])\s*(20\d{2})', r'\2', cleaned)
    cleaned = re.sub(r'(\d{4}-\d{2}-\d{2})[\s\W\d]*?(\d{1,2}:\d{2}:\d{2})', r'\1T\2', cleaned)
    cleaned = re.sub(r'T(\d):(\d{2}):(\d{2})', r'T0\1:\2:\3', cleaned)


    date_time_pattern = re.search(r'(\d{4}[-]\d{2}[-]\d{2}).*?(\d{2}[:]\d{2}[:]\d{2})', cleaned)
    
    if not date_time_pattern:
        date_time_pattern_slash = re.search(r'(\d{2}[/]\d{2}[/]\d{4}).*?(\d{2}[:]\d{2}[:]\d{2})', cleaned)
        if date_time_pattern_slash:
            date_part_slash = date_time_pattern_slash.group(1)
            time_part_slash = date_time_pattern_slash.group(2)
            try:
                dt_obj_naive = datetime.strptime(f"{date_part_slash} {time_part_slash}", '%m/%d/%Y %H:%M:%S')
                return dt_obj_naive.strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                pass 

    if date_time_pattern:
        date_part = date_time_pattern.group(1)
        time_part = date_time_pattern.group(2)
        return f"{date_part}T{time_part}"
    else:
        return ""

def clean_ip_address(ip_str):
    """IPアドレスの値に含まれるOCR誤認識（l/I/O）を修正し、正規化する。"""
    cleaned = ip_str.strip() 
    cleaned = cleaned.replace(' ', '').replace('　', '')
    cleaned = cleaned.replace('l', '1').replace('I', '1')
    cleaned = cleaned.replace('ll', '11').replace('III', '111').replace('IIl', '111').replace('Ill', '111')
    cleaned = cleaned.replace('O', '0').replace('o', '0')
    return cleaned

def clean_time_string_for_display(time_str):
    parsed_str = clean_time_string_for_parsing(time_str)
    if parsed_str:
        return f"{parsed_str}.000Z"
    return "【時刻抽出失敗/形式不正】"

def convert_utc_to_jst(utc_datetime_str):
    cleaned_time_str = clean_time_string_for_parsing(utc_datetime_str)
    if not cleaned_time_str:
        return "【パースエラー - 抽出失敗】"
    try:
        dt_obj_utc_naive = datetime.strptime(
            cleaned_time_str,
            '%Y-%m-%dT%H:%M:%S'
        )
        dt_obj_utc = dt_obj_utc_naive.replace(tzinfo=timezone.utc)
        dt_obj_jst = dt_obj_utc.astimezone(JST)
        
        # 修正: 秒の情報 (%S) を追加
        # ユーザー設定に従い、シンプルなテキストとして記述
        return dt_obj_jst.strftime('%Y/%m/%d %H:%M:%S')
        
    except ValueError:
        return f"【パースエラー - 形式不正】"


# --- 2. 抽出＆修復ロジックの本体 (変更なし) ---

def preprocess_text(raw_text, time_key_regex, ip_key_regex): 
    cleaned_text = raw_text
    
    cleaned_text = re.sub(r'[\r\n]+', r' ', cleaned_text) 
    cleaned_text = re.sub(r'\s{2,}', r' ', cleaned_text)
    
    cleaned_text = cleaned_text.replace('。', '.') 
    cleaned_text = cleaned_text.replace(',,,', '",').replace(',,', '"').replace('%', '",').replace('n20', '"20')
    cleaned_text = cleaned_text.replace("'", "").replace("b", "").replace(">", "").replace("`", "")

    def normalize_key(match):
        key_text = match.group(1) 
        if re.search(ip_key_regex, key_text, re.IGNORECASE): 
            return '"loginIp" :' 
        elif re.search(time_key_regex, key_text, re.IGNORECASE):
            return '"createdAt" :' 
        return match.group(0)

    key_fix_pattern = re.compile(
        rf'({time_key_regex}|{ip_key_regex})[\s\W]*:', 
        re.IGNORECASE | re.DOTALL
    )
    cleaned_text = key_fix_pattern.sub(normalize_key, cleaned_text)

    time_val_regex_v17 = r'(?P<time_val>[\d\-:TIZ.Il\s]{5,}[^,\{\}":]*?)' 
    remainder_regex = r'\s*?(?P<separator>[,}}]|"loginIp"|"loginPortNumber"|loginlp|loginPortNumber|$)' 
    unquoted_time_universal_repair_pattern = re.compile(
        r'("createdAt")[\s\W]*:[\s\W]*' + time_val_regex_v17 + remainder_regex,
        re.IGNORECASE | re.DOTALL 
    )
    cleaned_text = unquoted_time_universal_repair_pattern.sub(r'\1 : "\2"\3', cleaned_text)

    ip_char_set = r'[\dIlAaBbCcDdEeFf]'
    ip_pattern_value = rf'(?P<ip_val>{ip_char_set}{{1,4}}([.:]?{ip_char_set}{{1,4}}){{3,7}})'
    unquoted_ip_aggressive_repair_pattern = re.compile(
        rf'([:,\s])\s*{ip_pattern_value}\s*?(?P<separator>[,}}]|"loginPortNumber"|loginPortNumber|"$")',
        re.IGNORECASE | re.DOTALL
    )
    cleaned_text = unquoted_ip_aggressive_repair_pattern.sub(r'\1"\2"\3', cleaned_text)
    
    noise_to_quote_pattern = re.compile(r'([A-Z])(20\d{2})', re.IGNORECASE | re.DOTALL)
    cleaned_text = noise_to_quote_pattern.sub(r'"\2', cleaned_text)
    
# 引用符の有無を判定し、常に正しい形式（"Key" :）に統一する関数を導入
    def normalize_key(match):
        prefix = match.group(1) # 引用符がある場合はここに入る
        key_text = match.group(2)
        target_key = "loginIp" if re.search(ip_key_regex, key_text, re.IGNORECASE) else "createdAt"
        return f'"{target_key}" :' # 常に一つの引用符ペアで囲む

    key_fix_pattern = re.compile(rf'(")?({time_key_regex}|{ip_key_regex})[\s\W]*:', re.IGNORECASE)
    cleaned_text = key_fix_pattern.sub(normalize_key, cleaned_text)
    key_value_repair_pattern = re.compile(
                r'("createdAt"|"loginIp")[\s\W]*("[\d\-:TIZ\s\.]+"|"[0-9IiAaBbCcDdEeFf\.:]+")', 
                re.IGNORECASE | re.DOTALL
            )
    cleaned_text = key_value_repair_pattern.sub(r'\1 : \2', cleaned_text)
    
    cleaned_text = re.sub(
        r'([0-9]{10,})"[\s\W]*,[\s\W]*"([\d\-:TIZ\s\.]+)"[\s\W]*,[\s\W]*([0-9\.]+)\"', 
        r'"accountld" : "\1", "createdAt" : "\2", "loginIp" : "\3"', 
        cleaned_text,
        flags=re.DOTALL
    )
    cleaned_text = re.sub(
        r'([0-9]{10,})"[\s\W]*,[\s\W]*"([\d\-:TIZ\s\.]+)"', 
        r'"accountld" : "\1", "createdAt" : "\2"',
        cleaned_text,
        flags=re.DOTALL
    )
    
    time_part = r'(\d{4}[-]\d{2}[-]\d{2})'
    time_clock_part = r'(\d{1,2}[:]\d{2}[:]\d{2}[^"\s,]*?)'
    ip_part = r'([0-9IiAaBbCcDdEeFf\.:]{7,})'
    
    cleaned_text = re.sub(
        rf'{time_part}[\s\W]*?{time_clock_part}[\s\W]*{ip_part}', 
        r'"createdAt" : "\1T\2", "loginIp" : "\3"',
        cleaned_text,
        flags=re.DOTALL
    )

    return cleaned_text


def extract_key_based_data(cleaned_text, mode, time_key_regex, time_format_regex):
    results = []
    if mode == 'PATTERN':
        # 1. IPアドレスの正規表現 (saiyomikaku.txt のような生IPに対応)
        ip_char_set = r'[\dIlAaBbCcDdEeFf]'
        ip_pattern = rf'{ip_char_set}{{1,4}}([.:]{ip_char_set}{{1,4}}){{3,7}}'
        
        # 2. 時刻とIPのどちらかを見つける複合正規表現
        combined_pattern = re.compile(f'({time_format_regex})|({ip_pattern})', re.DOTALL)
        matches = list(combined_pattern.finditer(cleaned_text))
        
        results = []
        current_time = None
        for m in matches:
            val = m.group(0).strip()
            # 時刻パターンに一致する場合
            if re.search(time_format_regex, val):
                current_time = val
            # IPパターンに一致する場合、直前の時刻とセットにする
            else:
                ip_val = clean_ip_address(val)
                results.append({
                    'No.': len(results)+1, 
                    'UTC (Before Clean)': current_time if current_time else "【時刻欠落】", 
                    'UTC (Cleaned)': clean_time_string_for_display(current_time) if current_time else "【抽出失敗】", 
                    'JST (UTC + 9h)': convert_utc_to_jst(current_time) if current_time else "【抽出失敗】", 
                    'loginIp': ip_val
                })
                current_time = None # ペアが完成したのでリセット
    else:
        # Xモード / HYBRIDモード用の抽出処理
        ip_field_pattern = r'"loginIp"[\s\W]*:[\s\W]*"(?P<ip_value>[^"]+?)"'
        time_field_pattern = r'"createdAt"[\s\W]*:[\s\W]*"(?P<time_value>[^"]+?)"'
        combined_pattern = re.compile(f'({ip_field_pattern}|{time_field_pattern})', re.IGNORECASE)
        
        current_time = None
        for match in combined_pattern.finditer(cleaned_text):
            if match.group('time_value'):
                current_time = match.group('time_value').strip()
            elif match.group('ip_value'):
                ip_val = clean_ip_address(match.group('ip_value').strip())
                results.append({
                    'No.': len(results)+1,
                    'UTC (Before Clean)': current_time if current_time else "【時刻欠落】",
                    'UTC (Cleaned)': clean_time_string_for_display(current_time) if current_time else "【抽出失敗】",
                    'JST (UTC + 9h)': convert_utc_to_jst(current_time) if current_time else "【抽出失敗】",
                    'loginIp': ip_val
                })
                current_time = None
    return pd.DataFrame(results), []

def extract_ip_audit_data_final(raw_text, mode='X', time_key_option=None, ip_key_option=None, time_format_option=None): 
    if mode == 'X':
        # Xモードは従来通りのJSON整形プロセスを通す
        t_reg, i_reg = map_time_key_to_regex('createdAt'), map_ip_key_to_regex('loginIp')
        t_fmt = map_time_format_to_regex('Custom (YYYY-MM-DD...HH:MM:SS)')
        cleaned = preprocess_text(raw_text, t_reg, i_reg)
        df, _ = extract_key_based_data(cleaned, 'HYBRID', t_reg, t_fmt)
    else:
        # Otherモードの設定を取得
        t_reg = map_time_key_to_regex(time_key_option)
        t_fmt = map_time_format_to_regex(time_format_option)
        
        if mode == 'PATTERN':
            # 💡 キーがないファイルの場合、前処理(preprocess)をせず生テキストで抽出
            df, _ = extract_key_based_data(raw_text, 'PATTERN', t_reg, t_fmt)
        else:
            # HYBRIDモードなら従来通り
            cleaned = preprocess_text(raw_text, t_reg, i_reg)
            df, _ = extract_key_based_data(cleaned, 'HYBRID', t_reg, t_fmt)
    return df

    cleaned_text = preprocess_text(raw_text, time_key_regex, ip_key_regex) 
    df_key_based, extracted_spans = extract_key_based_data(cleaned_text, mode, time_key_regex, time_format_regex)

    if not df_key_based.empty:
        df_final = df_key_based.drop(columns=['start_pos', 'end_pos'], errors='ignore')
    else:
        df_final = pd.DataFrame(columns=['No.', 'UTC (Before Clean)', 'UTC (Cleaned)', 'JST (UTC + 9h)', 'loginIp'])

    if not df_final.empty:
        df_final['No.'] = range(1, len(df_final) + 1)

    return df_final


# --- 3. Tkinter GUIロジック ---

class AuditApp:
    def __init__(self, master):
        self.master = master
        self.version = "v1.4.3" # 👈 バージョン更新
        master.title(f"読取大臣 {self.version} - ログ分析補助ツール") 
        
        # --- ウィンドウの最大化 (全画面表示化) ---
        master.state('zoomed') 
        if sys.platform == "darwin":
            master.attributes('-zoom', True)
        # ------------------------------------

        self.df_result = None
        self.input_filepath = ""
        self.canvas_widget = None # グラフ表示用ウィジェットを保持
        self.original_geometry = master.geometry() # ウィンドウの元のサイズと位置を保持
        self.is_zoomed = True # 最大化状態を保持

        # 設定保持変数
        self.mode_var = tk.StringVar(value="X")
        self.detection_var = tk.StringVar(value="HYBRID")
        self.time_key_var = tk.StringVar(value=TIME_KEY_OPTIONS[0]) 
        self.ip_key_var = tk.StringVar(value=IP_KEY_OPTIONS[0]) 
        self.time_format_var = tk.StringVar(value=TIME_FORMAT_OPTIONS[0])
        
        # 日付関連の変数 (新規/変更)
        self.date_range_mode_var = tk.StringVar(value="CALENDAR") # カレンダー/オフセットの選択
        self.offset_value_var = tk.StringVar(value="1") # オフセット値 (例: 1)
        self.offset_unit_var = tk.StringVar(value="月") # オフセット単位 (例: 月)
        self.selected_ip_var = tk.StringVar(value="ALL_IPS") # IPフィルタリング用変数

        # スタイルの設定 (変更なし)
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass 

        self.PRIMARY_COLOR = '#007BFF' 
        self.ACCENT_COLOR = '#0056b3'  
        self.BG_COLOR = '#f8f9fa'      
        self.TEXT_COLOR = '#343a30'    

        master.configure(bg=self.BG_COLOR)
        
        font_config = ('sans-serif', 10) 
        if chosen_font:
             font_config = (chosen_font, 10)
        
        style.configure('Header.TLabel', font=(font_config[0], 18, 'bold'), foreground=self.PRIMARY_COLOR, background=self.BG_COLOR)
        style.configure('TLabel', font=font_config, padding=5, background=self.BG_COLOR, foreground=self.TEXT_COLOR)
        style.configure('Bold.TLabel', font=(font_config[0], 11, 'bold'), background=self.BG_COLOR, foreground=self.TEXT_COLOR)
        style.configure('Status.TLabel', font=(font_config[0], 10, 'italic'), foreground='gray', background=self.BG_COLOR)
        style.configure('TButton', font=(font_config[0], 10, 'bold'), padding=10, 
                        background=self.PRIMARY_COLOR, foreground='white', borderwidth=0)
        style.map('TButton', 
                  background=[('active', self.ACCENT_COLOR), ('disabled', 'gray')],
                  foreground=[('disabled', '#f8f9fa')])
        style.configure('TFrame', background=self.BG_COLOR)
        style.configure('OptionFrame.TFrame', background='#e9ecef', relief='groove', borderwidth=1)
        style.configure('Analysis.TFrame', background='#fff3cd', relief='solid', borderwidth=1) 

        # --- GUIレイアウト (スクロール機能) ---
        container = ttk.Frame(master)
        container.pack(fill='both', expand=True)

        canvas = tk.Canvas(container, bg=self.BG_COLOR, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        
        main_frame = ttk.Frame(canvas, style='TFrame', padding="25 25 25 25") 

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas_frame_id = canvas.create_window((0, 0), window=main_frame, anchor="nw", tags="scrollable_frame")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        def on_canvas_resize(event):
            canvas.itemconfig(canvas_frame_id, width=event.width)

        main_frame.bind("<Configure>", on_frame_configure)
        canvas.bind('<Configure>', on_canvas_resize)
        
        def _on_mouse_wheel(event):
            if event.num == 5 or (sys.platform in ('win32', 'darwin') and event.delta < 0): 
                canvas.yview_scroll(1, "units")
            elif event.num == 4 or (sys.platform in ('win32', 'darwin') and event.delta > 0): 
                canvas.yview_scroll(-1, "units")

        canvas.bind("<MouseWheel>", _on_mouse_wheel) 
        canvas.bind("<Button-4>", _on_mouse_wheel)    
        canvas.bind("<Button-5>", _on_mouse_wheel)    
        main_frame.bind("<MouseWheel>", _on_mouse_wheel)
        main_frame.bind("<Button-4>", _on_mouse_wheel)
        main_frame.bind("<Button-5>", _on_mouse_wheel)
        main_frame.bind('<Enter>', lambda e: main_frame.focus_set())
        
        self.canvas = canvas
        self.main_frame = main_frame


        # ----------------------------------------------------

        # ヘッダー (変更なし)
        header_label = ttk.Label(main_frame, text=f"🕵️ ログ抽出＆JST変換ツール ({self.version})", style='Header.TLabel')
        header_label.pack(pady=(0, 15))

        self.info_label = ttk.Label(master, text="未知のOCR誤表記があった場合、データの正確性を維持するため、『データ欠落』を故意に発生させています。お手数ですが、『データ欠落』が生じた場合は、目視で内容を確認してください。", justify=tk.CENTER)
        self.info_label.pack(pady=5)
        
        # --- 設定エリア (ステップ 1) ---
        ttk.Label(main_frame, text="1. ⚙️ 検出設定を選択してください。", style='Bold.TLabel').pack(pady=(10, 5), anchor='w')
        
        option_frame = ttk.Frame(main_frame, style='OptionFrame.TFrame', padding="15 10")
        option_frame.pack(fill='x', pady=5)
        
        # 1.1. モード選択 (X / Other)
        mode_radio_frame = ttk.Frame(option_frame)
        mode_radio_frame.pack(pady=5, fill='x')
        ttk.Label(mode_radio_frame, text="抽出モード:", style='Bold.TLabel').pack(side='left', padx=(0, 10))
        ttk.Radiobutton(mode_radio_frame, text="X (デフォルト・固定キー)", variable=self.mode_var, value="X", command=self.update_option_visibility).pack(side='left', padx=10)
        ttk.Radiobutton(mode_radio_frame, text="Other (カスタム設定)", variable=self.mode_var, value="Other", command=self.update_option_visibility).pack(side='left', padx=10)
        
        # 1.2. Other 選択時の詳細設定フレーム
        self.other_options_frame = ttk.Frame(option_frame, style='TFrame')
        self.other_options_frame.pack(fill='x', pady=10)
        
        # 1.2.1 検出方法選択 (ハイブリッド / パターン)
        detection_radio_frame = ttk.Frame(self.other_options_frame)
        detection_radio_frame.pack(pady=5, fill='x')
        ttk.Label(detection_radio_frame, text="検出方法:", style='Bold.TLabel').pack(side='left', padx=(0, 10))
        ttk.Radiobutton(detection_radio_frame, text="ハイブリッド検知 (キー名 + 時刻表記)", variable=self.detection_var, value="HYBRID", command=self.update_option_visibility).pack(side='left', padx=10)
        ttk.Radiobutton(detection_radio_frame, text="パターン検知 (時刻表記のみ)", variable=self.detection_var, value="PATTERN", command=self.update_option_visibility).pack(side='left', padx=10)

        # 1.2.2 時刻キー名選択 
        self.time_key_select_frame = ttk.Frame(self.other_options_frame, style='TFrame') 
        ttk.Label(self.time_key_select_frame, text="時刻キー名:", width=20, anchor='w').pack(side='left', padx=(0, 10))
        self.time_key_combobox = ttk.Combobox(self.time_key_select_frame, textvariable=self.time_key_var, values=TIME_KEY_OPTIONS, state='normal', width=30) 
        self.time_key_combobox.pack(side='left', fill='x', expand=True)
        self.time_key_combobox.current(0)

        # 1.2.3 IPキー名選択 
        self.ip_key_select_frame = ttk.Frame(self.other_options_frame, style='TFrame')
        ttk.Label(self.ip_key_select_frame, text="IPアドレスキー名:", width=20, anchor='w').pack(side='left', padx=(0, 10))
        self.ip_key_combobox_opt = ttk.Combobox(self.ip_key_select_frame, textvariable=self.ip_key_var, values=IP_KEY_OPTIONS, state='normal', width=30)
        self.ip_key_combobox_opt.pack(side='left', fill='x', expand=True)
        self.ip_key_combobox_opt.current(0)
        
        # 1.2.4 時刻表記選択
        self.format_select_frame = ttk.Frame(self.other_options_frame, style='TFrame')
        ttk.Label(self.format_select_frame, text="時刻表記 (Time Format):", width=20, anchor='w').pack(side='left', padx=(0, 10))
        self.format_combobox = ttk.Combobox(self.format_select_frame, textvariable=self.time_format_var, values=TIME_FORMAT_OPTIONS, state='normal', width=30)
        self.format_combobox.pack(side='left', fill='x', expand=True)
        self.format_combobox.current(0)
        
        # 1.3. 説明追加フレーム
        self.explanation_frame = ttk.Frame(option_frame, style='TFrame', padding="0 5 0 0")
        
        explanation_text = (
            "💡 **ハイブリッド検知**: ログ内の「時刻キー名」「IPキー名」と「時刻/IPのパターン」の両方を基にレコードを特定します。信頼性は高いですが、キー名が完全にOCRで崩れていると失敗します。\n"
            "💡 **パターン検知**: ログ内の「時刻のパターン」と「IPアドレスのパターン」のみを頼りにレコードを特定します。キー名が完全に不明・不要な場合に有効ですが、無関係なデータも抽出する可能性があります。"
        )
        self.explanation_label = ttk.Label(self.explanation_frame, text=explanation_text, wraplength=700, justify='left', style='Status.TLabel', foreground='black')
        self.explanation_label.pack(fill='x')


        self.update_option_visibility() # 初期状態の表示を更新

        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=15)
        
        # --- ファイル選択 (ステップ 2) ---
        ttk.Label(main_frame, text="2. 📂 OCRテキストファイルを選択し、処理を開始してください。", style='Bold.TLabel').pack(pady=(10, 5), anchor='w')
        
        # 💡 修正: widthを30から45に拡張し、テキスト切れを解消
        self.select_button = ttk.Button(main_frame, text="📄 ファイルを選択し、抽出処理を開始", command=self.select_file, width=45) 
        self.select_button.pack(pady=5, anchor='w')

        # ファイルパス表示
        self.filepath_var = tk.StringVar(main_frame, value="--- ファイルが選択されていません ---")
        self.filepath_label = ttk.Label(main_frame, textvariable=self.filepath_var, wraplength=700, foreground=self.TEXT_COLOR)
        self.filepath_label.pack(pady=5, anchor='w')
        
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=20)

        # --- 結果保存 (ステップ 3) ---
        ttk.Label(main_frame, text="3. 💾 処理結果をCSVとして保存します。", style='Bold.TLabel').pack(pady=(0, 5), anchor='w')

        # CSV保存ボタン（最初は無効）
        self.save_button = ttk.Button(main_frame, text="📥 結果をCSVとして保存", command=self.save_csv, state=tk.DISABLED, width=30)
        self.save_button.pack(pady=10, anchor='w')
        
        # ------------------------------------------------------------------
        # ステータス表示 (前回の修正でここに移動済み)
        self.status_var = tk.StringVar(main_frame, value="準備完了。設定を選択し、ファイルを選択してください。")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, wraplength=700, style='Status.TLabel', foreground='black')
        self.status_label.pack(pady=(0, 15), anchor='w') 
        # ------------------------------------------------------------------
        
        ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=20)
        
        # --- 高度な分析と可視化 (ステップ 4) ---
        ttk.Label(main_frame, text="4. 📊 高度な分析と可視化 (期間とIPフィルタリング)", style='Bold.TLabel').pack(pady=(0, 10), anchor='w')
        
        self.analysis_container_frame = ttk.Frame(main_frame, style='Analysis.TFrame', padding="15 10")
        self.analysis_container_frame.pack(fill='x', pady=5)
        
        # --- 4.1 期間指定方法の選択 (TOP) ---
        date_mode_frame = ttk.Frame(self.analysis_container_frame, style='TFrame')
        date_mode_frame.pack(fill='x', pady=5)
        ttk.Label(date_mode_frame, text="📅 期間指定方法:", style='Bold.TLabel').pack(side='left', padx=5)
        
        ttk.Radiobutton(date_mode_frame, text="カレンダー範囲", variable=self.date_range_mode_var, value="CALENDAR", command=self.update_date_range_visibility).pack(side='left', padx=10)
        ttk.Radiobutton(date_mode_frame, text="前後期間 (オフセット)", variable=self.date_range_mode_var, value="OFFSET", command=self.update_date_range_visibility).pack(side='left', padx=10)

        # --- 4.2 カレンダー範囲指定フレーム (期間指定方法の直下) ---
        self.calendar_range_frame = ttk.Frame(self.analysis_container_frame, style='TFrame')
        ttk.Label(self.calendar_range_frame, text="開始日:", width=8, anchor='w').pack(side='left', padx=5)
        if DateEntry:
            # 💡 drop_down_style='up' は残す (これが効く環境ではこれでOK)
            self.start_date_cal = DateEntry(self.calendar_range_frame, width=12, background=self.PRIMARY_COLOR, foreground='white', borderwidth=2, date_pattern='yyyy/mm/dd', locale='ja_JP', drop_down_style='up')
            self.start_date_cal.pack(side='left', padx=5)
            # 💡 修正点: ウィンドウ位置調整のためのバインドを追加
            self.start_date_cal.bind('<ButtonPress>', lambda e: self.adjust_window_position_for_calendar(e.widget))
            self.start_date_cal.bind('<Map>', lambda e: self.reset_window_position_after_calendar())
            
            ttk.Label(self.calendar_range_frame, text="終了日:", width=8, anchor='w').pack(side='left', padx=5)
            self.end_date_cal = DateEntry(self.calendar_range_frame, width=12, background=self.PRIMARY_COLOR, foreground='white', borderwidth=2, date_pattern='yyyy/mm/dd', locale='ja_JP', drop_down_style='up')
            self.end_date_cal.pack(side='left', padx=5)
            # 💡 修正点: ウィンドウ位置調整のためのバインドを追加
            self.end_date_cal.bind('<ButtonPress>', lambda e: self.adjust_window_position_for_calendar(e.widget))
            self.end_date_cal.bind('<Map>', lambda e: self.reset_window_position_after_calendar())
        else:
            # tkcalendarがない場合のフォールバック（分析機能は使えない）
            ttk.Label(self.calendar_range_frame, text="tkcalendarが必要です。", foreground='red').pack(side='left', padx=5)


        # --- 4.3 オフセット期間指定フレーム (期間指定方法の直下) ---
        self.offset_range_frame = ttk.Frame(self.analysis_container_frame, style='TFrame')
        ttk.Label(self.offset_range_frame, text="基準日:", width=8, anchor='w').pack(side='left', padx=5)
        if DateEntry:
            self.base_date_cal = DateEntry(self.offset_range_frame, width=12, background=self.PRIMARY_COLOR, foreground='white', borderwidth=2, date_pattern='yyyy/mm/dd', locale='ja_JP', drop_down_style='up')
            self.base_date_cal.pack(side='left', padx=5)
            # 💡 修正点: ウィンドウ位置調整のためのバインドを追加
            self.base_date_cal.bind('<ButtonPress>', lambda e: self.adjust_window_position_for_calendar(e.widget))
            self.base_date_cal.bind('<Map>', lambda e: self.reset_window_position_after_calendar())
            
            ttk.Label(self.offset_range_frame, text="前後期間:", width=10, anchor='w').pack(side='left', padx=5)
            self.offset_entry = ttk.Entry(self.offset_range_frame, textvariable=self.offset_value_var, width=5)
            self.offset_entry.pack(side='left', padx=5)
            
            self.offset_unit_combobox = ttk.Combobox(
                self.offset_range_frame, 
                textvariable=self.offset_unit_var, 
                values=["月", "週", "日"], 
                state='readonly', 
                width=5
            )
            self.offset_unit_combobox.pack(side='left', padx=5)
            self.offset_unit_combobox.set("月")
        

        # --- 4.4 IPアドレスフィルタリング (日付指定の下に固定) ---
        # 💡 レイアウト修正のためインスタンス変数として保持
        self.ip_filter_frame = ttk.Frame(self.analysis_container_frame, style='TFrame') 
        self.ip_filter_frame.pack(fill='x', pady=10) 

        ttk.Label(self.ip_filter_frame, text="💻 IPアドレスフィルタ:", width=20, anchor='w').pack(side='left', padx=5)
        
        # IPフィルタリング用のコンボボックス 
        self.ip_combobox = ttk.Combobox(
            self.ip_filter_frame, 
            textvariable=self.selected_ip_var, 
            values=["ALL_IPS"], 
            state='readonly', 
            width=30
        )
        self.ip_combobox.pack(side='left', fill='x', expand=True, padx=5)
        self.ip_combobox.set("ALL_IPS")

        # --- 4.5 分析実行ボタン ---
        self.analyze_button = ttk.Button(self.analysis_container_frame, text="📈 傾向分析とグラフ描画を実行", command=self.perform_analysis_and_plot, state=tk.DISABLED, width=30)
        self.analyze_button.pack(pady=10, anchor='w')

        # グラフ表示用のフレーム (変更なし)
        self.plot_frame = ttk.Frame(self.analysis_container_frame, style='TFrame')
        self.plot_frame.pack(fill='both', expand=True, pady=5)

        # 初期表示更新 (ここでいずれかのフレームがpackされる)
        self.update_date_range_visibility() 

    
    # 💡 新規メソッド: カレンダー表示時のウィンドウ位置調整
    def adjust_window_position_for_calendar(self, calendar_widget):
        """
        カレンダーウィジェットがクリックされた際に、画面の下端で見切れないようにメインウィンドウを一時的に移動させる。
        """
        if self.master.state() == 'zoomed':
            self.is_zoomed = True
            return # 最大化されている場合は位置調整しない（しても効かないことが多い）
        else:
            self.is_zoomed = False

        # 現在のウィンドウの位置とサイズを取得
        self.master.update_idletasks()
        
        # ウィンドウのジオメトリをパースし、元の位置を保存
        geometry_str = self.master.geometry()
        match = re.match(r'(\d+)x(\d+)\+(\d+)\+(\d+)', geometry_str)
        if match:
            width, height, x_pos, y_pos = map(int, match.groups())
            self.original_geometry = geometry_str
        else:
            # 取得できない場合は処理を中止
            return

        # カレンダーウィジェットの画面上の絶対座標を取得
        # rootx, rooty はカレンダーの左上の絶対座標
        cal_root_y = calendar_widget.winfo_rooty()
        
        # 画面の高さ（デスクトップの高さ）を取得
        screen_height = self.master.winfo_screenheight()
        
        # カレンダーのおおよその高さ（約250ピクセルとして見積もる）
        CALENDAR_HEIGHT = 280
        
        # カレンダーが表示されたときのY座標の下端
        # DateEntryの高さは約30pxなので、ドロップダウンが下に開くと約30 + 280 = 310
        # drop_down_style='up'を設定しているため、上に開くと仮定し、DateEntryの上端Y座標を見る
        
        # 画面の上端で見切れる可能性（上に開く場合）: カレンダー上端Y座標 < カレンダーの高さ
        if cal_root_y - CALENDAR_HEIGHT < 0:
            # カレンダーが上に開いても画面上端で見切れる場合
            y_diff = abs(cal_root_y - CALENDAR_HEIGHT) + 20 # 20pxの余裕
            new_y = y_pos + y_diff
            
            # メインウィンドウを下に移動（カレンダー全体が画面内に入るように）
            new_geometry = f"{width}x{height}+{x_pos}+{new_y}"
            self.master.geometry(new_geometry)
            
            # ポップアップが開いた後に元の位置に戻す処理をスケジュール
            self.master.after(50, self.reset_window_position_after_calendar)


    def reset_window_position_after_calendar(self):
        """
        カレンダーが閉じられた後にウィンドウを元の位置に戻す
        (ただし、最大化状態でない場合のみ)
        """
        # <Map>イベントはカレンダーポップアップが閉じられるときに頻繁に発生するため、
        # 誤動作防止のため、短い遅延を設けるか、より正確なイベントを探す必要があるが、
        # tkcalendarでは難しい。ここでは単純に元の位置に戻す。
        if not self.is_zoomed and self.original_geometry:
            self.master.geometry(self.original_geometry)
            self.original_geometry = None # 念のためリセット

    
    def update_option_visibility(self):
        """モードと検出方法に応じて、オプションの表示/非表示を切り替える"""
        mode = self.mode_var.get()
        detection = self.detection_var.get()
        
        if mode == "Other":
            self.other_options_frame.pack(fill='x', pady=10)
            self.explanation_frame.pack(fill='x', pady=10) 
            
            if detection == "HYBRID":
                self.time_key_select_frame.pack(pady=5, fill='x')
                self.ip_key_select_frame.pack(pady=5, fill='x') 
                self.format_select_frame.pack(pady=5, fill='x')
                
                self.time_key_combobox.config(state='normal')
                self.ip_key_combobox_opt.config(state='normal') 
                self.format_combobox.config(state='normal')
            elif detection == "PATTERN":
                self.time_key_select_frame.forget()
                self.ip_key_select_frame.forget() 
                self.format_select_frame.pack(pady=5, fill='x')
                
                self.time_key_combobox.config(state='disabled') 
                self.ip_key_combobox_opt.config(state='disabled') 
                self.format_combobox.config(state='normal')
            
        else:
            self.other_options_frame.forget() 
            self.explanation_frame.pack_forget() 
            self.time_key_combobox.config(state='disabled') 
            self.ip_key_combobox_opt.config(state='disabled') 
            self.format_combobox.config(state='disabled')

    # --- 期間指定UIの制御 (修正済み) ---
    def update_date_range_visibility(self):
        """日付範囲の表示を切り替え、常にIPフィルタリングフレームの前に配置する"""
        if not DateEntry:
            return

        mode = self.date_range_mode_var.get()
        
        # 一旦両方を非表示にする
        self.calendar_range_frame.forget()
        self.offset_range_frame.forget()
        
        # before=self.ip_filter_frame を使って、配置位置を固定する
        if mode == "CALENDAR":
            # カレンダー範囲を表示し、IPフィルタリングフレームの前に配置
            self.calendar_range_frame.pack(fill='x', pady=5, before=self.ip_filter_frame)
        elif mode == "OFFSET":
            # オフセットを表示し、IPフィルタリングフレームの前に配置
            self.offset_range_frame.pack(fill='x', pady=5, before=self.ip_filter_frame)

    # --- IPアドレスリストの更新 (変更なし) ---
    def update_ip_list(self):
        """抽出されたデータに基づいてIPアドレスのコンボボックスを更新する"""
        if self.df_result is not None and not self.df_result.empty:
            # 欠落データを除外し、ユニークなIPアドレスのリストを作成
            unique_ips = self.df_result[
                ~self.df_result['loginIp'].astype(str).str.contains('【')
            ]['loginIp'].unique().tolist()
            
            # 'ALL_IPS'を先頭に追加
            ip_options = ["ALL_IPS"] + sorted(unique_ips)
            
            # コンボボックスの値を更新
            self.ip_combobox['values'] = ip_options
            
            # 選択中の値がリストに存在しない場合は'ALL_IPS'にリセット
            if self.selected_ip_var.get() not in ip_options:
                self.selected_ip_var.set("ALL_IPS")
        else:
            self.ip_combobox['values'] = ["ALL_IPS"]
            self.selected_ip_var.set("ALL_IPS")
            
    def select_file(self):
        # 既存のプロットがあればクリア
        self.clear_plot_frame()
        self.analyze_button.config(state=tk.DISABLED)

        self.input_filepath = filedialog.askopenfilename(
            title="OCRテキストファイルを選択してください",
            filetypes=[("Text files", "*.txt")]
        )
        
        if self.input_filepath:
            self.filepath_var.set(f"選択ファイル: {os.path.basename(self.input_filepath)}")
            self.status_var.set("処理中... ファイルを読み込み、データ抽出と変換を実行しています。")
            self.status_label.config(foreground=self.ACCENT_COLOR) 
            self.master.update() 
            self.process_file()
        else:
            self.filepath_var.set("--- ファイルが選択されていません ---")
            self.status_var.set("キャンセルされました。ファイルを選択してください。")
            self.status_label.config(foreground='gray')
            self.save_button.config(state=tk.DISABLED)

    def process_file(self):
        mode = self.mode_var.get()
        if mode == "Other":
            mode = self.detection_var.get()
            time_key_option = self.time_key_var.get()
            ip_key_option = self.ip_key_var.get()
            time_format_option = self.time_format_var.get()
        else:
            time_key_option = 'createdAt'
            ip_key_option = 'loginIp'
            time_format_option = 'Custom (YYYY-MM-DD...HH:MM:SS)'
            
        raw_text = None
        # 文字化け対策: UTF-8での読み込みを試み、失敗したらcp932を試みる
        try:
            with open(self.input_filepath, 'r', encoding='utf-8') as f: 
                raw_text = f.read()
        except UnicodeDecodeError:
            try:
                # 日本語環境で一般的な cp932 (Shift-JIS) で再試行
                with open(self.input_filepath, 'r', encoding='cp932') as f:
                    raw_text = f.read()
                messagebox.showwarning("エンコーディング警告", "ファイルを cp932 (Shift-JIS) として読み込みました。")
            except Exception:
                messagebox.showerror("エラー", f"ファイルの読み込みに失敗しました。エンコーディングを確認してください。")
                self.status_var.set("処理失敗: ファイル読み込みエラー")
                self.status_label.config(foreground='red')
                self.save_button.config(state=tk.DISABLED)
                return
        except Exception as e:
            messagebox.showerror("エラー", f"ファイル処理中にエラーが発生しました: {e}")
            self.status_var.set("処理失敗: I/Oエラー")
            self.status_label.config(foreground='red')
            self.save_button.config(state=tk.DISABLED)
            return

        # 抽出ロジックの実行
        self.df_result = extract_ip_audit_data_final(
            raw_text, 
            mode=mode, 
            time_key_option=time_key_option, 
            ip_key_option=ip_key_option, 
            time_format_option=time_format_option
        )

        log_path = os.path.join(os.path.dirname(sys.argv[0]), "debug_log.txt")
        try:
            with open(log_path, 'a', encoding='utf-8') as log_file:
                log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] \n")
                log_file.write(f"Input File: {os.path.basename(self.input_filepath)}\n")
                log_file.write(f"Mode: {mode}, Time Key: {time_key_option}, IP Key: {ip_key_option}, Format: {time_format_option}\n") 
                log_file.write(f"DataFrame Rows (Result): {len(self.df_result) if self.df_result is not None else 0}\n")
                
                if not self.df_result.empty:
                    err_ip = (self.df_result['loginIp'].astype(str).str.contains('【IP欠落')).sum()
                    err_ts = (self.df_result['UTC (Before Clean)'].astype(str).str.contains('【時刻欠落')).sum()
                    log_file.write(f"Detected IP Missing Errors (No Reconciliation): {err_ip}\n")
                    log_file.write(f"Detected Time Missing Errors (No Reconciliation): {err_ts}\n")
                
                log_file.write("--------------------------------\n")
        except Exception as log_e:
             print(f"Log error: {log_e}")
             pass
        
        if not self.df_result.empty:
            
            # --- ここから分析の前処理 ---
            # JST時刻の文字列をDatetimeオブジェクトに変換
            # 修正後のformat: '%Y/%m/%d %H:%M:%S'
            self.df_result['JST_Datetime'] = pd.to_datetime(
                self.df_result['JST (UTC + 9h)'], 
                format='%Y/%m/%d %H:%M:%S', 
                errors='coerce' # パースエラーの場合はNaT (Not a Time) にする
            )
            self.df_result.dropna(subset=['JST_Datetime'], inplace=True)
            
            if self.df_result.empty:
                messagebox.showerror("エラー", "抽出されたレコードから有効なJST時刻を特定できませんでした。")
                self.status_var.set("処理失敗: JST時刻の変換に失敗。")
                self.status_label.config(foreground='red')
                self.save_button.config(state=tk.DISABLED)
                self.analyze_button.config(state=tk.DISABLED)
                return

            # 初期期間設定 (最小/最大日付)
            min_date = self.df_result['JST_Datetime'].dt.date.min()
            max_date = self.df_result['JST_Datetime'].dt.date.max()
            
            if DateEntry:
                # DateEntryウィジェットに値をセット
                self.start_date_cal.set_date(min_date)
                self.end_date_cal.set_date(max_date)
                self.base_date_cal.set_date(max_date)
            
            # IPリストの更新
            self.update_ip_list()

            # --- 前処理ここまで ---

            self.status_label.config(foreground='green')
            self.status_var.set(f"✅ 抽出完了！ {len(self.df_result)}件のレコードを処理しました。CSV保存または傾向分析を実行してください。")
            self.save_button.config(state=tk.NORMAL)
            self.analyze_button.config(state=tk.NORMAL) # 成功したら分析ボタンを有効化

            err_ip = (self.df_result['loginIp'].astype(str).str.contains('【IP欠落')).sum()
            err_ts = (self.df_result['UTC (Before Clean)'].astype(str).str.contains('【時刻欠落')).sum()
            
            if err_ip > 0 or err_ts > 0:
                 messagebox.showwarning("警告", f"🚨 データ欠落（紐づけズレの可能性）のあるレコードを**{err_ip + err_ts}件**検出しました。これらの欠落は自動補完されていません。CSVで「【欠落】」と表示されている行を確認してください。")
            
            if self.df_result['JST (UTC + 9h)'].astype(str).str.contains('【パースエラー').any():
                messagebox.showwarning("警告", "一部の時刻データの変換に失敗しました。CSVのデータを確認してください。")

        else:
            self.status_label.config(foreground='red')
            messagebox.showerror("エラー", "ファイルから有効なデータパターンを抽出できませんでした。debug_log.txtを確認してください。")
            self.status_var.set("処理失敗: データ抽出できず。debug_log.txtを確認してください。")
            self.save_button.config(state=tk.DISABLED)
            self.analyze_button.config(state=tk.DISABLED)

    def clear_plot_frame(self):
        """プロット表示エリアをクリアする"""
        if self.canvas_widget:
            self.canvas_widget.destroy()
            self.canvas_widget = None
        for widget in self.plot_frame.winfo_children():
            widget.destroy()

    def perform_analysis_and_plot(self):
        if self.df_result is None or self.df_result.empty:
            messagebox.showwarning("警告", "抽出結果がありません。先にファイルを処理してください。")
            return
        
        if plt is None or sns is None or DateEntry is None or pd_offsets is None:
             messagebox.showerror("エラー", "Matplotlib、Seaborn、またはtkcalendarがインストールされていません。pip install pandas matplotlib seaborn tkcalendar を実行してください。")
             return

        self.status_var.set("分析実行中... グラフを生成しています。")
        self.status_label.config(foreground=self.ACCENT_COLOR) 
        self.master.update()

        try:
            date_format = '%Y/%m/%d'
            start_dt = None
            end_dt_original = None
            
            mode = self.date_range_mode_var.get()
            
            # --- 期間のバリデーションと計算 ---
            if mode == "CALENDAR":
                # カレンダーモード
                start_dt = self.start_date_cal.get_date()
                end_dt_original = self.end_date_cal.get_date()
                
            elif mode == "OFFSET":
                # オフセットモード
                base_dt = self.base_date_cal.get_date()
                offset_value = int(self.offset_value_var.get())
                offset_unit = self.offset_unit_var.get()
                
                # 基準日を終了日とする
                end_dt_original = base_dt 
                
                # 開始日を計算
                # pandasのDateOffsetを利用して正確な月次計算を行う
                if offset_unit == "月":
                    start_dt = (datetime.combine(base_dt, datetime.min.time()) - pd.DateOffset(months=offset_value)).date()
                elif offset_unit == "週":
                    start_dt = base_dt - timedelta(weeks=offset_value)
                elif offset_unit == "日":
                    start_dt = base_dt - timedelta(days=offset_value)
                else:
                    raise ValueError("無効なオフセット単位が選択されました。")
            
            # Validation: 開始日は終了日より過去または同日であること
            if start_dt > end_dt_original:
                raise ValueError("開始日は終了日より過去または同日である必要があります。")

            # フィルタリング用の終了日（翌日）を設定
            filter_end_dt = end_dt_original + timedelta(days=1) 
            
            # IPフィルタリング
            selected_ip = self.selected_ip_var.get()
            
            # フィルタリングの実行
            filtered_df = self.df_result[
                (self.df_result['JST_Datetime'].dt.date >= start_dt) & 
                (self.df_result['JST_Datetime'].dt.date < filter_end_dt) 
            ].copy()
            
            if selected_ip != "ALL_IPS":
                filtered_df = filtered_df[filtered_df['loginIp'] == selected_ip].copy()
            
            if filtered_df.empty:
                messagebox.showwarning("警告", "指定された期間またはIPアドレスの条件に合致するデータがありませんでした。")
                self.status_var.set("分析完了: データなし")
                self.status_label.config(foreground='orange')
                return

            # --- 集計処理 ---
            
            # 1. 日次集計
            daily_count = filtered_df['JST_Datetime'].dt.date.value_counts().sort_index()
            daily_df = daily_count.rename('Count').reset_index()
            daily_df.columns = ['Date', 'Count']

            # 2. 月次集計
            monthly_count = filtered_df['JST_Datetime'].dt.to_period('M').value_counts().sort_index()
            monthly_df = monthly_count.rename('Count').reset_index()
            monthly_df.columns = ['Month', 'Count']
            
            # 3. 曜日別集計 (0=月, 6=日)
            weekday_order = [
                '月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日', '日曜日'
            ]
            # 💡 修正: dayofweekのインデックス3 (木曜日) を '水曜日' から '木曜日' に修正
            weekday_df = filtered_df['JST_Datetime'].dt.dayofweek.map(
                {0: '月曜日', 1: '火曜日', 2: '水曜日', 3: '木曜日', 4: '金曜日', 5: '土曜日', 6: '日曜日'}
            ).value_counts().reindex(weekday_order, fill_value=0).rename('Count').reset_index()
            weekday_df.columns = ['Weekday', 'Count']
            
            # 4. 時間帯別集計 (Hour)
            hour_count = filtered_df['JST_Datetime'].dt.hour.value_counts().sort_index().rename('Count').reset_index()
            hour_count.columns = ['Hour', 'Count']
            # 0-23時の欠損を補完
            hour_full_df = pd.DataFrame({'Hour': range(24)}).merge(hour_count, on='Hour', how='left').fillna(0)
            
            # 2. 集計処理
            heatmap_data = filtered_df.copy()
            heatmap_data['Hour'] = heatmap_data['JST_Datetime'].dt.hour
            heatmap_data['Weekday_Name'] = heatmap_data['JST_Datetime'].dt.dayofweek.map(
                {0: '月曜日', 1: '火曜日', 2: '水曜日', 3: '木曜日', 4: '金曜日', 5: '土曜日', 6: '日曜日'}
            )
            heatmap_pivot = heatmap_data.groupby(['Hour', 'Weekday_Name']).size().unstack(fill_value=0)
            heatmap_pivot = heatmap_pivot.reindex(columns=weekday_order, fill_value=0)
            all_hours = pd.Index(range(24), name='Hour')
            heatmap_pivot = heatmap_pivot.reindex(all_hours, fill_value=0)

            # 3. グラフ領域のサイズを大きく確保 (figsizeを横12, 縦8などに広げる)
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10)) 
            plt.subplots_adjust(hspace=0.4) # グラフ間の上下の隙間を広げる

            # 4. ヒートマップの描画設定を強化
            sns.heatmap(
                heatmap_pivot, 
                annot=True, 
                fmt='d', 
                cmap='YlGnBu', 
                ax=ax2, 
                square=False,           # 横幅いっぱいに広げる
                annot_kws={
                    'size': 10,         # 文字を大きく
                    'weight': 'bold'    # 太字にする
                },
                cbar_kws={'label': 'ログイン回数'}
            )

            ax2.set_title('曜日 × 時間帯別 ログイン回数ヒートマップ', fontsize=14, pad=10)


            # --- グラフ描画 ---
            self.clear_plot_frame() # 既存のプロットをクリア
            
            fig, axes = plt.subplots(5, 1, figsize=(12, 18))
            
            fig.tight_layout(pad=4.5) 
            plt.subplots_adjust(hspace=0.7) 
            
            title_fontsize = 11

            # 1. 日次ログ件数 (Line Plot)
            title_range = f'({start_dt.strftime(date_format)} - {end_dt_original.strftime(date_format)})'
            if selected_ip != "ALL_IPS":
                 title_range += f" (IP: {selected_ip})"
                 
            sns.lineplot(ax=axes[0], x='Date', y='Count', data=daily_df, marker='o', color=self.PRIMARY_COLOR)
            axes[0].set_title(f'日次アクセス件数 {title_range}', fontsize=title_fontsize)
            axes[0].set_xlabel('日付')
            axes[0].set_ylabel('件数')
            axes[0].tick_params(axis='x', rotation=45, labelsize=8)
            axes[0].grid(True, linestyle='--', alpha=0.6)

            # 2. 月次傾向 (Bar Plot)
            sns.barplot(ax=axes[1], x='Month', y='Count', data=monthly_df, palette="viridis")
            axes[1].set_title('月次アクセス傾向', fontsize=title_fontsize)
            axes[1].set_xlabel('月')
            axes[1].set_ylabel('件数')
            axes[1].tick_params(axis='x', rotation=45, labelsize=10)

            # 3. 曜日別傾向 (Bar Plot)
            sns.barplot(ax=axes[2], x='Weekday', y='Count', data=weekday_df, order=weekday_order, palette="plasma")
            axes[2].set_title('曜日別アクセス傾向', fontsize=title_fontsize)
            axes[2].set_xlabel('曜日')
            axes[2].set_ylabel('件数')

            # 4. 時間帯別傾向 (Bar Plot)
            sns.barplot(ax=axes[3], x='Hour', y='Count', data=hour_full_df, palette="magma")
            axes[3].set_title('時間帯別アクセス傾向 (JST)', fontsize=title_fontsize)
            axes[3].set_xlabel('時刻 (時)')
            axes[3].set_ylabel('件数')
            axes[3].set_xticks(range(0, 24, 2))
            
            # 5. 曜日×時間帯ヒートマップ
            sns.heatmap(
                heatmap_pivot, 
                ax=axes[4], 
                cmap="YlGnBu", 
                annot=True, 
                fmt="d", 
                linewidths=.5, 
                cbar_kws={'label': '件数'},
                annot_kws={'fontsize': 8} # 💡 修正: フォントサイズを8に縮小し、重なりを解消
            )
            axes[4].set_title('曜日×時間帯別 アクセスヒートマップ (JST)', fontsize=title_fontsize)
            axes[4].set_xlabel('曜日')
            axes[4].set_ylabel('時刻 (時)')
            axes[4].tick_params(axis='y', rotation=0) 

            
            # Tkinterに埋め込み
            canvas_plot = FigureCanvasTkAgg(fig, master=self.plot_frame)
            self.canvas_widget = canvas_plot.get_tk_widget()
            self.canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=1)

            # ツールバーを追加
            toolbar = NavigationToolbar2Tk(canvas_plot, self.plot_frame)
            toolbar.update()
            canvas_plot.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

            self.status_var.set("✅ 分析完了！傾向グラフを表示しました。")
            self.status_label.config(foreground='green')

        except Exception as e:
            self.clear_plot_frame()
            messagebox.showerror("分析エラー", f"分析処理中に予期せぬエラーが発生しました: {e}")
            self.status_var.set("分析失敗: 処理エラー")
            self.status_label.config(foreground='red')


    def save_csv(self):
        if self.df_result is None or self.df_result.empty:
            messagebox.showwarning("警告", "保存するデータがありません。")
            return

        # CSVにエクスポートする際、分析用の列は削除
        df_export = self.df_result.drop(columns=['JST_Datetime'], errors='ignore')

        output_filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile="yomidai_result_analysis.csv", # ファイル名を変更
            filetypes=[("CSV files", "*.csv")]
        )
        
        if output_filepath:
            try:
                # 文字化け対策: cp932 (Shift-JIS)でエンコードを固定
                df_export.to_csv(output_filepath, index=False, encoding='cp932')
                
                self.status_var.set(f"保存完了: {os.path.basename(output_filepath)}")
                
                if messagebox.askyesno("完了", f"結果を以下のファイルに保存しました:\n{os.path.basename(output_filepath)}\n\nこのファイルを開きますか？"):
                    try:
                        if sys.platform == "win32":
                            os.startfile(output_filepath)
                        elif sys.platform == "darwin": 
                            os.system(f'open "{output_filepath}"')
                        else: 
                            os.system(f'xdg-open "{output_filepath}"')
                    except Exception as open_e:
                        messagebox.showerror("エラー", f"ファイルのオープンに失敗しました。手動で開いてください。\nエラー: {open_e}")
                        
            except Exception as e:
                messagebox.showerror("エラー", f"CSVファイルの保存中に失敗しました: {e}")
                self.status_var.set("保存失敗")

# --- 4. 💡 スプラッシュスクリーンのアップグレード版 ---

def show_splash_screen():
    """洗練されたデザインのスプラッシュスクリーン"""
    splash = tk.Toplevel()
    splash.overrideredirect(True)
    
    # 配色設定
    COLOR_BG = "#2C3E50"  # ミッドナイトブルー
    COLOR_ACCENT = "#3498DB" # スカイブルー
    COLOR_TEXT = "#ECF0F1" # オフホワイト

    splash.config(bg=COLOR_BG)
    
    # サイズと配置
    width, height = 450, 280
    x = (splash.winfo_screenwidth() // 2) - (width // 2)
    y = (splash.winfo_screenheight() // 2) - (height // 2)
    splash.geometry(f'{width}x{height}+{x}+{y}')

    # フェードイン効果（透明度を徐々に上げる）
    splash.attributes("-alpha", 0.0)
    
    # コンテンツ
    container = tk.Frame(splash, bg=COLOR_BG, highlightbackground=COLOR_ACCENT, highlightthickness=2)
    container.pack(fill='both', expand=True)

    tk.Label(
        container, text="🕵️", font=("Segoe UI Emoji", 40), bg=COLOR_BG, fg=COLOR_ACCENT
    ).pack(pady=(40, 0))

    tk.Label(
        container, text="読 取 大 臣", bg=COLOR_BG, fg=COLOR_TEXT, 
        font=(chosen_font if chosen_font else 'sans-serif', 24, 'bold')
    ).pack()

    tk.Label(
        container, text="AI Log Analysis System Engine", 
        bg=COLOR_BG, fg=COLOR_ACCENT, font=('Consolas', 9, 'italic')
    ).pack(pady=(0, 20))

    # モダンなプログレスバー
    style = ttk.Style()
    style.theme_use('default')
    style.configure("Splash.Horizontal.TProgressbar", 
                    background=COLOR_ACCENT, troughedcolor=COLOR_BG, 
                    thickness=4, borderwidth=0)
    
    progress = ttk.Progressbar(container, style="Splash.Horizontal.TProgressbar", 
                               orient="horizontal", length=300, mode="determinate")
    progress.pack(pady=10)

    status_label = tk.Label(container, text="Initializing modules...", bg=COLOR_BG, fg="gray", font=(10))
    status_label.pack()

    # アニメーション処理
    def animate_splash():
        # フェードイン
        for i in range(11):
            alpha = i / 10
            splash.attributes("-alpha", alpha)
            splash.update()
            splash.after(20)
        
        # プログレスバーの動き
        steps = [("Loading core logic...", 20), 
                 ("Setting up UI components...", 50), 
                 ("Optimizing OCR patterns...", 80), 
                 ("Ready!", 100)]
        
        for text, val in steps:
            status_label.config(text=text)
            progress['value'] = val
            splash.update()
            splash.after(400) # 読み込みを演出

    animate_splash()
    return splash

# メイン処理
if __name__ == '__main__':
    # 1. パスの設定（変更なし）
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(__file__)
        
    # 2. Tkinterのルートを作成し、スプラッシュスクリーンを表示
    root = tk.Tk()
    root.withdraw() # メインウィンドウを非表示にしておく
    splash_win = show_splash_screen()
    
    # 3. メインアプリケーションのインスタンス化 (ここで時間がかかる)
    # 💡 Tkinterのメインループに入る前に重い処理を実行
    app = AuditApp(root)
    
    # 4. スプラッシュスクリーンを閉じる
    splash_win.destroy()
    
    # 5. メインウィンドウを表示
    root.deiconify()
    
    # 6. メインループの実行
    root.mainloop()
