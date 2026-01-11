import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta, timezone
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
import os
import urllib.request
import io # Excel出力用

# ==========================================
# 0. フォント設定部 (IBM Plex Sans JP版)
# ==========================================
def configure_japanese_font():
    """
    日本語フォント(IBM Plex Sans JP)を自動ダウンロードして設定する関数
    """
    font_dir = "fonts"
    font_file = os.path.join(font_dir, "IBMPlexSansJP-Regular.ttf")
    font_url = "https://raw.githubusercontent.com/google/fonts/main/ofl/ibmplexsansjp/IBMPlexSansJP-Regular.ttf"

    if not os.path.exists(font_dir):
        os.makedirs(font_dir)

    if not os.path.exists(font_file):
        try:
            with st.spinner("日本語フォント(IBM Plex Sans JP)をダウンロード中..."):
                opener = urllib.request.build_opener()
                opener.addheaders = [('User-agent', 'Mozilla/5.0')]
                urllib.request.install_opener(opener)
                urllib.request.urlretrieve(font_url, font_file)
        except Exception as e:
            st.error(f"フォントのダウンロードに失敗しました: {e}")
            return

    try:
        fm.fontManager.addfont(font_file)
        font_prop = fm.FontProperties(fname=font_file)
        plt.rcParams['font.family'] = font_prop.get_name()
    except Exception as e:
        st.warning(f"フォントの設定に失敗しました: {e}")
        plt.rcParams['font.family'] = 'sans-serif'

configure_japanese_font()


# ==========================================
# 1. ロジック部 (抽出・クリーニング)
# ==========================================

JST = timezone(timedelta(hours=9), 'JST')

DEFAULT_TIME_KEY = r'createdat|cneatedat|cneated'
DEFAULT_TIME_FORMAT_PATTERN = r'(\d{4}[-]\d{2}[-]\d{2}).*?(\d{2}[:]\d{2}[:]\d{2})'
DEFAULT_IP_KEY = r'loginIp|loginlp|loglnip|login|loglnip'

TIME_KEY_OPTIONS = ['createdAt', 'timestamp', 'logged_at', 'start_time', 'Custom (時刻キー名を入力)']
IP_KEY_OPTIONS = ['loginIp', 'sourceIp', 'clientIp', 'RemoteAddr', 'Custom (IPキー名を入力)']
TIME_FORMAT_OPTIONS = ['YYYY-MM-DDTHH:MM:SS', 'YYYY/MM/DD HH:MM:SS', 'YYYY-MM-DD HH:MM:SS', 'MM/DD/YYYY HH:MM:SS', 'Custom (YYYY-MM-DD...HH:MM:SS)']

def map_time_format_to_regex(option, custom_val=""):
    if option == 'YYYY-MM-DDTHH:MM:SS': return r'(\d{4}[-]\d{2}[-]\d{2})T(\d{2}[:]\d{2}[:]\d{2})'
    elif option == 'YYYY/MM/DD HH:MM:SS': return r'(\d{4}[/]\d{2}[/]\d{2})\s(\d{2}[:]\d{2}[:]\d{2})'
    elif option == 'YYYY-MM-DD HH:MM:SS': return r'(\d{4}[-]\d{2}[-]\d{2})\s(\d{2}[:]\d{2}[:]\d{2})'
    elif option == 'MM/DD/YYYY HH:MM:SS': return r'(\d{2}[/]\d{2}[/]\d{4})\s(\d{2}[:]\d{2}[:]\d{2})'
    custom_input = custom_val.strip()
    if not custom_input: return DEFAULT_TIME_FORMAT_PATTERN
    return custom_input

def map_time_key_to_regex(option, custom_val=""):
    if option == 'createdAt': return r'createdat|cneatedat'
    elif option == 'timestamp': return r'timestamp|timestmp'
    elif option == 'logged_at': return r'logged_at|loged_at'
    elif option == 'start_time': return r'start_time|stat_time'
    custom_key = custom_val.strip()
    if not custom_key: return DEFAULT_TIME_KEY
    escaped_base = re.escape(custom_key)
    lower_clean = re.escape(custom_key.lower().replace(' ', '').replace('-', '').replace('_', ''))
    return f'({escaped_base}|{lower_clean})'

def map_ip_key_to_regex(option, custom_val=""):
    if option == 'loginIp': return r'loginIp|loginlp|loglnip|login'
    elif option == 'sourceIp': return r'sourceIp|sourcelp'
    elif option == 'clientIp': return r'clientIp|clientlp'
    elif option == 'RemoteAddr': return r'RemoteAddr|RemoteAdr'
    custom_key = custom_val.strip()
    if not custom_key: return DEFAULT_IP_KEY
    escaped_base = re.escape(custom_key)
    lower_clean = re.escape(custom_key.lower().replace(' ', '').replace('-', '').replace('_', ''))
    return f'({escaped_base}|{lower_clean})'

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
    cleaned = ip_str.strip()
    cleaned = cleaned.replace(' ', '').replace('　', '')
    cleaned = cleaned.replace('l', '1').replace('I', '1')
    cleaned = cleaned.replace('ll', '11').replace('III', '111').replace('IIl', '111').replace('Ill', '111')
    cleaned = cleaned.replace('O', '0').replace('o', '0')
    cleaned = cleaned.replace('-', ':').replace(';', ':').replace(':', ':')
    cleaned = re.sub(r':{2,}', ':', cleaned)
    cleaned = re.sub(r'^[^0-9a-fA-F]+', '', cleaned)
    cleaned = re.sub(r'[^0-9a-fA-F]+$', '', cleaned)
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
        dt_obj_utc_naive = datetime.strptime(cleaned_time_str, '%Y-%m-%dT%H:%M:%S')
        dt_obj_utc = dt_obj_utc_naive.replace(tzinfo=timezone.utc)
        dt_obj_jst = dt_obj_utc.astimezone(JST)
        return dt_obj_jst.strftime('%Y/%m/%d %H:%M:%S')
    except ValueError:
        return f"【パースエラー - 形式不正】"

def preprocess_text(raw_text, time_key_regex, ip_key_regex):
    cleaned_text = raw_text
    cleaned_text = re.sub(r'[\r\n]+', r' ', cleaned_text)
    cleaned_text = re.sub(r'\s{2,}', r' ', cleaned_text)
    cleaned_text = cleaned_text.replace('。', '.')
    cleaned_text = cleaned_text.replace(',,,', '",').replace(',,', '"').replace('%', '",').replace('n20', '"20')
    cleaned_text = cleaned_text.replace("'", "").replace("b", "").replace(">", "").replace("`", "")

    def normalize_key_wrapper(match):
        key_text = match.group(2)
        target_key = "loginIp" if re.search(ip_key_regex, key_text, re.IGNORECASE) else "createdAt"
        return f'"{target_key}" :'

    key_fix_pattern = re.compile(rf'(")?({time_key_regex}|{ip_key_regex})[\s\W]*:', re.IGNORECASE)
    cleaned_text = key_fix_pattern.sub(normalize_key_wrapper, cleaned_text)
    key_value_repair_pattern = re.compile(r'("createdAt"|"loginIp")[\s\W]*("[\d\-:TIZ\s\.]+"|"[0-9IiAaBbCcDdEeFf\.:]+")', re.IGNORECASE | re.DOTALL)
    cleaned_text = key_value_repair_pattern.sub(r'\1 : \2', cleaned_text)
    
    cleaned_text = re.sub(r'([0-9]{10,})"[\s\W]*,[\s\W]*"([\d\-:TIZ\s\.]+)"[\s\W]*,[\s\W]*([0-9\.]+)\"', r'"accountld" : "\1", "createdAt" : "\2", "loginIp" : "\3"', cleaned_text, flags=re.DOTALL)
    cleaned_text = re.sub(r'([0-9]{10,})"[\s\W]*,[\s\W]*"([\d\-:TIZ\s\.]+)"', r'"accountld" : "\1", "createdAt" : "\2"', cleaned_text, flags=re.DOTALL)
    
    time_part = r'(\d{4}[-]\d{2}[-]\d{2})'
    time_clock_part = r'(\d{1,2}[:]\d{2}[:]\d{2}[^"\s,]*?)'
    ip_part = r'([0-9IiAaBbCcDdEeFf\.:]{7,})'
    cleaned_text = re.sub(rf'{time_part}[\s\W]*?{time_clock_part}[\s\W]*{ip_part}', r'"createdAt" : "\1T\2", "loginIp" : "\3"', cleaned_text, flags=re.DOTALL)
    return cleaned_text

def extract_key_based_data(raw_text, mode, time_key_regex, time_format_regex):
    results = []
    
    # RAW_SCAN (キーなし) or PATTERN
    if mode == 'PATTERN' or mode == 'RAW_SCAN':
        lines = [line.strip() for line in raw_text.split('\n') if line.strip()]
        current_time = None
        for line in lines:
            is_time = re.search(time_format_regex, line)
            if is_time:
                current_time = is_time.group(0).strip()
            elif current_time:
                ip_candidate = line.strip()
                if len(ip_candidate) > 4: 
                    ip_val = clean_ip_address(ip_candidate)
                    results.append({
                        'No.': len(results)+1, 
                        'UTC (Before Clean)': current_time, 
                        'UTC (Cleaned)': clean_time_string_for_display(current_time), 
                        'JST (UTC + 9h)': convert_utc_to_jst(current_time), 
                        'loginIp': ip_val
                    })
                    current_time = None

    # HYBRID (JSON-like)
    else:
        cleaned_text = raw_text 
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
    return pd.DataFrame(results)

def extract_ip_audit_data_final(raw_text, mode='X', time_key_option=None, ip_key_option=None, time_format_option=None, custom_vals={}):
    t_reg = map_time_key_to_regex(time_key_option, custom_vals.get('time_key', ''))
    t_fmt = map_time_format_to_regex(time_format_option, custom_vals.get('time_fmt', ''))
    i_reg = map_ip_key_to_regex(ip_key_option, custom_vals.get('ip_key', ''))

    if not re.search(t_reg, raw_text, re.IGNORECASE) and not re.search(i_reg, raw_text, re.IGNORECASE):
        mode_to_use = 'RAW_SCAN'
    else:
        mode_to_use = mode

    if mode_to_use == 'X' or mode_to_use == 'HYBRID':
        cleaned = preprocess_text(raw_text, t_reg, i_reg)
        df = extract_key_based_data(cleaned, 'HYBRID', t_reg, t_fmt)
    else:
        df = extract_key_based_data(raw_text, mode_to_use, t_reg, t_fmt)
        
    return df, mode_to_use

# ==========================================
# 2. UI部
# ==========================================

st.set_page_config(page_title="読取大臣 Web版", layout="wide", page_icon="🕵️")

st.title("🕵️ 読取大臣 v1.5.0 (Excel & 再分析対応)")
st.caption("AI Log Analysis System Engine")

# --- サイドバー ---
st.sidebar.header("1. ⚙️ 設定 (テキスト読取時)")

mode_select = st.sidebar.radio("抽出モード", ["自動判定 (推奨)", "Other (カスタム設定)"], index=0)
mode_code = "X" if "自動判定" in mode_select else "Other"

detection_mode = "HYBRID"
time_key_opt = "createdAt"
ip_key_opt = "loginIp"
time_fmt_opt = "Custom (YYYY-MM-DD...HH:MM:SS)"
custom_inputs = {'time_key': '', 'ip_key': '', 'time_fmt': ''}

if mode_code == "Other":
    st.sidebar.markdown("---")
    detection_mode = st.sidebar.radio("検出方法", ["HYBRID (キーあり)", "PATTERN (キーなし/Raw)"])
    detection_code = "HYBRID" if "HYBRID" in detection_mode else "PATTERN"
    if detection_code == "HYBRID":
        time_key_opt = st.sidebar.selectbox("時刻キー名", TIME_KEY_OPTIONS)
        ip_key_opt = st.sidebar.selectbox("IPキー名", IP_KEY_OPTIONS)
    time_fmt_opt = st.sidebar.selectbox("時刻表記", TIME_FORMAT_OPTIONS)

# --- メインエリア ---
st.header("2. 📂 ファイルアップロード")
st.markdown("OCRしたテキストファイル、または**修正済みのCSV/Excelファイル**をアップロードできます。")
uploaded_file = st.file_uploader("対応形式: .txt, .csv, .xlsx", type=['txt', 'csv', 'xlsx'])

df_result = pd.DataFrame()
process_mode = "NONE"

if uploaded_file is not None:
    file_ext = uploaded_file.name.split('.')[-1].lower()
    
    # --- A. テキストファイル (OCR抽出処理) ---
    if file_ext == 'txt':
        try:
            raw_text = uploaded_file.read().decode("utf-8")
        except UnicodeDecodeError:
            try:
                uploaded_file.seek(0)
                raw_text = uploaded_file.read().decode("cp932")
                st.warning("⚠️ Shift-JIS (cp932) として読み込みました。")
            except Exception:
                st.error("ファイルの読み込みに失敗しました。")
                st.stop()

        with st.spinner('AI抽出エンジン実行中...'):
            exec_mode = mode_code
            if mode_code == "Other":
                exec_mode = detection_code

            df_result, used_mode = extract_ip_audit_data_final(
                raw_text, 
                mode=exec_mode,
                time_key_option=time_key_opt,
                ip_key_option=ip_key_opt,
                time_format_option=time_fmt_opt,
                custom_vals=custom_inputs
            )
            process_mode = f"OCR抽出 (Mode: {used_mode})"

    # --- B. CSV/Excelファイル (修正データ読み込み) ---
    else:
        try:
            if file_ext == 'csv':
                # Shift-JISとUTF-8の両方を試行
                try:
                    df_result = pd.read_csv(uploaded_file, encoding='cp932')
                except UnicodeDecodeError:
                    uploaded_file.seek(0)
                    df_result = pd.read_csv(uploaded_file, encoding='utf-8')
            elif file_ext == 'xlsx':
                df_result = pd.read_excel(uploaded_file)
            
            process_mode = "修正データ読み込み"
            st.info("📂 修正済みデータを読み込みました。抽出プロセスをスキップして分析に進みます。")
            
            # 必須カラムの確認
            required_cols = ['JST (UTC + 9h)', 'loginIp']
            missing = [c for c in required_cols if c not in df_result.columns]
            if missing:
                st.error(f"エラー: アップロードされたファイルに必須列 {missing} が含まれていません。")
                df_result = pd.DataFrame() # クリア
                
        except Exception as e:
            st.error(f"ファイルの読み込みに失敗しました: {e}")

    # --- 結果表示とダウンロード ---
    if not df_result.empty:
        st.success(f"✅ 処理完了 ({process_mode}) - {len(df_result)} 件")
        
        st.subheader("3. 📝 データプレビュー & ダウンロード")
        st.dataframe(df_result, use_container_width=True)
        
        col_dl1, col_dl2 = st.columns(2)
        
        # CSVダウンロード (Shift-JIS)
        csv_data = df_result.drop(columns=['JST_Datetime'], errors='ignore').to_csv(index=False, encoding='cp932')
        col_dl1.download_button("📥 CSV (Shift-JIS)", data=csv_data, file_name="result.csv", mime="text/csv")
        
        # Excelダウンロード (xlsx)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df_result.drop(columns=['JST_Datetime'], errors='ignore').to_csv(index=False) # CSV経由の方が型トラブルが少ないケースもあるが、ここは直接Excelへ
            df_result.drop(columns=['JST_Datetime'], errors='ignore').to_excel(writer, index=False, sheet_name='Sheet1')
        excel_data = output.getvalue()
        col_dl2.download_button("📥 Excel (.xlsx)", data=excel_data, file_name="result.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        st.caption("※ Excel形式なら「秒」が隠れずに表示されます。")

        # --- 分析グラフ ---
        st.markdown("---")
        st.header("4. 📊 傾向分析")
        
        # 日付変換 (OCR直後でもファイル読み込みでもここで統一的にDatetime化)
        df_result['JST_Datetime'] = pd.to_datetime(df_result['JST (UTC + 9h)'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        valid_df = df_result.dropna(subset=['JST_Datetime']).copy()

        if not valid_df.empty:
            col1, col2 = st.columns(2)
            with col1:
                min_d, max_d = valid_df['JST_Datetime'].dt.date.min(), valid_df['JST_Datetime'].dt.date.max()
                date_range = st.date_input("期間指定", value=(min_d, max_d))
            with col2:
                ips = ["ALL_IPS"] + sorted(valid_df['loginIp'].astype(str).unique().tolist())
                selected_ip = st.selectbox("IPフィルタ", ips)

            if st.button("グラフを描画"):
                if isinstance(date_range, tuple) and len(date_range) == 2:
                    mask = (valid_df['JST_Datetime'].dt.date >= date_range[0]) & (valid_df['JST_Datetime'].dt.date <= date_range[1])
                    if selected_ip != "ALL_IPS": mask &= (valid_df['loginIp'] == selected_ip)
                    f_df = valid_df[mask]
                    
                    if not f_df.empty:
                        # グラフデータ作成
                        daily = f_df['JST_Datetime'].dt.date.value_counts().sort_index().reset_index()
                        daily.columns = ['Date', 'Count']
                        
                        hour_df = f_df['JST_Datetime'].dt.hour.value_counts().sort_index().reset_index()
                        hour_df.columns = ['Hour', 'Count']
                        hour_full = pd.DataFrame({'Hour': range(24)}).merge(hour_df, on='Hour', how='left').fillna(0)
                        
                        # 曜日データ
                        weekday_order = ['月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日', '日曜日']
                        weekday_df = f_df['JST_Datetime'].dt.dayofweek.map(
                            {0: '月曜日', 1: '火曜日', 2: '水曜日', 3: '木曜日', 4: '金曜日', 5: '土曜日', 6: '日曜日'}
                        ).value_counts().reindex(weekday_order, fill_value=0).reset_index()
                        weekday_df.columns = ['Weekday', 'Count']

                        # 描画
                        fig1, ax1 = plt.subplots(1, 2, figsize=(15, 5))
                        sns.lineplot(x='Date', y='Count', data=daily, marker='o', ax=ax1[0], color='#007BFF')
                        ax1[0].set_title("日次推移")
                        ax1[0].tick_params(axis='x', rotation=45)
                        
                        sns.barplot(x='Hour', y='Count', data=hour_full, ax=ax1[1], palette="magma")
                        ax1[1].set_title("時間帯別件数")
                        st.pyplot(fig1)
                        
                        fig2, ax2 = plt.subplots(figsize=(8, 4))
                        sns.barplot(x='Weekday', y='Count', data=weekday_df, ax=ax2, palette="plasma")
                        ax2.set_title("曜日別件数")
                        st.pyplot(fig2)

                    else:
                        st.warning("条件に一致するデータなし")
        else:
            st.warning("有効な日付データがありません。手動でJST列を修正してから再アップロードしてください。")
    else:
        if uploaded_file:
            st.error("有効なデータが見つかりませんでした。")
