import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta, timezone
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import seaborn as sns
import os
import urllib.request  # フォントダウンロード用

# ==========================================
# 0. フォント設定部 (日本語対応の決定版)
# ==========================================
def configure_japanese_font():
    """
    日本語フォント(Noto Sans JP)を自動ダウンロードして設定する関数
    Streamlit Cloudなど、日本語フォントがない環境での文字化けを防ぎます。
    """
    font_dir = "fonts"
    font_file = os.path.join(font_dir, "NotoSansJP-Regular.ttf")
    font_url = "https://raw.githubusercontent.com/google/fonts/main/ofl/notosansjp/NotoSansJP-Regular.ttf"

    # フォントディレクトリがない場合は作成
    if not os.path.exists(font_dir):
        os.makedirs(font_dir)

    # フォントファイルがない場合はダウンロード
    if not os.path.exists(font_file):
        try:
            with st.spinner("日本語フォントをダウンロード中..."):
                urllib.request.urlretrieve(font_url, font_file)
        except Exception as e:
            st.error(f"フォントのダウンロードに失敗しました: {e}")
            return

    # フォントをMatplotlibに登録
    try:
        fm.fontManager.addfont(font_file)
        font_prop = fm.FontProperties(fname=font_file)
        plt.rcParams['font.family'] = font_prop.get_name()
    except Exception as e:
        st.warning(f"フォントの設定に失敗しました: {e}")
        # フォールバック
        plt.rcParams['font.family'] = 'sans-serif'

# アプリ起動時にフォント設定を実行
configure_japanese_font()


# ==========================================
# 1. ロジック部 (元のコードの機能を完全移植)
# ==========================================

# タイムゾーン設定
JST = timezone(timedelta(hours=9), 'JST')

# 定数定義
DEFAULT_TIME_KEY = r'createdat|cneatedat|cneated'
DEFAULT_TIME_FORMAT_PATTERN = r'(\d{4}[-]\d{2}[-]\d{2}).*?(\d{2}[:]\d{2}[:]\d{2})'
DEFAULT_IP_KEY = r'loginIp|loginlp|loglnip|login|loglnip'

TIME_KEY_OPTIONS = [
    'createdAt', 'timestamp', 'logged_at', 'start_time', 'Custom (時刻キー名を入力)'
]
IP_KEY_OPTIONS = [
    'loginIp', 'sourceIp', 'clientIp', 'RemoteAddr', 'Custom (IPキー名を入力)'
]
TIME_FORMAT_OPTIONS = [
    'YYYY-MM-DDTHH:MM:SS',
    'YYYY/MM/DD HH:MM:SS',
    'YYYY-MM-DD HH:MM:SS',
    'MM/DD/YYYY HH:MM:SS',
    'Custom (YYYY-MM-DD...HH:MM:SS)'
]

# マッピング関数群
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

# データ整形・クリーニング関数 (元のロジックを維持)
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

    def normalize_key(match):
        key_text = match.group(1)
        if re.search(ip_key_regex, key_text, re.IGNORECASE):
            return '"loginIp" :'
        elif re.search(time_key_regex, key_text, re.IGNORECASE):
            return '"createdAt" :'
        return match.group(0)
    
    # 引用符の有無を判定し、常に正しい形式（"Key" :）に統一する関数
    def normalize_key_wrapper(match):
        # グループ構成: (引用符)? (キー名)
        key_text = match.group(2)
        target_key = "loginIp" if re.search(ip_key_regex, key_text, re.IGNORECASE) else "createdAt"
        return f'"{target_key}" :'

    key_fix_pattern = re.compile(rf'(")?({time_key_regex}|{ip_key_regex})[\s\W]*:', re.IGNORECASE)
    cleaned_text = key_fix_pattern.sub(normalize_key_wrapper, cleaned_text)

    # 値の修復パターン
    key_value_repair_pattern = re.compile(
                r'("createdAt"|"loginIp")[\s\W]*("[\d\-:TIZ\s\.]+"|"[0-9IiAaBbCcDdEeFf\.:]+")', 
                re.IGNORECASE | re.DOTALL
            )
    cleaned_text = key_value_repair_pattern.sub(r'\1 : \2', cleaned_text)
    
    # OCRズレの強力補正 (accountId, createdAt, loginIp の並び)
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
    
    # 時刻とIPが直接連続しているケースの補正
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
        ip_char_set = r'[\dIlAaBbCcDdEeFf]'
        ip_pattern = rf'{ip_char_set}{{1,4}}([.:]{ip_char_set}{{1,4}}){{3,7}}'
        combined_pattern = re.compile(f'({time_format_regex})|({ip_pattern})', re.DOTALL)
        matches = list(combined_pattern.finditer(cleaned_text))
        
        current_time = None
        for m in matches:
            val = m.group(0).strip()
            if re.search(time_format_regex, val):
                current_time = val
            else:
                ip_val = clean_ip_address(val)
                results.append({
                    'No.': len(results)+1, 
                    'UTC (Before Clean)': current_time if current_time else "【時刻欠落】", 
                    'UTC (Cleaned)': clean_time_string_for_display(current_time) if current_time else "【抽出失敗】", 
                    'JST (UTC + 9h)': convert_utc_to_jst(current_time) if current_time else "【抽出失敗】", 
                    'loginIp': ip_val
                })
                current_time = None
    else:
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
    # 元コードのロジックに従い、モード分岐を処理
    if mode == 'X':
        t_reg = map_time_key_to_regex('createdAt')
        i_reg = map_ip_key_to_regex('loginIp')
        t_fmt = map_time_format_to_regex('Custom (YYYY-MM-DD...HH:MM:SS)')
        cleaned = preprocess_text(raw_text, t_reg, i_reg)
        df = extract_key_based_data(cleaned, 'HYBRID', t_reg, t_fmt)
    else:
        t_reg = map_time_key_to_regex(time_key_option, custom_vals.get('time_key', ''))
        t_fmt = map_time_format_to_regex(time_format_option, custom_vals.get('time_fmt', ''))
        
        if mode == 'PATTERN':
            df = extract_key_based_data(raw_text, 'PATTERN', t_reg, t_fmt)
        else:
            i_reg = map_ip_key_to_regex(ip_key_option, custom_vals.get('ip_key', ''))
            cleaned = preprocess_text(raw_text, t_reg, i_reg)
            df = extract_key_based_data(cleaned, 'HYBRID', t_reg, t_fmt)
    return df

# ==========================================
# 2. UI部
# ==========================================

st.set_page_config(page_title="読取大臣 Web版", layout="wide", page_icon="🕵️")

st.title("🕵️ 読取大臣 v1.4.3 (Streamlit版)")
st.caption("AI Log Analysis System Engine - Desktop Logic Ported to Web")

# --- サイドバー (設定エリア) ---
st.sidebar.header("1. ⚙️ 設定")

mode_select = st.sidebar.radio("抽出モード", ["X (デフォルト・固定キー)", "Other (カスタム設定)"], index=0)
mode_code = "X" if "X" in mode_select else "Other"

# 初期値設定
detection_mode = "HYBRID"
time_key_opt = "createdAt"
ip_key_opt = "loginIp"
time_fmt_opt = "Custom (YYYY-MM-DD...HH:MM:SS)"
custom_inputs = {'time_key': '', 'ip_key': '', 'time_fmt': ''}

if mode_code == "Other":
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Otherモード設定**")
    detection_mode = st.sidebar.radio("検出方法", ["HYBRID (ハイブリッド)", "PATTERN (パターンのみ)"])
    detection_code = "HYBRID" if "HYBRID" in detection_mode else "PATTERN"
    
    # HYBRIDの場合のみキー設定を表示
    if detection_code == "HYBRID":
        time_key_opt = st.sidebar.selectbox("時刻キー名", TIME_KEY_OPTIONS)
        if "Custom" in time_key_opt:
            custom_inputs['time_key'] = st.sidebar.text_input("カスタム時刻キー名")
            
        ip_key_opt = st.sidebar.selectbox("IPキー名", IP_KEY_OPTIONS)
        if "Custom" in ip_key_opt:
            custom_inputs['ip_key'] = st.sidebar.text_input("カスタムIPキー名")

    time_fmt_opt = st.sidebar.selectbox("時刻表記", TIME_FORMAT_OPTIONS)
    if "Custom" in time_fmt_opt:
        custom_inputs['time_fmt'] = st.sidebar.text_input("カスタム時刻パターン")

    st.sidebar.info(
        "💡 **ハイブリッド検知**: キー名と値のパターンの両方を見ます。\n"
        "💡 **パターン検知**: 値の形式（日付やIPの形状）のみを見て抽出します。"
    )

# --- メインエリア (ファイルアップロードと実行) ---
st.header("2. 📂 ファイルアップロード")
uploaded_file = st.file_uploader("OCRテキストファイル (.txt) を選択", type="txt")

if uploaded_file is not None:
    # ファイル読み込み (文字化け対策込み)
    try:
        raw_text = uploaded_file.read().decode("utf-8")
    except UnicodeDecodeError:
        try:
            uploaded_file.seek(0)
            raw_text = uploaded_file.read().decode("cp932")
            st.warning("⚠️ Shift-JIS (cp932) として読み込みました。")
        except Exception:
            st.error("ファイルの読み込みに失敗しました。エンコーディングを確認してください。")
            st.stop()

    # 処理実行
    with st.spinner('データ抽出中... (AI Logic Engine Running)'):
        # Otherモードの場合は、detection_code (PATTERN or HYBRID) をモードとして渡す必要があるため調整
        exec_mode = mode_code
        if mode_code == "Other":
            exec_mode = detection_code # PATTERN か HYBRID を渡す

        df_result = extract_ip_audit_data_final(
            raw_text, 
            mode=exec_mode,
            time_key_option=time_key_opt,
            ip_key_option=ip_key_opt,
            time_format_option=time_fmt_opt,
            custom_vals=custom_inputs
        )

    if not df_result.empty:
        # 結果表示
        st.success(f"✅ 抽出完了！ {len(df_result)} 件のレコードが見つかりました。")
        
        # エラー警告の表示 (欠落チェック)
        err_ip = df_result['loginIp'].astype(str).str.contains('【IP欠落', na=False).sum()
        err_ts = df_result['UTC (Before Clean)'].astype(str).str.contains('【時刻欠落', na=False).sum()
        if err_ip > 0 or err_ts > 0:
            st.warning(f"🚨 データ欠落のあるレコードを {err_ip + err_ts} 件検出しました。CSVで内容を確認してください。")

        st.subheader("3. 📝 抽出結果プレビュー")
        st.dataframe(df_result, use_container_width=True)
        
        # CSVダウンロード
        csv_data = df_result.drop(columns=['JST_Datetime'], errors='ignore').to_csv(index=False, encoding='cp932')
        st.download_button(
            label="📥 結果をCSVとして保存 (Shift-JIS)",
            data=csv_data,
            file_name="yomidai_result_web.csv",
            mime="text/csv"
        )

        # --- 分析セクション ---
        st.markdown("---")
        st.header("4. 📊 傾向分析と可視化")

        # 前処理: JST文字列をdatetime型に変換
        df_result['JST_Datetime'] = pd.to_datetime(df_result['JST (UTC + 9h)'], format='%Y/%m/%d %H:%M:%S', errors='coerce')
        valid_df = df_result.dropna(subset=['JST_Datetime']).copy()

        if valid_df.empty:
            st.warning("有効な日付データがないため、分析できません。")
        else:
            col1, col2 = st.columns(2)
            with col1:
                # 日付範囲指定 (StreamlitのDate Inputを使用)
                min_date = valid_df['JST_Datetime'].dt.date.min()
                max_date = valid_df['JST_Datetime'].dt.date.max()
                
                date_range = st.date_input("期間指定", value=(min_date, max_date))
            
            with col2:
                # IPフィルタリング
                unique_ips = ["ALL_IPS"] + sorted(valid_df['loginIp'].unique().tolist())
                selected_ip = st.selectbox("IPフィルタ", unique_ips)

            if st.button("グラフを描画"):
                if isinstance(date_range, tuple) and len(date_range) == 2:
                    start_d, end_d = date_range
                    # フィルタリング実行
                    filter_mask = (valid_df['JST_Datetime'].dt.date >= start_d) & (valid_df['JST_Datetime'].dt.date <= end_d)
                    if selected_ip != "ALL_IPS":
                        filter_mask &= (valid_df['loginIp'] == selected_ip)
                    
                    filtered_df = valid_df[filter_mask].copy()
                    
                    if filtered_df.empty:
                        st.warning("条件に一致するデータがありません。")
                    else:
                        # --- 集計ロジック (Matplotlib/Seaborn用) ---
                        daily_df = filtered_df['JST_Datetime'].dt.date.value_counts().sort_index().reset_index()
                        daily_df.columns = ['Date', 'Count']
                        
                        monthly_df = filtered_df['JST_Datetime'].dt.to_period('M').value_counts().sort_index().reset_index()
                        monthly_df.columns = ['Month', 'Count']
                        monthly_df['Month'] = monthly_df['Month'].astype(str)

                        weekday_order = ['月曜日', '火曜日', '水曜日', '木曜日', '金曜日', '土曜日', '日曜日']
                        weekday_df = filtered_df['JST_Datetime'].dt.dayofweek.map(
                            {0: '月曜日', 1: '火曜日', 2: '水曜日', 3: '木曜日', 4: '金曜日', 5: '土曜日', 6: '日曜日'}
                        ).value_counts().reindex(weekday_order, fill_value=0).reset_index()
                        weekday_df.columns = ['Weekday', 'Count']

                        hour_full_df = pd.DataFrame({'Hour': range(24)})
                        hour_count = filtered_df['JST_Datetime'].dt.hour.value_counts().reset_index()
                        hour_count.columns = ['Hour', 'Count']
                        hour_df = hour_full_df.merge(hour_count, on='Hour', how='left').fillna(0)

                        # ヒートマップ用データ作成
                        heatmap_data = filtered_df.copy()
                        heatmap_data['Hour'] = heatmap_data['JST_Datetime'].dt.hour
                        heatmap_data['Weekday'] = heatmap_data['JST_Datetime'].dt.dayofweek.map(
                            {0: '月曜日', 1: '火曜日', 2: '水曜日', 3: '木曜日', 4: '金曜日', 5: '土曜日', 6: '日曜日'}
                        )
                        heatmap_pivot = heatmap_data.groupby(['Hour', 'Weekday']).size().unstack(fill_value=0)
                        heatmap_pivot = heatmap_pivot.reindex(columns=weekday_order, fill_value=0)
                        heatmap_pivot = heatmap_pivot.reindex(range(24), fill_value=0)

                        # --- 描画 (Matplotlib) ---
                        st.markdown("### 分析グラフ")
                        
                        # 1. 日次 & 月次
                        fig1, ax1 = plt.subplots(1, 2, figsize=(15, 6))
                        sns.lineplot(x='Date', y='Count', data=daily_df, marker='o', ax=ax1[0], color='#007BFF')
                        ax1[0].set_title("日次推移", fontsize=14)
                        ax1[0].tick_params(axis='x', rotation=45)
                        ax1[0].grid(True, linestyle='--', alpha=0.6)
                        
                        sns.barplot(x='Month', y='Count', data=monthly_df, ax=ax1[1], palette="viridis")
                        ax1[1].set_title("月別件数", fontsize=14)
                        st.pyplot(fig1)

                        # 2. 曜日 & 時間帯
                        fig2, ax2 = plt.subplots(1, 2, figsize=(15, 6))
                        sns.barplot(x='Weekday', y='Count', data=weekday_df, ax=ax2[0], palette="plasma")
                        ax2[0].set_title("曜日別件数", fontsize=14)
                        
                        sns.barplot(x='Hour', y='Count', data=hour_df, ax=ax2[1], palette="magma")
                        ax2[1].set_title("時間帯別件数", fontsize=14)
                        st.pyplot(fig2)

                        # 3. ヒートマップ
                        fig3, ax3 = plt.subplots(figsize=(12, 8))
                        sns.heatmap(heatmap_pivot, annot=True, fmt="d", cmap="YlGnBu", ax=ax3, annot_kws={'size': 10, 'weight': 'bold'})
                        ax3.set_title("曜日×時間帯 ヒートマップ", fontsize=16)
                        st.pyplot(fig3)
                else:
                    st.error("正しい期間を選択してください。")

    else:
        st.error("データの抽出に失敗しました。ファイルの内容または設定を確認してください。")

else:
    st.info("左側のサイドバーで設定を行い、ファイルをアップロードしてください。")
