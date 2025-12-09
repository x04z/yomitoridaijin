import streamlit as st
import re
import pandas as pd
from datetime import datetime, timedelta, timezone

# --- 1. 定数とユーティリティ関数 ---

# 日本標準時 (JST) のタイムゾーンオブジェクト (UTC+9)
JST = timezone(timedelta(hours=9), 'JST')

def clean_time_string_for_parsing(time_str):
    """
    OCR誤認識を修正し、datetime.strptimeでパース可能な
    標準形式 (YYYY-MM-DDTHH:MM:SS) に整形する
    【パース用】: Zやミリ秒は含まない
    """
    
    # 1. l/I -> 1 の置換（ll -> 11 への対応）
    cleaned = time_str.replace('l', '1').replace('I', '1')
    
    # 2. 余分なノイズ文字を削除
    # この関数は新しい抽出ロジックでは主に時刻のクリーンアップに利用される
    cleaned = cleaned.replace("'", "").replace("b", "").replace(">", "").replace("`", "")

    # 3. 日付と時刻を厳密な正規表現で抽出
    # YYYY-MM-DD と HH:MM:SS のパターンに一致する部分を検索
    date_pattern = re.search(r'(\d{4}[-]\d{2}[-]\d{2})', cleaned)
    time_pattern = re.search(r'(\d{2}[:]\d{2}[:]\d{2})', cleaned)
    
    if date_pattern and time_pattern:
        date_part = date_pattern.group(1)
        time_part = time_pattern.group(1)
        
        # 4. 標準形式 YYYY-MM-DDTHH:MM:SS で再構築
        return f"{date_part}T{time_part}"
    else:
        return ""

def clean_time_string_for_display(time_str):
    """
    ユーザーが視認するためのクリーン済みUTC文字列 (YYYY-MM-DDTHH:MM:SS.000Z) を生成する
    【表示用】: .000Z を付与
    """
    # 新しいロジックでは、抽出された時刻文字列が既にクリーンに近い形式であるため
    # clean_time_string_for_parsing を通して、念のため形式を統一
    parsed_str = clean_time_string_for_parsing(time_str)
    
    if parsed_str:
        return f"{parsed_str}.000Z"
    return "**[抽出失敗]**"


def convert_utc_to_jst(utc_datetime_str):
    """
    UTC時刻文字列をJSTに変換し、'YYYY-MM-DD HH:MM:SS'形式で返す
    """
    # 抽出された時刻文字列は、この関数に渡される前にパース可能な形式になっていることが期待されるが、
    # 念のため clean_time_string_for_parsing を通す
    cleaned_time_str = clean_time_string_for_parsing(utc_datetime_str)
    
    if not cleaned_time_str:
        return "**[パースエラー - 抽出失敗]**"

    try:
        dt_obj_utc_naive = datetime.strptime(
            cleaned_time_str,
            '%Y-%m-%dT%H:%M:%S'
        )
        
        dt_obj_utc = dt_obj_utc_naive.replace(tzinfo=timezone.utc)
        dt_obj_jst = dt_obj_utc.astimezone(JST)
        
        return dt_obj_jst.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        return f"**[パースエラー - 形式不正]** (クリーン後: {cleaned_time_str}, エラー: {e})"

def extract_ip_audit_data_final(raw_text):
    """
    OCRテキストから、UTC時刻とIPアドレスのペアを抽出し、DataFrameを返す
    ロジック変更: 時刻とIPアドレスのペアを同時に検索する正規表現を使用
    """
    
    # 1. l/I -> 1 の置換（ll -> 11 への対応）をまず全体に行う
    # テキスト全体をクリーンアップ
    cleaned_text_for_search = raw_text.replace('l', '1').replace('I', '1')
    
    # 2. UTC時刻とIPアドレスのペアを同時に抽出する正規表現
    # グループ1: UTC時刻 (YYYY-MM-DDTHH:MM:SS)
    # グループ2: IPアドレス (d.d.d.d)
    # OCR結果の特性上、時刻とIPアドレスの間に様々なノイズや改行があるため、re.DOTALL (.が改行も含む) を使用し、.*? (非貪欲マッチ) で結合する
    combined_pattern = re.compile(
        r'(\d{4}[-]\d{2}[-]\d{2}[T]\d{2}[:]\d{2}[:]\d{2})'  # 確実に時刻部分をキャプチャ (グループ1)
        r'.*?'                                              # 時刻とIPの間の任意の文字（非貪欲マッチで次のIPへ）
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'              # 確実にIPアドレス部分をキャプチャ (グループ2)
        , re.DOTALL                                         # .が改行も含むようにする
    )
    
    # テキスト全体からすべてのマッチング結果をリストで取得
    # all_pairs は [(utc_time_str, ip_address_str), ...] のタプルのリストになる
    all_pairs = combined_pattern.findall(cleaned_text_for_search)

    st.info(f"抽出されたUTC時刻・IPアドレスのペアレコード数: **{len(all_pairs)}**")

    results = []
    
    for utc_time_raw, ip_address in all_pairs:
        
        results.append({
            'UTC (元データ)': utc_time_raw.strip(),
            'UTC (クリーン済)': clean_time_string_for_display(utc_time_raw),
            'JST (UTC + 9時間)': convert_utc_to_jst(utc_time_raw),
            'IPアドレス (loginIp)': ip_address.strip()
        })

    return pd.DataFrame(results)

# --- 2. Streamlit UI定義 ---

st.title("🫅 読取大臣（仮）V1.2.1")
st.markdown("動作確認用のテスト版を作成しました。")
st.markdown("OCRテキストの構造（時刻とIPが離れている）に対応するため、**時刻とIPアドレスのパターンを同時に検索し、それらをペアとして抽出する**ロジックに修正しました。")
st.markdown("createdAtのキー名誤認識（cneatedAt）の直接的な検出は不要になりました。")
st.markdown("IPアドレスの抽出は、3つの「.」で区切られた4つの数値の組み合わせを抽出します。IPv6には対応していません。")
st.markdown("createdAtの文字やIPアドレスの数字がほかの文字に誤認識された場合は、その文字も反映できるようにしますので教えてください！")
st.markdown("アップロードされたテキストファイルは、このアプリ内で処理・完結します。なので、情報漏えいの心配はありません。心配の方はGitHubからPythonコードを見て判断してください!")
st.markdown("---")
st.markdown("### 読取革命のスキャンのコツとやり方")
st.markdown("- エクセレントモードでスキャンする。")
st.markdown("- 英語モードに設定する（どっちか忘れましたけど、アメリカかイギリスの国旗のマークだったと思います。)")
st.markdown("- PDFのページ全体を四角で囲って抽出範囲の選択をする。（ただし、余計な上の部分や下のページ番号、PGP SIGNATUREなどの暗号部分は選択しない。）")
st.markdown("- 一太郎のアイコンからtxt形式で保存する。")
st.markdown("- 保存したtxtファイルをこのアプリにアップロードする。")
st.markdown("---")

# ファイルアップローダーウィジェット
uploaded_file = st.file_uploader(
    "テキストファイル (例：yomikaku.txt) をアップロードしてください", 
    type=['txt']
)

if uploaded_file is not None:
    try:
        raw_text = uploaded_file.read().decode('utf-8')
        st.success(f"ファイル名: **{uploaded_file.name}** を読み込みました。")
        
        # 処理実行
        df_result = extract_ip_audit_data_final(raw_text)
        
        st.header("✅ 抽出・変換結果")
        
        if not df_result.empty:
            if df_result['JST (UTC + 9時間)'].str.contains('エラー').any():
                st.warning("一部の時刻データの変換に失敗しました。パースエラーの詳細を確認してください。")
            
            # 連番(番号)列を新設し、一番左に移動させる
            df_result.insert(0, '番号', range(1, 1 + len(df_result)))
            
            # Streamlit表示用のDataFrameを準備（インデックスの連番化は行わない）
            st.dataframe(
                df_result,
                use_container_width=True,
                # Streamlitのデフォルトインデックス（謎の列）は表示させない
                hide_index=True 
            )

            # CSVダウンロードボタン
            @st.cache_data
            def convert_df_to_csv(df):
                # エンコーディングはCP932（Shift-JIS）を維持、番号列があるので index=False でOK
                # Note: セーブ情報に基づき、数字にカンマは入れずシンプルなテキストとして記述されます。
                return df.to_csv(index=False, encoding='cp932').encode('cp932')
            
            csv = convert_df_to_csv(df_result)
            st.download_button(
                label="📥 結果をCSVとしてダウンロード",
                data=csv,
                file_name='yomidai.csv',
                mime='text/csv',
            )
            
        else:
            st.error("ファイルから有効なデータパターンを抽出できませんでした。")

    except Exception as e:
        st.error(f"ファイルの処理中に予期せぬエラーが発生しました: {e}")
