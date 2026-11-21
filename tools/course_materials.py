"""Build the report and slide deck from a tested snapshot and measured benchmark."""
import json
import re
import subprocess
import threading
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn
from docx.shared import Cm, Pt
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.util import Inches, Pt as SlidePt
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server
from backend.app import app

OUT = Path("build")
B = json.loads((OUT / "benchmark.json").read_text())

BEFORE = B["before"]["median_ms"]
AFTER = B["after"]["median_ms"]
FONT = "Noto Sans CJK SC"


E = json.loads((OUT / "library-evidence.json").read_text())
PILLOW_HITS = 0


def figures():
    global PILLOW_HITS
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1160, "height": 790})
            page.goto(f"http://127.0.0.1:{server.server_port}/?q=pillow")
            page.get_by_role("heading", name="查软件包").wait_for()
            page.screenshot(path=OUT/"home.png")
            page.get_by_role("link", name=re.compile("Python 图片处理库")).click()
            page.get_by_role("link", name="只看有命中的版本").click()
            page.get_by_role("heading", name=re.compile("版本与漏洞")).scroll_into_view_if_needed()
            page.locator("#versions").screenshot(path=OUT/"versions.png")
            page.get_by_role("link", name="12.3.0", exact=True).click()
            heading = page.locator("#version-result h2")
            heading.wait_for()
            PILLOW_HITS = int(heading.inner_text().split("命中")[1].split()[0])
            assert PILLOW_HITS > 0
            browser.close()
    finally:
        server.shutdown()
        thread.join()
    dot = """digraph {
      rankdir=LR;graph[bgcolor=white,dpi=155,nodesep=.22,ranksep=.43];
      node[shape=box,style="rounded,filled",fillcolor="#e7f2ed",color="#90b7ae",fontname="DejaVu Sans",fontsize=10];
      edge[color="#426c67",arrowsize=.55];
      lib_package -> lib_affected; lib_advisory -> lib_affected; lib_affected -> lib_span;
      lib_package -> lib_release; lib_package -> lib_profile; lib_project -> lib_profile;
      lib_profile -> lib_edge; lib_project -> lib_check; lib_advisory -> lib_alias;
      lib_alias -> lib_nvd [style=dashed,label="CVE"]; lib_nvd -> lib_cpe;
    }"""
    subprocess.run(["dot","-Tpng","-o",str(OUT/"er.png")],input=dot,text=True,check=True)


def report():
    d = Document()
    sec = d.sections[0]
    sec.page_height, sec.page_width = Cm(29.7), Cm(21)
    sec.top_margin, sec.bottom_margin = Cm(2), Cm(1.8)
    sec.left_margin, sec.right_margin = Cm(2.3), Cm(2.3)
    sec.footer.paragraphs[0].text = "数据库系统课程报告   ·   VulnLensDB"
    for style_name in ["Normal", "Title", "Heading 1", "Heading 2"]:
        s = d.styles[style_name]
        s.font.name = FONT
        s.element.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), FONT)
    d.styles["Normal"].font.size = Pt(10.5)
    def h(text): d.add_heading(text, 1)
    def p(text): d.add_paragraph(text)
    def t(headers, rows):
        table = d.add_table(rows=0, cols=len(headers))
        table.style = "Light Shading Accent 1"
        for row in [headers, *rows]:
            for cell, value in zip(table.add_row().cells, row):
                cell.text = str(value)
    def fig(name, width): d.add_picture(str(OUT/name), width=Cm(width))
    counts = E["counts"]
    d.add_heading("开源依赖漏洞多源整合数据库", 0)
    p("数据库系统课程报告　　VulnLensDB　　姓名／学号／组号：________________")
    h("1　选题与功能需求")
    p("开发者输入软件包和固定版本，查询命中的公开漏洞公告、严重度与修复端点。数据库需要处理同一漏洞的多个编号、一个公告关联多个软件包，以及多个维护分支各自的受影响区间。")
    p(f"系统整合 PyPI、Maven、Go 三个生态，包含 {counts['lib_package']:,} 个软件包、{counts['lib_advisory']:,} 条去重公告和 {counts['lib_span']:,} 段版本区间。游客可以查询和导出结果，注册用户可保存检查摘要，管理员可刷新包级统计。")
    fig("home.png", 15.5)
    p("图 1　按软件包浏览。同一个生态的同名包合并为一条结果，完整名称排在部分匹配之前。")
    d.add_page_break()
    h("2　关系模型与完整性")
    fig("er.png", 15.5)
    p("图 2　核心实体与明细。虚线表示两源按 CVE 字符串对齐。")
    t(["实体组", "主键与约束", "行数"], [
        ("包与公告", "lib_package 的生态和名称唯一。lib_advisory 以公告编号为主键。",
         f"{counts['lib_package']:,} 包／{counts['lib_advisory']:,} 公告"),
        ("受影响关系", "lib_affected 以包 ID 与公告 ID 为联合键。lib_span 以同一组合外键引用。",
         f"{counts['lib_affected']:,} 关系／{counts['lib_span']:,} 区间"),
        ("别名与官方数据", "lib_alias 以别名为主键。lib_cpe 以 CVE 外键连接 lib_nvd。",
         f"{counts['lib_alias']:,} 别名／{counts['lib_nvd']} CVE"),
        ("版本与画像", "lib_release 主键为包和版本。lib_profile 链接采样版本与项目。",
         f"{counts['lib_release']:,} 发行记录／{counts['lib_project']} 源码项目"),
        ("依赖与统计", "依赖边保留解析图的根版本。物化统计每包一行。",
         f"{counts['lib_edge']} 条边／{counts['lib_stats']:,} 统计行"),
    ])
    p("公告内容、包版本发布时间和项目评分分别存储，避免在每个区间或每条依赖边复制属性。更新快照时，统计与源表在同一事务内提交。")
    d.add_page_break()
    h("3　索引与查询")
    p("使用 InnoDB。包和公告关联表的组合键支持定位单包公告。标题与 NVD 英文描述全文索引支持关键词查找，编号、包名和标题也支持字面子串匹配。SQL 接收绑定参数。")
    t(["编号与功能", "查询实现"], [
        ("Q1／Q7　单版与批量检查", "按包键读取区间和显式版本，逐项判定。支持固定版本 POM、requirements.txt 与 CSV。"),
        ("Q2　双源详情", "按 CVE 别名关联 OSV 公告与 NVD 产品配置。Git 区间和完整 CPE 配置逻辑由源站复核。"),
        ("Q3　近十二个月高危", "按快照时间限制窗口，COUNT DISTINCT、GROUP BY 与 HAVING。"),
        ("Q4　来源覆盖", "LEFT JOIN、NOT EXISTS、UNION ALL 计算交集与单边集合。"),
        ("Q5　公告搜索", "精确和子串条件配合 FULLTEXT，支持生态、严重度、年份和分页。"),
        ("Q6　下游影响面", "按不同下游包计数，DENSE_RANK 对并列给出相同排名。"),
        ("Q8　修复历史", "按公告分区，用 ROW_NUMBER 找到最早有发布日期的修复版。"),
        ("Q9　健康评分分层", "用 NTILE(4) 分组，再按每百个发行版本计算公告密度。"),
    ])
    h("4　数据工程与覆盖范围")
    p("OSV 按生态导出，过滤撤回记录和 MAL 编号，借助共有别名合并公告。PyPI 包名归一化，Maven 和 Go 保留坐标与路径。NVD 由指定 CVE 和一个独立的时间窗样本组成。deps.dev 采集固定根版本的图、发行记录与 Scorecard。")
    p("当前 NVD 与依赖图用于样本对照。仅在某一来源出现，表示本次采集中的差异。下游排名和健康度分层只按已采集记录计算。快照与来源清单位于 data/library。")
    d.add_page_break()
    h("5　版本查询与结果呈现")
    fig("versions.png", 15.5)
    p("图 3　Pillow 版本表。每个版本有确认命中的公告总数与严重度分布。点版本可以看到具体公告与修复端点。")
    p("PyPI 按 PEP 440，Go 用语义版本。Maven 支持数值版本区间和 OSV 显式版本列表。无法比较的区间显示待核对。修复端点为开区间，last_affected 为闭区间。")
    p(f"浏览器实测 Pillow 12.3.0，当前快照命中 {PILLOW_HITS} 条公告。版本发布日期来自已采集的 deps.dev 发行记录。缺少发行列表的包可查 OSV 中出现的版本和端点，也可手动检查固定版本。")
    d.add_page_break()
    h("6　云端运行与索引实验")
    p(f"MySQL {B['mysql']}，Python {B['python']}。每组先执行 EXPLAIN ANALYZE，再计时七次取中位数。计时包含数据库往返和读取结果。索引前后返回记录逐行一致。")
    t(["被测数据", "行数／命中", "加索引前后中位数（ms）"], [
        ("全部真实包公告关联", f"{E['full_rows']:,}／{E['matched']}", f"{E['before']['median_ms']} → {E['after']['median_ms']}"),
        ("百万行合成压力表", f"{B['synthetic_rows']:,}／{B['matched']}", f"{BEFORE} → {AFTER}"),
    ])
    p("真实关系实验固定 Django 的包 ID，增加 (package_id, advisory_id) 索引后由扫描临时表转为索引定位。合成表包含一万个均匀分布的包。实验使用单连接和热缓存。执行计划与每轮值可从两份 JSON 复查。")
    p("GitHub Actions 在独立 MySQL 环境运行回归测试。浏览器验收覆盖包搜索、版本筛选和明细，包含原始来源页面。代码使用参数绑定、XML 安全解析、上传大小限制、密码散列和写操作的 CSRF 令牌。")
    h("7　使用帮助与工具声明")
    p("启动 Codespace 后打开转发端口。先搜 Pillow，再查看版本表，切到公告目录查询 CVE-2021-44228，最后在统计查询中展开 Q6 与 Q9 的 SQL。")
    p("使用 Codex 辅助设计、写代码、跑云端测试与整理交付材料。数据处理使用 Python，数据库使用 MySQL，应用使用 Flask，截图由 Chromium 从实际页面生成。")
    d.add_page_break()
    h("8　可持续性")
    p("仓库保留采集脚本、压缩快照和采集时间。数据导入具备指纹检查，提交失败时回滚。问题复核使用公告编号与源站链接。扩充依赖图时可以沿用同一表结构和验证脚本。")
    h("9　总结")
    p("完成三生态公告整合、版本命中、双源范围、下游影响面和评分分层。当前 NVD 与依赖图的样本规模限制了分析结论。Maven 复杂限定符以明确的 OSV 版本证据或待核对状态呈现。")
    h("10　个人贡献说明")
    p("姓名／学号／组号：________________")
    p("实际分工、本人复核的案例及学习反思由本人据实填写。")
    p("复核文件包含 sql/library.sql、backend/library.py、tools/verify_library.py 和 data/library/manifest.json。来源为 OSV、NVD 和 deps.dev。")
    d.save(OUT/"VulnLensDB-report.docx")


def slides():
    deck = Presentation()
    deck.slide_width, deck.slide_height = Inches(13.333), Inches(7.5)
    def slide(title):
        s = deck.slides.add_slide(deck.slide_layouts[6])
        s.background.fill.solid()
        s.background.fill.fore_color.rgb = RGBColor.from_string("F6F8F4")
        label(s,title,.7,.45,12,1,32,"123B40")
        return s
    def label(s,txt,x,y,w,h,size,color="243B3D"):
        box = s.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
        box.text_frame.word_wrap = True
        for i,line in enumerate(txt.split("\n")):
            para = box.text_frame.paragraphs[0] if i==0 else box.text_frame.add_paragraph()
            r=para.add_run(); r.text=line; r.font.name=FONT; r.font.size=SlidePt(size)
            r.font.color.rgb=RGBColor.from_string(color)
    def pic(s,file,x,y,w): s.shapes.add_picture(str(OUT/file), Inches(x), Inches(y), width=Inches(w))
    counts = E["counts"]
    s = slide("开源依赖漏洞多源整合数据库")
    label(s,"从软件包到具体版本\n用公开数据解释一次漏洞命中",.8,2.1,11.8,2.1,37)
    label(s,"VulnLensDB   /   数据库系统课程答辩",.8,5.7,11.8,.7,21,"16695D")
    s = slide("三个来源覆盖不同层次")
    for i,(title,desc) in enumerate([
        ("OSV",f"{counts['lib_advisory']:,} 条去重公告 · PyPI、Maven、Go"),
        ("NVD",f"{counts['lib_nvd']} 条 CVE 样本 · 分数与 CPE 产品配置"),
        ("deps.dev",f"{counts['lib_profile']} 个根版本 · 依赖图、发行记录与 Scorecard")
    ]):
        label(s,title,.9,1.8+i*1.4,2.8,.8,27,"14695F")
        label(s,desc,3.8,1.8+i*1.4,8.6,.85,24)
    s = slide("用包和公告关联受影响区间")
    pic(s,"er.png",2.6665,1.45,8.0)
    label(s,"来源独立保存，通过软件包标识和 CVE 连接。",.9,6.3,11.7,.7,21)
    s = slide("先找软件包 再查具体版本")
    pic(s,"versions.png",.75,1.45,7.8)
    label(s,f"搜索 Pillow，筛选有命中的版本。\n\n12.3.0 命中 {PILLOW_HITS} 条公告。\n\n点公告可查看修复端点和来源。",8.8,1.65,4,4.8,22)
    s = slide("下游依赖与健康度如何统计")
    label(s,"Q6  下游依赖排名",.9,1.8,11.5,.8,28,"14695F")
    label(s,"按不同下游包计数。跨多个解析图的同包边只计一次。",.9,2.7,11.5,1,23)
    label(s,"Q9  Scorecard 分层",.9,4.1,11.5,.8,28,"14695F")
    label(s,"按得分分四组，比较每百个发行版本的公告数。",.9,5,11.5,1.1,23)
    s = slide("真实包公告关联的联合索引实验")
    label(s,f"{E['before']['median_ms']} ms",.9,2,5.8,1.1,42)
    label(s,f"{E['after']['median_ms']} ms",7,2,5.8,1.1,42,"14695F")
    label(s,"扫描临时表",.9,3.35,5.7,.85,26)
    label(s,"按包和公告联合键定位",7,3.35,5.7,.85,26)
    label(s,f"全量 {E['full_rows']:,} 条真实关联。七次查询取中位数，前后均返回 {E['matched']} 条。\n百万行合成压力实验另附原始数据。",.9,5.1,11.8,1.4,21)
    s = slide("现场演示与数据范围")
    label(s,"1  搜索 Pillow，点开受影响版本。\n\n2  在公告目录打开 Log4j 的 OSV 与 NVD 对照。\n\n3  查看下游排名、评分分层和执行计划。",.9,1.65,11.7,4.5,25)
    label(s,"NVD 与依赖图采用采样覆盖。",.9,6.2,11.7,.7,20,"14695F")
    deck.save(OUT/"VulnLensDB-defense.pptx")


if __name__ == "__main__":
    figures()
    report()
    slides()
