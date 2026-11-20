"""Build the report and slide deck from a tested snapshot and measured benchmark."""
import json
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
C = B["counts"]
BEFORE = B["before"]["median_ms"]
AFTER = B["after"]["median_ms"]
FONT = "Noto Sans CJK SC"


def figures():
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1050, "height": 720}, device_scale_factor=1)
            page.goto(f"http://127.0.0.1:{server.server_port}/")
            page.get_by_text("开源依赖漏洞目录", exact=True).wait_for()
            page.screenshot(path=OUT / "home.png")
            page.get_by_role("link", name="依赖检查").click()
            page.locator("textarea").fill("django==3.2.9\ndjango==3.2.13\nflask==3.0")
            page.locator("form button").click()
            page.get_by_text("包未收录", exact=True).wait_for()
            page.get_by_text("本快照未命中", exact=True).wait_for()
            page.screenshot(path=OUT / "check.png", full_page=True)
            browser.close()
    finally:
        server.shutdown()
        thread.join()
    dot = """digraph {rankdir=LR;graph [bgcolor=white,dpi=155];
    node [shape=box,style="rounded,filled",color="#acd1c8",fillcolor="#eaf4ef",fontname="DejaVu Sans"];
    edge [fontname="DejaVu Sans",fontsize=10,color="#39716c"];
    package -> package_release [label="1:N"];package_release -> affected_range [label="1:N"];
    advisory -> affected_range [label="1:N"];advisory -> advisory_alias [label="1:N"];
    advisory_alias -> nvd_rating [label="CVE lookup",style=dashed];advisory -> evidence [label="1:N"];}"""
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
    d.add_heading("开源依赖漏洞多源整合数据库", 0)
    p("数据库系统课程报告　　VulnLensDB　　姓名／学号／组号：________________")
    h("1　选题与需求分析")
    p("同一漏洞可能拥有多个编号，并分别影响一个包的多条维护分支。本项目回答三个问题：某个固定版本是否命中已收录公告，修复端点在哪里，判定依据来自哪个来源。")
    p("目标用户是维护 Python 项目的开发者。输入包名、别名或不超过 20 项的精确版本清单，输出公告、评分、命中区间及原始证据。公开页面只读，数据刷新由维护者在云端执行。")
    fig("home.png",15.3)
    p("图 1　真实快照的目录首页。页面计数由 MySQL 查询产生。")
    d.add_page_break()
    h("2　概念设计与逻辑设计")
    fig("er.png",16)
    p("图 2　箭头从父实体指向明细。虚线表示按 CVE 值关联；两个来源可以独立存在，因此这里保留逻辑匹配。")
    t(["关系","主键或唯一标识","快照行数"],[(k,pk,C[k]) for k,pk in [
       ("package","name"),("advisory","id"),("advisory_alias","alias_id"),("affected_range","公告、包、起点、修复端点"),
       ("package_release","包、版本"),("nvd_rating","cve"),("evidence","公告、来源、URL")]])
    p("核心表 affected_range 的 introduced 与 fixed 保存原始版本字符串。introduced 为 0 表示没有下界。联合主键约束同一区间只出现一次；包与修复版的组合外键使每个修复端点都能关联到已导入的发布日期。")
    p("修复版发布时间依赖于包和版本，NVD 评分依赖于 CVE，公告摘要依赖于 OSV 编号。将三类事实分表，可避免在多个区间重复更新同一项属性。详情查询用连接恢复这些关系。")
    d.add_page_break()
    h("3　物理设计与 SQL 实现")
    p("引擎采用 InnoDB。主键和外键维护实体完整性，by_package(package_name, advisory_id) 支持按包定位区间，英文公告标题使用 FULLTEXT。版本比较由 packaging.version.Version 执行。")
    t(["查询","实现及判读"],[
      ("Q1／Q7 版本命中","一次按包名集合取回候选区间，再逐项比较 introduced ≤ version < fixed；保留输入顺序。"),
      ("Q2／Q5 公告搜索","编号走精确匹配或 EXISTS 别名子查询；英文标题走 MATCH … AGAINST。"),
      ("Q3 等级分布","对公告按 OSV 等级 GROUP BY，并以 HAVING 筛选非空组。"),
      ("Q4 两源覆盖","NOT EXISTS、LEFT JOIN 与 UNION ALL 组合单边集合和交集。"),
      ("Q6 包排名","先按包聚合 MAX(score)，再用 DENSE_RANK 排序。"),
      ("Q8 修复历史","LAG 按包分区，按发布时间和版本标识排序，给出前一条样本记录。"),
      ("Q9 证据覆盖","按 provider 统计链接、去重公告和采集时间。")])
    h("4　数据工程")
    p("采集器用 OSV 主编号获取 PyPI 区间和别名，再用 CVE 查询 NVD CVSS 3.1 评分，用规范化包名与修复版本查询 deps.dev 发布日期。三源数据分字段保存，避免用发布时间推测修复时间。")
    p("固定快照的采集时间为 2026-11-20 08:23:37 UTC。刷新命令为 python tools/collect.py；格式异常、撤回、非预期区间或远端失败均不会替换现有快照。导入器在一次事务中重建样本行，完整性检查出错则回滚。来源 URL 可在详情页逐项核查。")
    d.add_page_break()
    h("5　系统设计与功能实现")
    p("浏览器提交表单，Flask 校验与规范化输入，PyMySQL 以参数化查询读取 MySQL，Jinja 模板输出 HTML。四个主要入口是 /、/advisories/<id>、/check 和 /reports。")
    fig("check.png",13.8)
    p("图 3　同一次检查的三种结果。3.2.9 命中 CVE-2022-28346；3.2.13 等于修复端点，本快照未命中；Flask 未进入样本。后两种结果均不能推断组件在整个生态中安全。")
    d.add_page_break()
    h("6　工程质量与性能实验")
    p(f"实验运行于 GitHub 云端 Linux，MySQL {B['mysql']}、Python {B['python']}。采样时间 {B['utc']}。每种查询先执行 EXPLAIN ANALYZE，再连续执行七次。耗时含数据库往返和取回结果，表中列中位数。")
    t(["实验数据","返回行数","中位耗时（ms）"],[
       ("全部真实业务表：按 django 查询区间",B["snapshot_lookup"]["rows"],B["snapshot_lookup"]["median_ms"]),
       ("百万行合成临时表：仅主键",B["matched"],BEFORE),
       ("同表：增加 (package_id, advisory_id)",B["matched"],AFTER)])
    p("实验构造 10,000 个均匀分布的包编号，每包 100 行。在同一连接中固定 package_id=42，按 advisory_id、seq 排序。两组结果逐行相同。临时表在连接结束时释放。")
    p(B["query"].replace("%s","42"))
    p(f"本次中位耗时比为 {BEFORE / AFTER:.1f} 倍。复合索引缩小候选集合，并使包内记录按公告键排列。热缓存、均匀分布和单并发限制了该结果的适用范围。完整执行计划和七次原始值见同包 benchmark.json。")
    p("测试涵盖 PEP 440 顺序、修复上界、重复导入、别名命中、未知包、非法输入、五个统计视图及 MySQL 连通。发布流水线还用 Chromium 提交三项依赖并读取真实页面。")
    p("Web 限制表单字节数和依赖行数。数据库凭据从环境读取。演示环境的应用与导入器共用数据库账户；对外长期部署前应拆分只读与写入权限。固定快照与建表脚本支持重建课程数据。")
    d.add_page_break()
    h("7　帮助与工具声明")
    p("打开已有 Codespace 的 5000 端口，从公告目录搜索 PYSEC-2022-190，打开详情核对分支；再转入依赖检查。README 包含启动、更新、测试和演示操作。重新导入前应保存自行增加的数据。")
    p("本作业使用 Codex 辅助设计、生成代码、执行云端测试和整理报告。数据库与 Python 工具包括 MySQL、Flask、PyMySQL、packaging、pytest。截图由浏览器访问实际应用生成，实验数字由程序从数据库读取。")
    h("8　可持续性")
    p("固定快照支持离线复现和重复答辩。扩展样本前应处理开放区间、多个 CVE 匹配策略及不同生态的版本规范。当前按 OSV 别名选择 NVD 记录，不能据此推算两个库在全世界的覆盖率。")
    h("9　总结")
    p("本版完成了三个来源的版本与编号对齐、七表模型、四类页面和索引对照实验。原方案的 Q6 下游依赖传播改为最高评分排序，Q9 Scorecard 关联改为来源覆盖统计。未来可先独立采集 NVD 对照样本，再扩展依赖边和项目健康分。")
    h("10　个人贡献说明")
    p("姓名／学号／组号：________________。请本人填写实际负责事项、亲自验证的操作及学习反思。可用复核题：为何修复端点不命中？为何比较 3.2.9 与 3.2.13 不能按字符串排序？")
    p("证据与复现：github.com/xiaomaodie/VulnLensDB；sql/schema.sql；backend/views.py；tools/benchmark.py。数据来源：osv.dev、nvd.nist.gov、docs.deps.dev。")
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
    s=slide("开源依赖漏洞多源整合数据库")
    label(s,"Django 3.2.9 与 3.2.13\n为什么会得到不同的检查结果？",.8,2.1,11.8,2.1,37)
    label(s,"VulnLensDB   /   数据库系统课程答辩",.8,5.7,11.8,.7,21,"16695D")
    s=slide("三种来源共同解释一个版本区间")
    for i,(src,desc) in enumerate([("OSV","公告、别名与受影响区间"),("NVD","按 CVE 对齐 CVSS 3.1 评分"),("deps.dev","按包名与修复端点核对发布时间")]):
        label(s,src,.9,1.65+i*1.4,2.6,.7,29,"14695F")
        label(s,desc,3.7,1.65+i*1.4,8.7,.8,25)
    label(s,"真实快照包含 3 个包、3 条公告和 6 个版本区间。",.9,6.0,11.5,.65,20)
    s=slide("七张表保留版本区间与来源")
    pic(s,"er.png",1.2,1.55,10.6)
    label(s,"公告与包通过区间关联；同一修复版本的发布时间只保存一次。",.8,6.25,11.8,.7,19)
    s=slide("修复端点决定是否命中")
    pic(s,"check.png",.7,1.45,6.6)
    label(s,"django==3.2.9\n在 [3.2, 3.2.13) 内，命中。\n\ndjango==3.2.13\n等于上界，本快照未命中。\n\nflask==3.0\n包未收录，无法判断。",7.65,1.55,5.15,5.5,21)
    s=slide("查询如何回答课程问题")
    label(s,"编号对齐",.9,1.6,3,.8,27,"14695F");label(s,"EXISTS 搜别名；外连接和集合运算比较 CVE 覆盖。",4,1.6,8.3,1,23)
    label(s,"包的排名",.9,3.1,3,.8,27,"14695F");label(s,"先按包取最高 CVSS，再以 DENSE_RANK 处理并列。",4,3.1,8.3,1,23)
    label(s,"修复历史",.9,4.65,3,.8,27,"14695F");label(s,"在包内按发布时间排序，用 LAG 提取上一条记录。",4,4.65,8.3,1,23)
    s=slide("百万行合成实验中的索引收益")
    label(s,f"{BEFORE:g} ms",.9,2.0,5.4,1.1,45);label(s,f"{AFTER:g} ms",7.0,2.0,5.4,1.1,45,"14695F")
    label(s,"仅主键",.9,3.35,5.5,.8,26);label(s,"增加包与公告的复合索引",7,3.35,5.8,1,25)
    label(s,"同一查询返回相同的 100 行。各测 7 次，取中位数。\n数据均匀、单并发、热缓存；真实公告样本另行测量。",.9,5.1,11.8,1.4,21)
    s=slide("覆盖范围决定结论能走多远")
    label(s,"已验证",.9,1.7,2.5,.8,26,"14695F");label(s,"版本边界、编号映射、可追溯来源与真实数据库查询。",3.6,1.7,8.7,1.2,23)
    label(s,"当前边界",.9,3.35,2.5,.8,26,"14695F");label(s,"三条 PyPI 公告；样本未命中不能证明依赖安全。",3.6,3.35,8.7,1.2,23)
    label(s,"下一次扩展",.9,5.0,2.7,.8,26,"14695F");label(s,"独立采集 NVD 对照集，再加入依赖边和更多生态。",3.6,5,8.7,1.2,23)
    deck.save(OUT/"VulnLensDB-defense.pptx")


if __name__ == "__main__":
    figures()
    report()
    slides()
