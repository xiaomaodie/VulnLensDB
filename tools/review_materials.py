"""Check exported pages and assemble review thumbnails."""
import re
import subprocess
import tempfile
from pathlib import Path
from PIL import Image, ImageOps

ROOT = Path("build")


def review(stem, pages):
    pdf = ROOT / f"{stem}.pdf"
    info = subprocess.check_output(["pdfinfo", str(pdf)], text=True)
    actual = int(re.search(r"^Pages:\s+(\d+)", info, re.MULTILINE)[1])
    print(f"{stem}: {actual} pages", flush=True)
    with tempfile.TemporaryDirectory() as temp:
        subprocess.run(["pdftoppm","-scale-to","800","-png",str(pdf),f"{temp}/p"],check=True)
        thumbs = []
        for page in sorted(Path(temp).glob("p-*.png")):
            with Image.open(page) as img:
                thumbs.append(ImageOps.contain(img.convert("RGB"), (410,490)))
        cell_w, cell_h = max(i.width for i in thumbs)+8, max(i.height for i in thumbs)+8
        sheet = Image.new("RGB",(3*cell_w,((actual+2)//3)*cell_h),"#c7cdca")
        for i, im in enumerate(thumbs):
            sheet.paste(im,(i%3*cell_w+4,i//3*cell_h+4))
        sheet.save(ROOT/f"{stem}-preview.jpg",quality=82)
    assert actual == pages, f"Unexpected pagination for {stem}: {actual}, expected {pages}"


if __name__ == "__main__":
    review("VulnLensDB-report",6)
    review("VulnLensDB-defense",7)
