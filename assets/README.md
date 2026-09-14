# Assets

Demo captures and product-evidence media. These files are not part of the
documentation site — VitePress serves only [docs/public/](../docs/public/);
this directory is referenced from [PRODUCT.md](../PRODUCT.md) as evidence on
hand.

| File | What it is |
|---|---|
| `console-v0.6.png` | Console capture from the v0.6 release. |
| `rookhold-cli-recording.html` | The deterministic, self-playing CLI/MCP demo (open in a browser). |
| `rookhold-cli-mcp-demo.gif` | GIF export of the demo recording. |
| `rookhold-cli-mcp-demo.mp4` | MP4 export of the demo recording. |

## Regenerating the demo

The HTML demo is a deterministic self-playing page; the video exports are
recorded from it with [scripts/render-cli-demo.py](../scripts/README.md)
(Playwright), then converted with ffmpeg:

```bash
python3 scripts/render-cli-demo.py \
  --html assets/rookhold-cli-recording.html \
  --output /tmp/rookhold-cli-mcp-demo.webm
ffmpeg -i /tmp/rookhold-cli-mcp-demo.webm assets/rookhold-cli-mcp-demo.mp4
```
