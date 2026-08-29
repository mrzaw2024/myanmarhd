# SRRSORGYI - VIDEO Streaming Portal

Streaming portal with video player, favorites, and hot video sections.

## Files

- `index.html` - Frontend UI (single page app)
- `server.py` - Python streaming server (MP4 fast-start proxy with range support)

## Requirements

- Python 3.8+

## Run

```bash
python3 server.py
```

Then open `http://localhost:8000` in your browser.

The server listens on port `8000` and serves the frontend plus the `/stream`
endpoint used for fast video playback.

## Notes

- The upstream API/thumbnail host is `z317922-bh22ex.ls04.zwhhosting.com`
  (configured in `index.html` / `server.py`).
- Age verification is shown on first visit and stored in `localStorage`.
