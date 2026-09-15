# Renderer Resize Qualification

Use the Windows media diagnostic after the teacher-to-student GPU path is running:

```powershell
.\classmesh-media-receiver.exe --listen 0.0.0.0:57000 --seconds 300 --render
```

During the run, exercise all of the following without restarting the receiver:

1. drag-resize the presentation window repeatedly;
2. maximize and restore;
3. minimize for at least 10 seconds while media continues arriving;
4. restore and verify live motion resumes;
5. alternate portrait-like and landscape-like window shapes;
6. move the window between monitors with different DPI/refresh settings when available.

Expected behavior:

- no process crash;
- no teacher reconnect;
- no TCP/JPEG fallback;
- no growth in media queues;
- minimize is reported as presentation suspension rather than decode/network failure;
- restore triggers a bounded swap-chain resize and lazy video-processor rebuild;
- aspect ratio remains correct with letterbox/pillarbox as needed;
- decoded frames continue advancing while the presentation window is minimized.

A resize failure that reports DXGI device removed/reset/hung is not a normal window-resize error. It should enter the media GPU recovery path described in `RENDERER_LIFECYCLE.md`.
