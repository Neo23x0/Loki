# -*- mode: python -*-

a = Analysis(['loki-upgrader.py'],
             pathex=['.'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='loki-upgrader.exe',
          debug=False,
          strip=None,
          upx=False,
          console=True , icon='loki.ico')
